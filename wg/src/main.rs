mod log_setup;

use anyhow::Result;
use io_uring::{opcode, types, IoUring};
use kanal::{bounded, Receiver, Sender};
use log::debug;
use slab::Slab;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::time::Duration;
use tun::Device;
use wg_proto::data_types::{buffer::AllocBuffer, chunk, Buffer};

fn create_tun(addr: &IpAddr) -> Result<Device> {
    let mut tun_config = tun::Configuration::default();

    tun_config
        .address(addr)
        .netmask((255, 255, 255, 0))
        .mtu(8900)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    Ok(tun::create(&tun_config)?)
}

#[derive(Debug)]
enum EventToken {
    TunRead { chunk: chunk::Chunk<chunk::Read> },
}

enum WorkerMessage {
    Shutdown,
    TunRead {
        chunk: chunk::Chunk<chunk::Full>,
        len: usize,
    },
}

enum MasterMessage {
    ReturnBuffer { chunk: chunk::Chunk<chunk::Full> },
}

fn worker_inner(tx: &Sender<MasterMessage>, message: WorkerMessage) -> Result<()> {
    match message {
        WorkerMessage::TunRead { chunk, len } => {
            let chunk: chunk::Chunk<chunk::Read> = chunk.into();
            let buf = &chunk.as_ref()[..len];
            debug!("worker read: {:?}", buf);
            tx.send(MasterMessage::ReturnBuffer {
                chunk: chunk.into(),
            })?;
        }
        WorkerMessage::Shutdown => {
            return Err(anyhow::anyhow!("worker shutdown"));
        }
    }

    Ok(())
}

fn worker(rx: Receiver<WorkerMessage>, tx: Sender<MasterMessage>) {
    loop {
        match rx.recv() {
            Ok(message) => {
                if let WorkerMessage::Shutdown = message {
                    break;
                }
                if let Err(e) = worker_inner(&tx, message) {
                    eprintln!("worker error: {:?}", e);
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

fn main() -> Result<()> {
    log_setup::configure_logging(&None)?;

    let device = create_tun(&IpAddr::from_str("10.0.0.3")?)?;
    let raw_fd = device.as_raw_fd();

    let cpus = num_cpus::get();

    // let pool = ThreadPool::new(cpus);

    // let (stx, srx) = std::sync::mpsc::channel();

    let mut ring = IoUring::new(64)?;

    let (submitter, mut sq, mut cq) = ring.split();

    let mut token_alloc = Slab::with_capacity(64);

    let (wtx, wrx) = bounded(64);
    let (mtx, mrx) = bounded(64);

    for _ in 0..cpus {
        let wrx = wrx.clone();
        let mtx = mtx.clone();
        std::thread::spawn(move || worker(wrx, mtx));
    }

    // Create one vector enough to hold all the buffers for TUN reads/writes
    let mtu = 8932;
    let mut tun_buffer = AllocBuffer::new(vec![0; mtu * cpus * 2], mtu);

    // Create read from TUN requests for all the cpus
    for _ in 0..cpus {
        let chunk: chunk::Chunk<chunk::Read> = tun_buffer.get_chunk().unwrap().into();
        let mut_ptr = chunk.as_mut_ptr();
        let len = chunk.len();
        let read_token = token_alloc.insert(EventToken::TunRead { chunk });
        let read_e = opcode::Read::new(types::Fd(raw_fd), mut_ptr, len as _)
            .build()
            .user_data(read_token as _);
        unsafe {
            sq.push(&read_e)?;
        }
    }

    // Read from the tun device
    loop {
        sq.sync();
        submitter.submit()?;
        cq.sync();

        // Wait a bit if there are no messages to process
        if cq.len() == 0 && mrx.is_empty() {
            std::thread::sleep(Duration::from_millis(10));
        }

        // Process the messages for the master thread
        while let Some(message) = mrx.try_recv()? {
            match message {
                MasterMessage::ReturnBuffer { chunk } => {
                    // Create read request
                    let chunk: chunk::Chunk<chunk::Read> = chunk.into();
                    let mut_ptr = chunk.as_mut_ptr();
                    let len = chunk.len();
                    let read_token = token_alloc.insert(EventToken::TunRead { chunk });
                    let read_e = opcode::Read::new(types::Fd(raw_fd), mut_ptr, len as _)
                        .build()
                        .user_data(read_token as _);
                    unsafe {
                        sq.push(&read_e)?;
                    }
                }
            }
        }

        // Process IO events
        for cqe in &mut cq {
            let ret = cqe.result();
            let token_index = cqe.user_data() as usize;
            if ret < 0 {
                eprintln!(
                    "token {:?} error: {:?}",
                    token_alloc.get(token_index),
                    std::io::Error::from_raw_os_error(-ret)
                );
                continue;
            }

            let token = token_alloc.remove(token_index);
            match token {
                EventToken::TunRead { chunk } => {
                    let len = ret as usize;

                    // Send the buffer to processing threads channel
                    wtx.send(WorkerMessage::TunRead {
                        chunk: chunk.into(),
                        len,
                    })?;
                }
            }
        }
    }

    // Ok(())
}
