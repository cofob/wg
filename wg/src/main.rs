#![feature(mpmc_channel)]

mod log_setup;

use anyhow::Result;
use io_uring::{opcode, types, IoUring};
use log::debug;
use slab::Slab;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::sync::mpmc;
use std::time::Duration;
use tun::Device;

#[derive(Clone, Debug)]
enum Token {
    TunRead { buf_ptr: *mut u8, buf_len: usize },
}

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

enum WorkerMessage {
    Shutdown,
    Read { buf_ptr: usize, buf_len: usize },
}

enum MasterMessage {
    ReturnBuffer { buf_ptr: usize, buf_len: usize },
}

fn worker_inner(tx: &mpmc::Sender<MasterMessage>, message: WorkerMessage) -> Result<()> {
    match message {
        WorkerMessage::Read { buf_ptr, buf_len } => {
            let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len) };
            debug!("worker read: {:?}", buf);
            tx.send(MasterMessage::ReturnBuffer { buf_ptr, buf_len })?;
        }
        WorkerMessage::Shutdown => {
            return Err(anyhow::anyhow!("worker shutdown"));
        }
    }

    Ok(())
}

fn worker(rx: mpmc::Receiver<WorkerMessage>, tx: mpmc::Sender<MasterMessage>) {
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

/// Struct to hold the buffer data and get buffer chunks from it.
struct Buffer {
    data: Vec<u8>,
    chunk_size: usize,
    available_ptrs: Vec<usize>,
}

impl Buffer {
    fn new(data: Vec<u8>, chunk_size: usize) -> Self {
        let available_ptrs = Self::get_available_ptrs(&data, chunk_size);
        Self {
            data,
            chunk_size,
            available_ptrs,
        }
    }

    fn get_available_ptrs(data: &Vec<u8>, chunk_size: usize) -> Vec<usize> {
        let start_ptr = data.as_ptr() as usize;
        (0..data.len())
            .step_by(chunk_size)
            .map(|i| start_ptr + i)
            .collect()
    }

    fn get_chunk(&mut self) -> Option<&mut [u8]> {
        if let Some(ptr) = self.available_ptrs.pop() {
            Some(unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, self.chunk_size) })
        } else {
            None
        }
    }

    /// Read chunk should have additional 16 bytes in outer sides of the buffer
    /// to store the metadata and poly1305 tag.
    ///
    /// [ metadata | chunk | metadata ]
    fn get_read_chunk(&mut self) -> Option<&mut [u8]> {
        if let Some(ptr) = self.available_ptrs.pop() {
            Some(unsafe {
                std::slice::from_raw_parts_mut((ptr as *mut u8).offset(16), self.chunk_size - 32)
            })
        } else {
            None
        }
    }

    /// Convert read chunk to write chunk by adding 16 bytes in outer sides of the buffer.
    fn convert_read_chunk_to_write_chunk(&self, chunk: &mut [u8]) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                (chunk.as_ptr() as usize as *mut u8).offset(-16),
                self.chunk_size + 32,
            )
        }
    }

    fn return_chunk(&mut self, chunk: &mut [u8]) {
        self.available_ptrs.push(chunk.as_ptr() as usize);
    }

    fn get_available_chunks(&self) -> usize {
        self.available_ptrs.len()
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

    let (wtx, wrx) = mpmc::channel();
    let (mtx, mrx) = mpmc::channel();

    for _ in 0..cpus {
        let wrx = wrx.clone();
        let mtx = mtx.clone();
        std::thread::spawn(move || worker(wrx, mtx));
    }

    // Create one vector enough to hold all the buffers for TUN reads/writes
    let mtu = 8932;
    let mut tun_buffer = Buffer::new(vec![0; mtu * cpus * 2], mtu);

    // Create read from TUN requests for all the cpus
    for _ in 0..cpus {
        let buf = tun_buffer.get_read_chunk().unwrap();
        let read_token = token_alloc.insert(Token::TunRead {
            buf_ptr: buf.as_mut_ptr(),
            buf_len: buf.len(),
        });
        let read_e = opcode::Read::new(types::Fd(raw_fd), buf.as_mut_ptr(), buf.len() as _)
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

        // Wait for channel messages if there are no IO events
        let mut messages = vec![];
        if cq.len() == 0 {
            match mrx.recv_timeout(Duration::from_millis(10)) {
                Ok(message) => {
                    messages.push(message);
                },
                Err(_) => {
                    // If there are no messages, continue the loop
                    continue;
                }
            }
        }

        // Process the messages for the master thread
        for message in messages.into_iter().chain(mrx.try_iter()) {
            match message {
                MasterMessage::ReturnBuffer { buf_ptr, buf_len } => {
                    // Create read request
                    let buf =
                        unsafe { std::slice::from_raw_parts_mut(buf_ptr as *mut u8, buf_len) };
                    let read_token = token_alloc.insert(Token::TunRead {
                        buf_ptr: buf_ptr as *mut u8,
                        buf_len,
                    });
                    let read_e =
                        opcode::Read::new(types::Fd(raw_fd), buf.as_mut_ptr(), buf.len() as _)
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

            let token = &mut token_alloc[token_index];
            match token.clone() {
                Token::TunRead { buf_ptr, buf_len } => {
                    let len = ret as usize;
                    let buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_len) };

                    // Send the buffer to processing threads channel
                    wtx.send(WorkerMessage::Read {
                        buf_ptr: buf_ptr as usize,
                        buf_len: len,
                    })?;

                    // Remove the read token from the slab
                    token_alloc.remove(token_index);
                }
            }
        }
    }

    Ok(())
}
