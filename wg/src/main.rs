mod log_setup;

use anyhow::Result;
use io_uring::{cqueue, opcode, types, IoUring};
use kanal::{bounded, Receiver, Sender};
use log::debug;
use slab::Slab;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::str::FromStr;
use std::time::Duration;
use tun::Device;
use wg_proto::{
    data_types::{buffer::AllocBuffer, chunk, traits::Chunk, Buffer},
    ip::IPPacket,
};

#[macro_use]
extern crate log;

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
enum BufferGroup {
    Udp,
}

#[derive(Debug)]
enum EventToken {
    TunRead { chunk: chunk::RefChunk<chunk::Read> },
    UdpRead,
    Ignore,
}

enum WorkerMessage {
    Shutdown,
    TunEvent {
        chunk: chunk::RefChunk<chunk::Full>,
        len: usize,
    },
    UdpEvent {
        chunk: chunk::RefChunk<chunk::Full>,
        len: usize,
        buf_id: u16,
    },
}

enum MasterMessage {
    ReturnTunBuffer {
        chunk: chunk::RefChunk<chunk::Full>,
    },
    ReturnUdpBuffer {
        chunk: chunk::RefChunk<chunk::Full>,
        buf_id: u16,
    },
}

fn worker_inner(tx: &Sender<MasterMessage>, message: WorkerMessage) -> Result<()> {
    match message {
        WorkerMessage::TunEvent { chunk, len } => {
            let chunk: chunk::RefChunk<chunk::Read> = chunk.into_chunk();
            let buf = &chunk.as_ref()[..len];
            let packet = IPPacket::new(buf).unwrap();
            debug!("worker tun read: {:?}", packet);
            tx.send(MasterMessage::ReturnTunBuffer {
                chunk: chunk.into_chunk(),
            })?;
        }
        WorkerMessage::UdpEvent { chunk, len, buf_id } => {
            let buf = &chunk.as_ref()[..len];
            debug!("worker udp read: {:?}", buf);
            tx.send(MasterMessage::ReturnUdpBuffer { chunk, buf_id })?;
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
                    error!("worker error: {:?}", e);
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

fn extract_ip_from_msg(msg_out: &types::RecvMsgOut) -> Option<SocketAddr> {
    let name_data = &msg_out.name_data();
    let len = msg_out.incoming_name_len() as usize;

    // Check if the name data is long enough to contain the family
    if len >= 2 {
        let family = u16::from_ne_bytes([name_data[0], name_data[1]]) as i32;

        match family {
            // IPv4
            libc::AF_INET => {
                if len >= std::mem::size_of::<libc::sockaddr_in>() {
                    let port = u16::from_be_bytes([name_data[2], name_data[3]]);
                    let ip = std::net::Ipv4Addr::new(
                        name_data[4],
                        name_data[5],
                        name_data[6],
                        name_data[7],
                    );
                    Some(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                        ip, port,
                    )))
                } else {
                    None
                }
            }

            // IPv6
            libc::AF_INET6 => {
                if len >= std::mem::size_of::<libc::sockaddr_in6>() {
                    let port = u16::from_be_bytes([name_data[2], name_data[3]]);
                    let addr_bytes: [u8; 16] = name_data[8..24].try_into().unwrap();
                    let ip = std::net::Ipv6Addr::from(addr_bytes);
                    Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                        ip, port, 0, 0,
                    )))
                } else {
                    None
                }
            }

            // Unknown address family
            _ => None,
        }
    } else {
        None
    }
}

fn main() -> Result<()> {
    log_setup::configure_logging(&None)?;

    let config_str = std::fs::read_to_string("wg0.local.conf")?;
    let config: wg_proto::config::WireGuardConfig = serde_json::from_str(&config_str)?;

    debug!("{:?}", config);

    let device = create_tun(&IpAddr::from_str("10.0.0.3")?)?;
    let raw_fd = device.as_raw_fd();

    let udp_sock = std::net::UdpSocket::bind("0.0.0.0:5000")?;
    // let udp_sock = std::net::UdpSocket::bind("0.0.0.0:5000")?;

    let cpus = num_cpus::get();

    let mut ring = IoUring::new(64)?;

    let (submitter, mut sq, mut cq) = ring.split();

    let mut token_alloc = Slab::with_capacity(64);
    let mut bgroup_alloc = Slab::with_capacity(64);

    // Add ignore token
    let ignore_token = token_alloc.insert(EventToken::Ignore);

    let (wtx, wrx) = bounded(64);
    let (mtx, mrx) = bounded(64);

    for _ in 0..cpus {
        let wrx = wrx.clone();
        let mtx = mtx.clone();
        std::thread::spawn(move || worker(wrx, mtx));
    }

    let buffer_overhead = 44 + 16;
    let mtu = 8900 + buffer_overhead;

    // Create one vector enough to hold all the buffers for UDP reads/writes
    let mut udp_buffer = AllocBuffer::new_with_size(mtu, cpus);

    let mut msg_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut client_addr = std::mem::MaybeUninit::<libc::sockaddr_in6>::uninit();
    msg_hdr.msg_name = client_addr.as_mut_ptr() as *mut libc::c_void;
    msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t; // 28

    // Create multishot read for UDP socket
    let udp_bgroup_token = bgroup_alloc.insert(BufferGroup::Udp);
    {
        let read_token = token_alloc.insert(EventToken::UdpRead);

        let provide_bufs_e = opcode::ProvideBuffers::new(
            udp_buffer.as_mut_ptr(),
            udp_buffer.get_chunk_size() as _,
            udp_buffer.get_available_chunks() as _,
            0,
            0,
        )
        .build()
        .user_data(udp_bgroup_token as _)
        .into();

        unsafe {
            sq.push(&provide_bufs_e)?;
        }

        // Wait for the buffers to be provided
        sq.sync();
        submitter.submit_and_wait(1)?;

        let read_e = opcode::RecvMsgMulti::new(
            types::Fd(udp_sock.as_raw_fd()),
            &msg_hdr as *const _,
            udp_bgroup_token as _,
        )
        .build()
        .user_data(read_token as _)
        .into();

        unsafe {
            sq.push(&read_e)?;
        }
    }

    // Create one vector enough to hold all the buffers for TUN reads/writes
    let mut tun_buffer = AllocBuffer::new_with_size(mtu, cpus);

    // Create read from TUN requests for all the cpus
    for _ in 0..cpus {
        let mut chunk: chunk::RefChunk<chunk::Read> = tun_buffer.get_chunk().unwrap().into_chunk();
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
        if cq.is_empty() && mrx.is_empty() {
            std::thread::sleep(Duration::from_millis(10));
        }

        // Process the messages for the master thread
        while let Some(message) = mrx.try_recv()? {
            match message {
                MasterMessage::ReturnTunBuffer { chunk } => {
                    // Create read request
                    let mut chunk: chunk::RefChunk<chunk::Read> = chunk.into_chunk();
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
                MasterMessage::ReturnUdpBuffer { mut chunk, buf_id } => {
                    // Provide the buffer back to the kernel
                    let provide_bufs_e = opcode::ProvideBuffers::new(
                        chunk.as_mut_ptr(),
                        chunk.len() as _,
                        1,
                        udp_bgroup_token as _,
                        buf_id,
                    )
                    .build()
                    .user_data(ignore_token as _);

                    unsafe {
                        sq.push(&provide_bufs_e)?;
                    }
                }
            }
        }

        // Process IO events
        for cqe in &mut cq {
            let ret = cqe.result();
            let token_index = cqe.user_data() as usize;
            if ret < 0 {
                error!(
                    "token {:?} error: {:?}",
                    token_alloc.get(token_index),
                    std::io::Error::from_raw_os_error(-ret)
                );
                continue;
            }

            let token = &token_alloc[token_index];
            match token {
                EventToken::TunRead { chunk: _ } => {
                    let len = ret as usize;
                    let owned_token = token_alloc.remove(token_index);
                    let chunk = match owned_token {
                        EventToken::TunRead { chunk } => chunk,
                        _ => unreachable!(),
                    };

                    // Send the buffer to processing threads channel
                    wtx.send(WorkerMessage::TunEvent {
                        chunk: chunk.into_chunk(),
                        len,
                    })?;
                }
                EventToken::UdpRead => {
                    let len = ret as usize;
                    let flags = cqe.flags();
                    if len == 0 {
                        debug!("udp read: 0 bytes, flags: {:?}", flags);
                        continue;
                    }
                    let buf_id = io_uring::cqueue::buffer_select(flags).unwrap();
                    let buf_start = (buf_id as usize) * (mtu as usize);
                    let chunk_size = udp_buffer.get_chunk_size();
                    let chunk: chunk::RefChunk<chunk::Full> = chunk::RefChunk::new(
                        &mut udp_buffer.as_mut()[buf_start..buf_start + chunk_size],
                    );
                    let msg_out = types::RecvMsgOut::parse(chunk.as_ref(), &msg_hdr).unwrap();
                    let src = extract_ip_from_msg(&msg_out).unwrap();

                    debug!("sender_addr: {:?}", src);

                    // Send the buffer to processing threads channel
                    wtx.send(WorkerMessage::UdpEvent {
                        chunk: chunk.into(),
                        len,
                        buf_id,
                    })?;

                    // Check if we should resubmit the multi read request
                    if !cqueue::more(flags) {
                        let read_e = opcode::RecvMsgMulti::new(
                            types::Fd(udp_sock.as_raw_fd()),
                            &msg_hdr as *const _,
                            udp_bgroup_token as _,
                        )
                        .build()
                        .user_data(token_index as _)
                        .into();

                        unsafe {
                            sq.push(&read_e)?;
                        }
                    }
                }
                EventToken::Ignore => {
                    // debug!("ignore token");
                }
            }
        }
    }

    // Ok(())
}
