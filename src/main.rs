mod types;

// use std::fs::read_to_string;
use anyhow::Result;
use mio::{Events, Interest, Poll, Token};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use tun::Device;

/// Struct to hold the TUN device and implement the `mio::event::Source` trait.
struct MioTun {
    dev: Device,
    raw_fd: RawFd,
}

impl MioTun {
    fn new(dev: tun::Device) -> Self {
        let raw_fd = dev.as_raw_fd();
        MioTun {
            // dev: Arc::new(Mutex::new(dev)),
            dev,
            raw_fd,
        }
    }
}

impl mio::event::Source for MioTun {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        let mut source_fd = mio::unix::SourceFd(&self.raw_fd);
        source_fd.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        let mut source_fd = mio::unix::SourceFd(&self.raw_fd);
        source_fd.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        let mut source_fd = mio::unix::SourceFd(&self.raw_fd);
        source_fd.deregister(registry)
    }
}

impl std::ops::Deref for MioTun {
    type Target = Device;

    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}

impl std::ops::DerefMut for MioTun {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.dev
    }
}

// impl Read for MioTun {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         self.dev.lock().unwrap().read(buf)
//     }

//     fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
//         self.dev.lock().unwrap().read_vectored(bufs)
//     }
// }

// impl Write for MioTun {
//     fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
//         self.dev.lock().unwrap().write(buf)
//     }

//     fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
//         self.dev.lock().unwrap().write_vectored(bufs)
//     }

//     fn flush(&mut self) -> std::io::Result<()> {
//         self.dev.lock().unwrap().flush()
//     }
// }

fn create_tun(addr: &IpAddr) -> Result<MioTun> {
    let mut tun_config = tun::Configuration::default();

    tun_config
        .address(addr)
        .netmask((255, 255, 255, 0))
        .mtu(1500)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    let dev = tun::create(&tun_config)?;

    Ok(MioTun::new(dev))
}

fn load_config() -> Result<types::Config> {
    let config_str = std::fs::read_to_string("config.json")?;
    let config: types::Config = serde_json::from_str(&config_str)?;
    Ok(config)
}

const TUN: Token = Token(0);
const UDP: Token = Token(1);

fn main() -> Result<()> {
    // Load the configuration.
    let config = load_config()?;

    // Create a poll instance.
    let mut poll = Poll::new()?;
    // Create storage for events.
    let mut events = Events::with_capacity(128);

    // Setup TUN interface.
    let mut tun = create_tun(&config.addr)?;

    // Register the TUN.
    poll.registry()
        .register(&mut tun, TUN, Interest::READABLE)?;

    // Setup UDP socket.
    let listen_addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
    let mut udp_sock = mio::net::UdpSocket::bind(listen_addr)?;

    // Register the UDP socket.
    poll.registry()
        .register(&mut udp_sock, UDP, Interest::READABLE)?;

    // Initialize a buffer for the UDP/TUN packets. We use the maximum size of a UDP
    // packet, which is the maximum value of 16 a bit integer.
    let mut buf = [0; 1 << 16];

    // Start an event loop.
    loop {
        // Poll Mio for events, blocking until we get an event.
        poll.poll(&mut events, None)?;

        // Process each event.
        for event in events.iter() {
            // We can use the token we previously provided to `register` to
            // determine for which socket the event is.
            match event.token() {
                TUN => {
                    println!("TUN event");
                    // The socket contains data to read.
                    let nbytes = tun.read(&mut buf)?;
                    println!("Read {} bytes from TUN", nbytes);
                    // Write the data back to the UDP socket.
                    udp_sock.send_to(&buf[..nbytes], config.peer)?;
                    println!("Sent {} bytes to UDP", nbytes);
                }
                UDP => {
                    println!("UDP event");
                    // The socket is ready to read.
                    loop {
                        // In this loop we receive all packets queued for the socket.
                        match udp_sock.recv_from(&mut buf) {
                            Ok((len, _src)) => {
                                println!("Read {} bytes from UDP", len);
                                // Send the packet to the TUN interface.
                                tun.write_all(&buf[..len])?;
                                println!("Sent {} bytes to TUN", len);
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                // If we get a `WouldBlock` error we know our socket
                                // has no more packets queued, so we can return to
                                // polling and wait for some more.
                                break;
                            }
                            Err(e) => {
                                // If it was any other kind of error, something went
                                // wrong and we terminate with an error.
                                return Err(e.into());
                            }
                        }
                    }
                }
                // We don't expect any events with tokens other than those we provided.
                _ => unreachable!(),
            }
        }
    }
}
