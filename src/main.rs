mod types;
mod log_setup;

use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::net::UdpSocket;
use tun::AsyncDevice;

fn create_tun(addr: &IpAddr) -> Result<AsyncDevice> {
    let mut tun_config = tun::Configuration::default();

    tun_config
        .address(addr)
        .netmask((255, 255, 255, 0))
        .mtu(1400)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    Ok(tun::create_as_async(&tun_config)?)
}

fn load_config() -> Result<types::Config> {
    let config_str = std::fs::read_to_string("config.json")?;
    let config: types::Config = serde_json::from_str(&config_str)?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    log_setup::configure_logging(&None)?;

    let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);

    ctrlc2::set_async_handler(async move {
        tx.send(()).await.expect("Signal error");
    })
    .await;

    main_entry(rx).await?;

    Ok(())
}

async fn main_entry(mut quit: tokio::sync::mpsc::Receiver<()>) -> Result<()> {
    // Load the configuration.
    let config = load_config()?;

    // Setup TUN interface.
    let tun = create_tun(&config.addr)?;

    // Setup UDP socket.
    let listen_addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
    let udp_sock = UdpSocket::bind(listen_addr).await?;

    // Initialize buffers for the UDP/TUN packets. We use the maximum size of a UDP
    // packet, which is the maximum value of 16 a bit integer.
    let mut tun_buf = [0; u16::MAX as usize];
    let mut udp_buf = [0; u16::MAX as usize];

    // Start an event loop.
    loop {
        // Read from either the TUN interface or the UDP socket.
        tokio::select! {
            n = tun.recv(&mut tun_buf) => {
                let n = n?;
                let _ = udp_sock.send_to(&tun_buf[..n], &config.peer).await?;
            }
            n = udp_sock.recv_from(&mut udp_buf) => {
                let (n, _) = n?;
                let _ = tun.send(&udp_buf[..n]).await?;
            }
            _ = quit.recv() => {
                println!("Received quit signal, exiting...");
                break;
            }
        }
    }

    Ok(())
}
