mod types;

use std::fs::read_to_string;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tun::BoxError;
use types::Config;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    main_entry().await?;
    Ok(())
}

async fn main_entry() -> Result<(), BoxError> {
    // Read config file.
    let app_config: Config = serde_json::from_str(&read_to_string("config.json")?)?;

    // Setup TUN interface.
    let mut tun_config = tun::Configuration::default();

    tun_config
        .address(app_config.addr)
        .netmask((255, 255, 255, 0))
        .mtu(5000)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    // Read data from UDP and send it to TUN.
    // Read data from TUN and send it to UDP.

    // 1. Create UDP socket.
    let udp_socket = UdpSocket::bind(app_config.listen).await?;

    // 2. Split the UDP socket into a reader and a writer.
    // udp_tx sends data to UDP socket.
    // udp_r receives data from UDP socket.
    let udp_r = Arc::new(udp_socket);
    let udp_s = udp_r.clone();
    let (udp_tx, mut udp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);

    tokio::spawn(async move {
        while let Some((bytes, addr)) = udp_rx.recv().await {
            let len = udp_s.send_to(&bytes, &addr).await.unwrap();
            // println!("{:?} bytes sent", len);
        }
    });

    // 3. Create TUN device.
    let dev = tun::create_as_async(&tun_config)?;

    // 4. Split the TUN device
    // tun_tx sends data to TUN device.
    // dev_rx receives data from TUN device.
    let (mut dev_rx, mut dev_tx) = split(dev);
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(1_000);

    tokio::spawn(async move {
        while let Some(bytes) = tun_rx.recv().await {
            dev_tx.write_all(&bytes).await.unwrap();
        }
    });

    // 5. Read data from UDP and send it to TUN.
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];

        loop {
            let (len, _addr) = udp_r.recv_from(&mut buf).await.unwrap();
            let data = buf[..len].to_vec();
            tun_tx.send(data).await.unwrap();
        }
    });

    // 6. Read data from TUN and send it to UDP.
    let mut buf = [0u8; 4096];

    loop {
        let len = dev_rx.read(&mut buf).await?;
        let data = buf[..len].to_vec();
        udp_tx.send((data, app_config.peer)).await?;
    }
}
