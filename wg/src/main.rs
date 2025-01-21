mod log_setup;

use anyhow::Result;
use base64::prelude::*;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio::net::UdpSocket;
use tun::AsyncDevice;
use wg_proto::operations::{decrypt_data_in_place, process_packet};
use wg_proto::{
    crypto::{
        blake2::Blake2s,
        chacha20poly1305::{ChaCha20Poly1305, EncryptionBuffer},
        tai64::Tai64N,
        x25519::{
            X25519EphemeralSecret, X25519OperableSecretKey, X25519PublicKey, X25519StaticSecret,
        },
    },
    data_types::{HandshakeInitiationMessage, HandshakeResponseMessage, PacketData, PeerState},
    operations::{
        encrypt_data_in_place, initiate_handshake, prepare_packet, process_handshake_response,
    },
};
use wg_rust_crypto::{blake2, chacha20poly1305, x25519};

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
    let mut tun_buf = [0u8; u16::MAX as usize];
    let mut udp_buf = [0u8; u16::MAX as usize];
    let mut rng = rand::thread_rng();

    // Load the static keys
    let mut initiator_static_private_buf: [u8; 32] = [0; 32];
    initiator_static_private_buf
        .copy_from_slice(&BASE64_STANDARD.decode("kLSlfaoabpt64dRjpuhQZP44ZQBMGXelGPPi0xdImmI=")?);
    let initiator_static_secret =
        wg_rust_crypto::x25519::X25519StaticSecret::from_bytes(&initiator_static_private_buf)?;
    let initiator_static_public = initiator_static_secret.public_key()?;

    let mut responder_static_public_buf: [u8; 32] = [0; 32];
    responder_static_public_buf
        .copy_from_slice(&BASE64_STANDARD.decode("/GWGlDyUlq3T6zyAGT0l4Yy93JbOnDwyizbTEcyQi00=")?);
    let responder_static_public =
        wg_rust_crypto::x25519::X25519PublicKey::from_bytes(&responder_static_public_buf)?;

    // Generate an ephemeral keypair
    let initiator_ephemeral_secret = wg_rust_crypto::x25519::X25519EphemeralSecret::generate();
    let initiator_ephemeral_public = initiator_ephemeral_secret.public_key()?;

    // Create a handshake initiation message
    let (msg, mut state) = initiate_handshake::<
        wg_rust_crypto::blake2::Blake2s,
        wg_rust_crypto::chacha20poly1305::ChaCha20Poly1305,
        wg_rust_crypto::tai64::Tai64N,
    >(
        &mut tun_buf,
        &mut rng,
        &initiator_static_secret,
        &initiator_static_public,
        &initiator_ephemeral_secret,
        &initiator_ephemeral_public,
        &responder_static_public,
    )?;

    println!("Sending: {:?}", &msg);

    let peer = SocketAddr::from(([159, 89, 2, 36], 62068));
    let udp_sock = UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0")?).await?;
    println!("UDP socket bound to: {:?}", udp_sock.local_addr()?);

    udp_sock.send_to(msg.as_bytes(), peer).await?;

    // Listen for response
    let mut buf = [0u8; 2048];
    let resp: HandshakeResponseMessage;

    tokio::select! {
        _ = quit.recv() => {
            println!("Received quit signal, exiting...");
            return Ok(());
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
            anyhow::bail!("Timeout");
        }
        result = udp_sock.recv_from(&mut buf) => {
            match result {
                Ok((n, s)) => {
                    resp = HandshakeResponseMessage::try_from(&mut buf[..n])?;
                    println!("Received: {:?}", &resp);
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    // // Stage 2. Data keys derivation.
    match state {
        PeerState::InitialHandshake(data) => {
            state = process_handshake_response::<
                wg_rust_crypto::blake2::Blake2s,
                wg_rust_crypto::chacha20poly1305::ChaCha20Poly1305,
                wg_rust_crypto::x25519::X25519PublicKey,
            >(
                &mut buf,
                data,
                &initiator_static_secret,
                &initiator_ephemeral_secret,
            )?;
        }
        _ => {
            anyhow::bail!("Invalid state");
        }
    }

    match state {
        PeerState::Ready(mut data) => {
            // Setup TUN interface.
            let mut tun = create_tun(&IpAddr::from([10, 9, 0, 3]))?;
            // Start an event loop.
            loop {
                // Read from either the TUN interface or the UDP socket.
                tokio::select! {
                    n = tun.recv(&mut buf[16..]) => {
                        let n = n?;
                        let (mut packet, edata) = prepare_packet(&mut buf, 16, n, &mut data)?;
                        encrypt_data_in_place::<
                            chacha20poly1305::ChaCha20Poly1305,
                            chacha20poly1305::EncryptionBuffer,
                        >(
                            &mut packet.encrypted_encapsulated_packet_mut(),
                            edata.padded_len,
                            &data.sending_key,
                            edata.counter,
                        )?;
                        udp_sock.send_to(&packet.as_bytes(), peer).await?;
                        // println!("Sent: {:?}", &packet);
                    }
                    n = udp_sock.recv_from(&mut udp_buf) => {
                        let (n, _) = n?;
                        let mut packet = process_packet(&mut udp_buf[..n])?;
                        if data.receiving_key_counter.put(packet.counter()).is_none() {
                            println!("Received duplicated counter, dropping packet");
                            continue;
                        }
                        let counter = packet.counter();
                        decrypt_data_in_place::<
                            chacha20poly1305::ChaCha20Poly1305,
                            chacha20poly1305::EncryptionBuffer,
                        >(
                            packet.encrypted_encapsulated_packet_mut(),
                            &data.receiving_key,
                            counter,
                        )?;
                        // println!("Received: {:?}", &packet);
                        tun.write(&packet.encapsulated_packet()).ok();
                    }
                    _ = quit.recv() => {
                        println!("Received quit signal, exiting...");
                        break;
                    }
                }
            }
        }
        _ => {
            anyhow::bail!("Invalid state");
        }
    }

    // println!("Sending: {:?}", packet.as_bytes());

    // udp_sock.send_to(packet.as_bytes(), peer).await?;

    // let mut packet: PacketData;

    // tokio::select! {
    //     _ = quit.recv() => {
    //         println!("Received quit signal, exiting...");
    //         return Ok(());
    //     }
    //     // _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
    //     //     anyhow::bail!("Timeout");
    //     // }
    //     result = udp_sock.recv_from(&mut buf) => {
    //         match result {
    //             Ok((n, s)) => {
    //                 println!("Received: {:?}", &buf[..n]);
    //                 packet = PacketData::try_from(&mut buf[..n])?;
    //             }
    //             Err(e) => {
    //                 return Err(e.into());
    //             }
    //         }
    //     }
    // }

    // // Decrypt the packet
    // let data = chacha20poly1305::ChaCha20Poly1305::aead_decrypt(
    //     &receiving_key,
    //     receiving_key_counter,
    //     &packet.encrypted_encapsulated_packet(),
    //     &[],
    // )?;

    // println!("Decrypted data: {:?}", data);

    Ok(())
}
