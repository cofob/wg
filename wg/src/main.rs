mod log_setup;

use anyhow::Result;
use base64::prelude::*;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::UdpSocket;
use wg_proto::{
    crypto::{
        blake2::{Blake2sHash, Blake2sHmac, Blake2sMac},
        chacha20poly1305::{ChaCha20Poly1305, EncryptionBuffer},
        tai64::Tai64N,
        x25519::{X25519OperableSecretKey, X25519PublicKey, X25519StaticSecret},
    },
    data_types::{HandshakeInitiationMessage, HandshakeResponseMessage, MessageType, PacketData},
};
use wg_rust_crypto::{blake2::Blake2s, chacha20poly1305, tai64, x25519};

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
    // Load the static keys
    let mut initiator_static_private_buf: [u8; 32] = [0; 32];
    initiator_static_private_buf
        .copy_from_slice(&BASE64_STANDARD.decode("kLSlfaoabpt64dRjpuhQZP44ZQBMGXelGPPi0xdImmI=")?);
    let initiator_static_private =
        wg_rust_crypto::x25519::X25519StaticSecret::from_bytes(&initiator_static_private_buf)?;
    let initiator_static_public = initiator_static_private.public_key()?;

    let mut responder_static_public_buf: [u8; 32] = [0; 32];
    responder_static_public_buf
        .copy_from_slice(&BASE64_STANDARD.decode("/GWGlDyUlq3T6zyAGT0l4Yy93JbOnDwyizbTEcyQi00=")?);
    let responder_static_public =
        wg_rust_crypto::x25519::X25519PublicKey::from_bytes(&responder_static_public_buf)?;

    // Generate an ephemeral keypair
    let ephemeral_secret = wg_rust_crypto::x25519::X25519EphemeralSecret::generate();
    let ephemeral_public = ephemeral_secret.public_key()?;

    // Compute hashes
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let chaining_key = Blake2s::hash(wg_proto::consts::CONSTRUCTION.as_bytes())?;
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let hash = Blake2s::hash(
        &vec![
            chaining_key.to_vec(),
            wg_proto::consts::IDENTIFIER.as_bytes().to_vec(),
        ]
        .concat(),
    )?;
    let hash =
        Blake2s::hash(&vec![hash.to_vec(), responder_static_public.to_bytes().to_vec()].concat())?;

    let mut msg_data = HandshakeInitiationMessage::init();
    let mut msg = HandshakeInitiationMessage::from_bytes_unchecked(&mut msg_data);

    // Generate a random 4-byte sender index
    // msg.sender_index = little_endian(initiator.sender_index)
    let sender_index = rand::random::<u32>();
    msg.set_sender_index(sender_index);

    // Next - 32 bytes of public ephemeral Curve25519 key
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    msg.set_unencrypted_ephemeral(ephemeral_public.to_bytes());

    // Extend hash with the message
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    let hash = Blake2s::hash(&vec![hash.to_vec(), ephemeral_public.to_bytes().to_vec()].concat())?;

    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    let temp = Blake2s::hmac(&chaining_key, ephemeral_public.to_bytes())?;

    // initiator.chaining_key = HMAC(temp, 0x1)
    let message: [u8; 1] = [0x1];
    let chaining_key = Blake2s::hmac(&temp, &message)?;

    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let dh_result = ephemeral_secret.diffie_hellman(&responder_static_public)?;
    let temp = Blake2s::hmac(&chaining_key, &dh_result)?;

    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = Blake2s::hmac(&temp, &message)?;

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = Blake2s::hmac(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat())?;

    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    let encrypted_static = chacha20poly1305::ChaCha20Poly1305::aead_encrypt(
        &key,
        0,
        initiator_static_public.to_bytes(),
        &hash,
    )?;
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    let hash = Blake2s::hash(&vec![hash.to_vec(), encrypted_static.to_vec()].concat())?;

    msg.set_encrypted_static(&encrypted_static);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let dh_result = initiator_static_private.diffie_hellman(&responder_static_public)?;
    let temp = Blake2s::hmac(&chaining_key, &dh_result)?;
    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = Blake2s::hmac(&temp, &message)?;
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = Blake2s::hmac(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat())?;

    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let encrypted_timestamp = chacha20poly1305::ChaCha20Poly1305::aead_encrypt(
        &key,
        0,
        &wg_rust_crypto::tai64::Tai64N::now().to_bytes(),
        &hash,
    )?;
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    let hash = Blake2s::hash(&vec![hash.to_vec(), encrypted_timestamp.clone()].concat())?;

    msg.set_encrypted_timestamp(&encrypted_timestamp);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let mac1 = Blake2s::mac(
        &Blake2s::hash(
            &vec![
                wg_proto::consts::LABEL_MAC1.as_bytes(),
                responder_static_public.to_bytes(),
            ]
            .concat(),
        )?,
        &msg.mac1_content(),
    )?;
    msg.set_mac1(&mac1);

    // mac2
    // if (initiator.last_received_cookie is empty or expired)
    //     msg.mac2 = [zeros]
    // else
    //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
    // buf.extend_from_slice(&[0u8; 16]);

    println!("Sending: {:?}", msg);

    let peer = SocketAddr::from(([159, 89, 2, 36], 62068));
    let udp_sock = UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0")?).await?;
    println!("UDP socket bound to: {:?}", udp_sock.local_addr()?);

    udp_sock.send_to(msg.as_ref(), peer).await?;

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
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    // Stage 2. Data keys derivation.
    println!("Received: {:?}", resp);

    // responser.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
    let hash = Blake2s::hash(&vec![hash.to_vec(), resp.unencrypted_ephemeral().to_vec()].concat())?;

    // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
    let temp = Blake2s::hmac(&chaining_key, resp.unencrypted_ephemeral())?;

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = Blake2s::hmac(&temp, &[0x1])?;

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
    let unencrypted_ephemeral = x25519::X25519PublicKey::from_bytes(resp.unencrypted_ephemeral())?;
    let dh_result = ephemeral_secret.diffie_hellman(&unencrypted_ephemeral)?;
    let temp = Blake2s::hmac(&chaining_key, &dh_result)?;

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = Blake2s::hmac(&temp, &[0x1])?;

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
    let dh_result = initiator_static_private.diffie_hellman(&unencrypted_ephemeral)?;
    let temp = Blake2s::hmac(&chaining_key, &dh_result)?;

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = Blake2s::hmac(&temp, &[0x1])?;

    // temp = HMAC(responder.chaining_key, preshared_key)
    let temp = Blake2s::hmac(&chaining_key, &[0u8; 32])?;

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = Blake2s::hmac(&temp, &[0x1])?;

    // temp2 = HMAC(temp, responder.chaining_key || 0x2)
    let temp2 = Blake2s::hmac(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat())?;

    // key = HMAC(temp, temp2 || 0x3)
    let key = Blake2s::hmac(&temp, &vec![temp2.to_vec(), [0x3].to_vec()].concat())?;

    // responder.hash = HASH(responder.hash || temp2)
    let hash = Blake2s::hash(&vec![hash.to_vec(), temp2.to_vec()].concat())?;

    // decrypt msg.encrypted_nothing
    let nothing_plain =
        chacha20poly1305::ChaCha20Poly1305::aead_decrypt(&key, 0, resp.encrypted_nothing(), &hash)
            .map_err(|_| anyhow::anyhow!("Decrypting 'encrypted_nothing' failed."))?;

    if !nothing_plain.is_empty() {
        anyhow::bail!("Responder's 'encrypted_nothing' decrypted to non-empty data!?");
    }

    println!("Decrypted 'encrypted_nothing' to empty data.");

    // temp1 = HMAC(initiator.chaining_key, [empty])
    let temp1 = Blake2s::hmac(&chaining_key, &[])?;
    // temp2 = HMAC(temp1, 0x1)
    let temp2 = Blake2s::hmac(&temp1, &[0x1])?;
    // temp3 = HMAC(temp1, temp2 || 0x2)
    let temp3 = Blake2s::hmac(&temp1, &vec![temp2.to_vec(), [0x2].to_vec()].concat())?;
    // initiator.sending_key = temp2
    let sending_key = temp2;
    // initiator.receiving_key = temp3
    let receiving_key = temp3;
    // initiator.sending_key_counter = 0
    let mut sending_key_counter: u64 = 0;
    // initiator.receiving_key_counter = 0
    let mut receiving_key_counter: u64 = 0;

    let mut icmp_data = BASE64_STANDARD.decode("RQAAVCmiQABAAa33CgkAAwoJAAEIAEBuAB8AAZ0pjWcAAAAAyw0DAAAAAAAQERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3")?;

    // let mut icmp_data = packet::ip::v4::Builder::default()
    //     .id(0x42)?
    //     .ttl(64)?
    //     .source("10.9.0.3".parse()?)?
    //     .destination("10.9.0.1".parse()?)?
    //     .icmp()?
    //     .echo()?
    //     .request()?
    //     .identifier(31)?
    //     .sequence(1)?
    //     .payload(&[0u8; 32])?
    //     .build()?;

    // encapsulated_packet = encapsulated_packet || zero padding in order to make the length a multiple of 16
    if icmp_data.len() % 16 != 0 {
        // Pad the data to a multiple of 16 bytes
        let padding = 16 - (icmp_data.len() % 16);
        icmp_data.extend_from_slice(&vec![0u8; padding]);
    }

    println!("Encapsulated packet: {:?}", icmp_data);

    // Get the length of the answer buffer including AEAD overhead and packet header
    let mut answer_buffer = [0u8; u16::MAX as usize];
    let answer_buffer_len = icmp_data.len() + 32;

    // Write the packet in the answer buffer with 16 byte offset
    answer_buffer[16..16 + icmp_data.len()].copy_from_slice(&icmp_data);

    let mut packet = PacketData::from_bytes_unchecked(&mut answer_buffer[..answer_buffer_len]);
    packet.prepare_data();

    // let mut answer_buffer = Vec::with_capacity(icmp_data.len() + 32);

    let receiver_index = resp.sender_index_bytes();

    // counter = initiator.sending_key_counter++
    // sending_key_counter += 1;

    packet.set_receiver_index(receiver_index);
    packet.set_counter(sending_key_counter);

    chacha20poly1305::ChaCha20Poly1305::aead_encrypt_in_place(
        &mut chacha20poly1305::EncryptionBuffer::new(
            packet.encrypted_encapsulated_packet_mut(),
            icmp_data.len(),
        ),
        &sending_key,
        sending_key_counter,
        &[],
    )?;

    println!("Sending: {:?}", packet.as_bytes());

    udp_sock.send_to(packet.as_bytes(), peer).await?;

    let mut packet: PacketData;

    tokio::select! {
        _ = quit.recv() => {
            println!("Received quit signal, exiting...");
            return Ok(());
        }
        // _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
        //     anyhow::bail!("Timeout");
        // }
        result = udp_sock.recv_from(&mut buf) => {
            match result {
                Ok((n, s)) => {
                    println!("Received: {:?}", &buf[..n]);
                    packet = PacketData::try_from(&mut buf[..n])?;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    // Decrypt the packet
    let data = chacha20poly1305::ChaCha20Poly1305::aead_decrypt(
        &receiving_key,
        receiving_key_counter,
        &packet.encrypted_encapsulated_packet(),
        &[],
    )?;

    println!("Decrypted data: {:?}", data);

    Ok(())
}
