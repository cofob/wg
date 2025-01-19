mod log_setup;
mod types;

use anyhow::Result;
use base64::prelude::*;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

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

const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &str = "mac1----";

// Function to compute a BLAKE2s hash with 32-byte output
// HASH(input): Blake2s(input, 32), returning 32 bytes of output
fn blake2s_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake2::Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// HMAC(key, input): HMAC-Blake2s(key, input, 32)
fn hmac_blake2s_256(key: &[u8], input: &[u8]) -> [u8; 32] {
    // BLAKE2s has a 64-byte internal block size:
    const BLOCK_SIZE: usize = 64;

    // 1) If `key` is longer than BLOCK_SIZE, reduce it by hashing once with BLAKE2s.
    let mut shortened_key = if key.len() > BLOCK_SIZE {
        let mut hasher = Blake2s256::new();
        hasher.update(key);
        hasher.finalize().to_vec() // 32-byte digest
    } else {
        key.to_vec()
    };

    // 2) Pad `shortened_key` to exactly BLOCK_SIZE bytes with zeros.
    shortened_key.resize(BLOCK_SIZE, 0);

    // 3) Create the inner (ipad) and outer (opad) padded keys.
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    let mut o_key_pad = [0u8; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        i_key_pad[i] = shortened_key[i] ^ 0x36; // 0x36 = ipad
        o_key_pad[i] = shortened_key[i] ^ 0x5C; // 0x5C = opad
    }

    // 4) Inner hash: H(i_key_pad || message)
    let inner_hash = Blake2s256::new()
        .chain_update(&i_key_pad)
        .chain_update(input)
        .finalize();

    // 5) Outer hash: H(o_key_pad || inner_hash)
    let result = Blake2s256::new().chain_update(&o_key_pad).chain_update(&inner_hash).finalize();

    // 6) Produce final 32-byte HMAC value
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// MAC(key, input): Keyed-Blake2s(key, input, 16)
fn mac_blake2s_128(key: &[u8], input: &[u8]) -> [u8; 16] {
    use blake2::digest::Mac;
    let result = Blake2sMac::<blake2::digest::consts::U16>::new_from_slice(key)
        .expect("Keyed BLAKE2s can use up to 32-byte keys")
        .chain_update(input)
        .finalize()
        .into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

// Function to perform AEAD encryption
fn aead_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
    use chacha20poly1305::KeyInit;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Create nonce with 32 bits of zeros followed by 64-bit little-endian counter
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    // Encrypt the plaintext
    cipher
        .encrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("Encryption failed")
}

async fn main_entry(mut quit: tokio::sync::mpsc::Receiver<()>) -> Result<()> {
    // Rng
    let mut rng = rand::thread_rng();

    // Load the static keys
    let mut initiator_static_private_buf: [u8; 32] = [0; 32];
    initiator_static_private_buf
        .copy_from_slice(&BASE64_STANDARD.decode("kLSlfaoabpt64dRjpuhQZP44ZQBMGXelGPPi0xdImmI=")?);
    let initiator_static_private = StaticSecret::from(initiator_static_private_buf);
    let initiator_static_public = PublicKey::from(&initiator_static_private);

    let mut responder_static_public_buf: [u8; 32] = [0; 32];
    responder_static_public_buf
        .copy_from_slice(&BASE64_STANDARD.decode("/GWGlDyUlq3T6zyAGT0l4Yy93JbOnDwyizbTEcyQi00=")?);
    let responder_static_public = PublicKey::from(responder_static_public_buf);

    // Generate an ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Compute hashes
    // initiator.chaining_key = HASH(CONSTRUCTION)
    let chaining_key = blake2s_256(CONSTRUCTION.as_bytes());
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let hash = blake2s_256(&vec![chaining_key.to_vec(), IDENTIFIER.as_bytes().to_vec()].concat());
    let hash =
        blake2s_256(&vec![hash.to_vec(), responder_static_public.as_bytes().to_vec()].concat());

    // First byte - message type (0x1 for request, 0x2 for response)
    // Second to fourth byte - reserved zeroes
    // msg.message_type = 1
    // msg.reserved_zero = { 0, 0, 0 }
    let mut buf: Vec<u8> = vec![0x1, 0x0, 0x0, 0x0];

    // Generate a random 4-byte sender index
    // msg.sender_index = little_endian(initiator.sender_index)
    let sender_index = rand::random::<u32>().to_le_bytes();
    buf.extend_from_slice(&sender_index);

    // Next - 32 bytes of public ephemeral Curve25519 key
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    buf.extend_from_slice(ephemeral_public.as_bytes());

    // Extend hash with the message
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    let hash = blake2s_256(&vec![hash.to_vec(), ephemeral_public.as_bytes().to_vec()].concat());

    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    let temp = hmac_blake2s_256(&chaining_key, ephemeral_public.as_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let message: [u8; 1] = [0x1];
    let chaining_key = hmac_blake2s_256(&temp, &message);

    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let dh_result = ephemeral_secret.diffie_hellman(&responder_static_public);
    let temp = hmac_blake2s_256(&chaining_key, dh_result.as_bytes());

    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac_blake2s_256(&temp, &message);

    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = hmac_blake2s_256(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat());

    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    let encrypted_static = aead_encrypt(&key, 0, initiator_static_public.as_bytes(), &hash);
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    let hash = blake2s_256(&vec![hash.to_vec(), encrypted_static.to_vec()].concat());

    buf.extend_from_slice(&encrypted_static);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let dh_result = initiator_static_private.diffie_hellman(&responder_static_public);
    let temp = hmac_blake2s_256(&chaining_key, dh_result.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac_blake2s_256(&temp, &message);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = hmac_blake2s_256(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat());

    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let encrypted_timestamp = aead_encrypt(&key, 0, &tai64::Tai64N::now().to_bytes(), &hash);
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    let hash = blake2s_256(&vec![hash.to_vec(), encrypted_timestamp.clone()].concat());

    buf.extend_from_slice(&encrypted_timestamp);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let mac1 = mac_blake2s_128(
        &blake2s_256(&vec![LABEL_MAC1.as_bytes(), responder_static_public.as_bytes()].concat()),
        &buf,
    );
    buf.extend_from_slice(&mac1);

    // mac2
    // if (initiator.last_received_cookie is empty or expired)
    //     msg.mac2 = [zeros]
    // else
    //     msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
    buf.extend_from_slice(&[0u8; 16]);

    println!("Sending: {:?}", buf);

    let peer = SocketAddr::from(([159, 89, 2, 36], 62068));
    let udp_sock = UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0")?).await?;

    udp_sock.send_to(&buf, peer).await?;

    // Listen for response
    let mut buf = [0u8; 2048];

    tokio::select! {
        _ = quit.recv() => {
            println!("Received quit signal, exiting...");
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
            println!("Timeout");
        }
        result = udp_sock.recv_from(&mut buf) => {
            match result {
                Ok((n, s)) => {
                    println!("Received response from {}: {:?}", s, &buf[..n]);
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
        }
    }

    Ok(())
}
