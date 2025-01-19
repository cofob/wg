mod log_setup;
mod types;

use anyhow::Result;
use base64::prelude::*;
use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::aead::{Aead, AeadMutInPlace, Buffer};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use packet::Builder;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::UdpSocket;
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret, StaticSecret};

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
    let result = Blake2s256::new()
        .chain_update(&o_key_pad)
        .chain_update(&inner_hash)
        .finalize();

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

// Function to perform AEAD encryption in buffer
fn aead_encrypt_in_place(
    buf: &mut impl Buffer,
    key: &[u8; 32],
    counter: u64,
    associated_data: &[u8],
) {
    use chacha20poly1305::KeyInit;

    let mut cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Create nonce with 32 bits of zeros followed by 64-bit little-endian counter
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce);

    // Encrypt the plaintext
    cipher
        .encrypt_in_place(nonce, associated_data, buf)
        .expect("Encryption failed")
}

#[derive(Clone, Copy, Debug)]
enum MessageType {
    HandshakeInitiation,
    HandshakeResponse,
    CookieReply,
    Data,
}

impl MessageType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::HandshakeInitiation),
            2 => Some(Self::HandshakeResponse),
            3 => Some(Self::CookieReply),
            4 => Some(Self::Data),
            _ => None,
        }
    }

    fn to_u8(&self) -> u8 {
        match self {
            Self::HandshakeInitiation => 1,
            Self::HandshakeResponse => 2,
            Self::CookieReply => 3,
            Self::Data => 4,
        }
    }
}

struct HandshakeInitiationMessage {
    data: [u8; 148],
}

impl HandshakeInitiationMessage {
    /// Create a new HandshakeInitiationMessage with all fields set to zero (except the message type).
    fn new() -> Self {
        let mut data = [0; 148];
        data[0] = MessageType::HandshakeInitiation.to_u8();
        HandshakeInitiationMessage { data }
    }

    /// Serialize the HandshakeInitiationMessage into a byte vector.
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Deserialize a HandshakeInitiationMessage from a byte slice.
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let mut data = [0; 148];
        data.copy_from_slice(bytes.as_ref());
        HandshakeInitiationMessage { data }
    }

    /// Get the message type.
    ///
    /// Always returns [`MessageType::HandshakeInitiation`].
    fn message_type(&self) -> MessageType {
        MessageType::from_u8(self.data[0]).expect("Invalid message type")
    }

    /// Set the message type.
    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.data[0] = message_type.to_u8();
        self
    }

    /// Get the sender index.
    fn sender_index(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Set the sender index.
    fn set_sender_index(&mut self, sender_index: u32) -> &mut Self {
        self.data[4..8].copy_from_slice(&sender_index.to_le_bytes());
        self
    }

    /// Get the unencrypted ephemeral public key.
    fn unencrypted_ephemeral(&self) -> &[u8] {
        &self.data[8..40]
    }

    /// Get the unencrypted ephemeral public key as a PublicKey.
    fn unencrypted_ephemeral_public(&self) -> PublicKey {
        let public_key_data = <&[u8; 32]>::try_from(self.unencrypted_ephemeral())
            .unwrap()
            .clone();
        PublicKey::from(public_key_data)
    }

    /// Set the unencrypted ephemeral public key.
    fn set_unencrypted_ephemeral(&mut self, ephemeral: impl AsRef<[u8]>) -> &mut Self {
        self.data[8..40].copy_from_slice(ephemeral.as_ref());
        self
    }

    /// Get the encrypted static public key.
    fn encrypted_static(&self) -> &[u8] {
        &self.data[40..88]
    }

    /// Set the encrypted static public key.
    fn set_encrypted_static(&mut self, static_key: impl AsRef<[u8]>) -> &mut Self {
        self.data[40..88].copy_from_slice(static_key.as_ref());
        self
    }

    /// Get the encrypted timestamp.
    fn encrypted_timestamp(&self) -> &[u8] {
        &self.data[88..116]
    }

    /// Set the encrypted timestamp.
    fn set_encrypted_timestamp(&mut self, timestamp: impl AsRef<[u8]>) -> &mut Self {
        self.data[88..116].copy_from_slice(timestamp.as_ref());
        self
    }

    /// Get the MAC1 field.
    fn mac1(&self) -> &[u8] {
        &self.data[116..132]
    }

    /// Set the MAC1 field.
    fn set_mac1(&mut self, mac1: impl AsRef<[u8]>) -> &mut Self {
        self.data[116..132].copy_from_slice(mac1.as_ref());
        self
    }

    /// Get message content for MAC1.
    fn mac1_content(&self) -> &[u8] {
        &self.data[..116]
    }

    /// Get the MAC2 field.
    fn mac2(&self) -> &[u8] {
        &self.data[132..148]
    }

    /// Set the MAC2 field.
    fn set_mac2(&mut self, mac2: impl AsRef<[u8]>) -> &mut Self {
        self.data[132..148].copy_from_slice(mac2.as_ref());
        self
    }

    /// Get message content for MAC2.
    fn mac2_content(&self) -> &[u8] {
        &self.data[..132]
    }
}

impl From<&HandshakeInitiationMessage> for Vec<u8> {
    fn from(value: &HandshakeInitiationMessage) -> Vec<u8> {
        value.to_bytes()
    }
}

impl From<[u8; 148]> for HandshakeInitiationMessage {
    fn from(value: [u8; 148]) -> Self {
        HandshakeInitiationMessage { data: value }
    }
}

impl TryFrom<&[u8]> for HandshakeInitiationMessage {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value[0] != MessageType::HandshakeInitiation.to_u8() {
            anyhow::bail!("Invalid message type");
        }
        let data: [u8; 148] = value.try_into()?;
        Ok(HandshakeInitiationMessage { data })
    }
}

impl std::fmt::Debug for HandshakeInitiationMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitiationMessage")
            .field("message_type", &self.message_type())
            .field("sender_index", &self.sender_index())
            .field("unencrypted_ephemeral", &self.unencrypted_ephemeral())
            .field("encrypted_static", &self.encrypted_static())
            .field("encrypted_timestamp", &self.encrypted_timestamp())
            .field("mac1", &self.mac1())
            .field("mac2", &self.mac2())
            .finish()
    }
}

impl AsRef<[u8]> for HandshakeInitiationMessage {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

struct HandshakeResponseMessage {
    data: [u8; 92],
}

impl HandshakeResponseMessage {
    /// Create a new HandshakeResponseMessage with all fields set to zero (except the message type).
    fn new() -> Self {
        let mut data = [0; 92];
        data[0] = MessageType::HandshakeResponse.to_u8();
        HandshakeResponseMessage { data }
    }

    /// Serialize the HandshakeResponseMessage into a byte vector.
    fn to_bytes(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Deserialize a HandshakeResponseMessage from a byte slice.
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let mut data = [0; 92];
        data.copy_from_slice(bytes.as_ref());
        if data[0] != MessageType::HandshakeResponse.to_u8() {
            panic!("Invalid message type");
        }
        HandshakeResponseMessage { data }
    }

    /// Get the message type.
    ///
    /// Always returns [`MessageType::HandshakeResponse`].
    fn message_type(&self) -> MessageType {
        MessageType::from_u8(self.data[0]).expect("Invalid message type")
    }

    /// Set the message type.
    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.data[0] = message_type.to_u8();
        self
    }

    /// Get the sender index.
    fn sender_index(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Get the sender index as byte slice.
    fn sender_index_bytes(&self) -> &[u8] {
        &self.data[4..8]
    }

    /// Set the sender index.
    fn set_sender_index(&mut self, sender_index: u32) -> &mut Self {
        self.data[4..8].copy_from_slice(&sender_index.to_le_bytes());
        self
    }

    /// Get the receiver index.
    fn receiver_index(&self) -> u32 {
        u32::from_le_bytes([self.data[8], self.data[9], self.data[10], self.data[11]])
    }

    /// Get the receiver index as byte slice.
    fn receiver_index_bytes(&self) -> &[u8] {
        &self.data[8..12]
    }

    /// Set the receiver index.
    fn set_receiver_index(&mut self, receiver_index: u32) -> &mut Self {
        self.data[8..12].copy_from_slice(&receiver_index.to_le_bytes());
        self
    }

    /// Get the unencrypted ephemeral public key.
    fn unencrypted_ephemeral(&self) -> &[u8] {
        &self.data[12..44]
    }

    /// Get the unencrypted ephemeral public key as a PublicKey.
    fn unencrypted_ephemeral_public(&self) -> PublicKey {
        let public_key_data = <&[u8; 32]>::try_from(self.unencrypted_ephemeral())
            .unwrap()
            .clone();
        PublicKey::from(public_key_data)
    }

    /// Set the unencrypted ephemeral public key.
    fn set_unencrypted_ephemeral(&mut self, ephemeral: impl AsRef<[u8]>) -> &mut Self {
        self.data[12..44].copy_from_slice(ephemeral.as_ref());
        self
    }

    /// Get the encrypted nothing.
    fn encrypted_nothing(&self) -> &[u8] {
        &self.data[44..60]
    }

    /// Set the encrypted nothing.
    fn set_encrypted_nothing(&mut self, nothing: impl AsRef<[u8]>) -> &mut Self {
        self.data[44..60].copy_from_slice(nothing.as_ref());
        self
    }

    /// Get the MAC1 field.
    fn mac1(&self) -> &[u8] {
        &self.data[60..76]
    }

    /// Set the MAC1 field.
    fn set_mac1(&mut self, mac1: impl AsRef<[u8]>) -> &mut Self {
        self.data[60..76].copy_from_slice(mac1.as_ref());
        self
    }

    /// Get message content for MAC1.
    fn mac1_content(&self) -> &[u8] {
        &self.data[..60]
    }

    /// Get the MAC2 field.
    fn mac2(&self) -> &[u8] {
        &self.data[76..92]
    }

    /// Set the MAC2 field.
    fn set_mac2(&mut self, mac2: impl AsRef<[u8]>) -> &mut Self {
        self.data[76..92].copy_from_slice(mac2.as_ref());
        self
    }

    /// Get message content for MAC2.
    fn mac2_content(&self) -> &[u8] {
        &self.data[..76]
    }
}

impl From<&HandshakeResponseMessage> for Vec<u8> {
    fn from(value: &HandshakeResponseMessage) -> Vec<u8> {
        value.to_bytes()
    }
}

impl From<[u8; 92]> for HandshakeResponseMessage {
    fn from(value: [u8; 92]) -> Self {
        if value[0] != MessageType::HandshakeResponse.to_u8() {
            panic!("Invalid message type");
        }
        HandshakeResponseMessage { data: value }
    }
}

impl TryFrom<&[u8]> for HandshakeResponseMessage {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value[0] != MessageType::HandshakeResponse.to_u8() {
            anyhow::bail!("Invalid message type");
        }
        let data: [u8; 92] = value.try_into()?;
        Ok(HandshakeResponseMessage { data })
    }
}

impl std::fmt::Debug for HandshakeResponseMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeResponseMessage")
            .field("message_type", &self.message_type())
            .field("sender_index", &self.sender_index())
            .field("receiver_index", &self.receiver_index())
            .field("unencrypted_ephemeral", &self.unencrypted_ephemeral())
            .field("encrypted_nothing", &self.encrypted_nothing())
            .field("mac1", &self.mac1())
            .field("mac2", &self.mac2())
            .finish()
    }
}

impl AsRef<[u8]> for HandshakeResponseMessage {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

struct PacketData<'a> {
    data: &'a [u8],
}

impl<'a> PacketData<'a> {
    /// Construct a new PacketData bytes from the given fields.
    fn construct_data(
        receiver_index: &[u8],
        counter: u64,
        encrypted_encapsulated_packet: &'a [u8],
    ) -> Vec<u8> {
        let mut data = vec![0u8; 16 + encrypted_encapsulated_packet.len()];
        data[0] = MessageType::Data.to_u8();
        data[4..8].copy_from_slice(&receiver_index);
        data[8..16].copy_from_slice(&counter.to_le_bytes());
        data[16..].copy_from_slice(encrypted_encapsulated_packet);
        data
    }

    /// Create a new PacketData from a byte slice.
    fn from_bytes(bytes: &'a [u8]) -> Self {
        PacketData { data: bytes }
    }

    /// Get the message type.
    ///
    /// Always returns [`MessageType::DataPacket`].
    fn message_type(&self) -> MessageType {
        MessageType::from_u8(self.data[0]).expect("Invalid message type")
    }

    /// Get the receiver index.
    fn receiver_index(&self) -> u32 {
        u32::from_le_bytes([self.data[4], self.data[5], self.data[6], self.data[7]])
    }

    /// Get the counter.
    fn counter(&self) -> u64 {
        u64::from_le_bytes([
            self.data[8],
            self.data[9],
            self.data[10],
            self.data[11],
            self.data[12],
            self.data[13],
            self.data[14],
            self.data[15],
        ])
    }

    /// Get the encrypted encapsulated packet.
    fn encrypted_encapsulated_packet(&self) -> &[u8] {
        &self.data[16..]
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketData<'a> {
    type Error = anyhow::Error;

    fn try_from(value: &'a [u8]) -> Result<Self> {
        if value[0] != MessageType::Data.to_u8() {
            anyhow::bail!("Invalid message type");
        }
        Ok(PacketData { data: value })
    }
}

impl std::fmt::Debug for PacketData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketData")
            .field("message_type", &self.message_type())
            .field("receiver_index", &self.receiver_index())
            .field("counter", &self.counter())
            .field(
                "encrypted_encapsulated_packet_len",
                &self.encrypted_encapsulated_packet().len(),
            )
            .finish()
    }
}

impl AsRef<[u8]> for PacketData<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

struct AnswerBuffer<'a> {
    data: &'a mut [u8],
    filled_pos: usize,
}

impl<'a> AnswerBuffer<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        AnswerBuffer {
            data,
            filled_pos: 0,
        }
    }
}

impl Buffer for AnswerBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        let len = other.len();
        if self.filled_pos + len > self.data.len() {
            return Err(chacha20poly1305::aead::Error);
        }
        self.data[self.filled_pos..self.filled_pos + len].copy_from_slice(other);
        self.filled_pos += len;
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn truncate(&mut self, _len: usize) {
        // do nothing
    }
}

impl AsMut<[u8]> for AnswerBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl AsRef<[u8]> for AnswerBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
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
    let ephemeral_secret = ReusableSecret::random_from_rng(&mut rng);
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
    let mut msg = HandshakeInitiationMessage::new();

    // Generate a random 4-byte sender index
    // msg.sender_index = little_endian(initiator.sender_index)
    let sender_index = rand::random::<u32>();
    msg.set_sender_index(sender_index);

    // Next - 32 bytes of public ephemeral Curve25519 key
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    msg.set_unencrypted_ephemeral(&ephemeral_public);

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

    msg.set_encrypted_static(&encrypted_static);

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

    msg.set_encrypted_timestamp(&encrypted_timestamp);

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let mac1 = mac_blake2s_128(
        &blake2s_256(&vec![LABEL_MAC1.as_bytes(), responder_static_public.as_bytes()].concat()),
        &msg.mac1_content(),
    );
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
                    resp = HandshakeResponseMessage::try_from(&buf[..n])?;
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
    let hash = blake2s_256(&vec![hash.to_vec(), resp.unencrypted_ephemeral().to_vec()].concat());

    // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
    let temp = hmac_blake2s_256(&chaining_key, resp.unencrypted_ephemeral());

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac_blake2s_256(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
    let dh_result = ephemeral_secret.diffie_hellman(&resp.unencrypted_ephemeral_public());
    let temp = hmac_blake2s_256(&chaining_key, dh_result.as_bytes());

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac_blake2s_256(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
    let dh_result = initiator_static_private.diffie_hellman(&resp.unencrypted_ephemeral_public());
    let temp = hmac_blake2s_256(&chaining_key, dh_result.as_bytes());

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac_blake2s_256(&temp, &[0x1]);

    // temp = HMAC(responder.chaining_key, preshared_key)
    let temp = hmac_blake2s_256(&chaining_key, &[0u8; 32]);

    // responder.chaining_key = HMAC(temp, 0x1)
    let chaining_key = hmac_blake2s_256(&temp, &[0x1]);

    // temp2 = HMAC(temp, responder.chaining_key || 0x2)
    let temp2 = hmac_blake2s_256(&temp, &vec![chaining_key.to_vec(), [0x2].to_vec()].concat());

    // key = HMAC(temp, temp2 || 0x3)
    let key = hmac_blake2s_256(&temp, &vec![temp2.to_vec(), [0x3].to_vec()].concat());

    // responder.hash = HASH(responder.hash || temp2)
    let hash = blake2s_256(&vec![hash.to_vec(), temp2.to_vec()].concat());

    // decrypt msg.encrypted_nothing
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key as ChachaKey, KeyInit, Nonce};

    let cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(&key));
    let nonce_zero = [0u8; 12]; // 32 bits of zeros + 64-bit counter=0
    let nothing_plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce_zero),
            Payload {
                msg: resp.encrypted_nothing(),
                aad: &hash,
            },
        )
        .map_err(|_| anyhow::anyhow!("Decrypting 'encrypted_nothing' failed."))?;

    if !nothing_plain.is_empty() {
        anyhow::bail!("Responder's 'encrypted_nothing' decrypted to non-empty data!?");
    }

    println!("Decrypted 'encrypted_nothing' to empty data.");

    // temp1 = HMAC(initiator.chaining_key, [empty])
    let temp1 = hmac_blake2s_256(&chaining_key, &[]);
    // temp2 = HMAC(temp1, 0x1)
    let temp2 = hmac_blake2s_256(&temp1, &[0x1]);
    // temp3 = HMAC(temp1, temp2 || 0x2)
    let temp3 = hmac_blake2s_256(&temp1, &vec![temp2.to_vec(), [0x2].to_vec()].concat());
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
    let answer_buffer_len = icmp_data.len() + 32;
    let mut answer_buffer = [0u8; u16::MAX as usize];
    // let mut answer_buffer = Vec::with_capacity(icmp_data.len() + 32);

    let receiver_index = resp.sender_index_bytes();

    // counter = initiator.sending_key_counter++
    // sending_key_counter += 1;

    answer_buffer[0] = MessageType::Data.to_u8();
    // answer_buffer.push(MessageType::Data.to_u8());
    // answer_buffer.extend_from_slice(&[0u8; 3]);
    answer_buffer[4..8].copy_from_slice(receiver_index);
    // answer_buffer.extend_from_slice(receiver_index);
    answer_buffer[8..16].copy_from_slice(&sending_key_counter.to_le_bytes());
    // answer_buffer.extend_from_slice(&sending_key_counter.to_le_bytes());

    // msg.encrypted_encapsulated_packet = AEAD(initiator.sending_key, counter, encapsulated_packet, [empty])
    // let encrypted_encapsulated_packet =
    //     aead_encrypt(&sending_key, sending_key_counter, &icmp_data, &[]);
    aead_encrypt_in_place(
        &mut AnswerBuffer::new(&mut answer_buffer[16..answer_buffer_len]),
        &sending_key,
        sending_key_counter,
        &[],
    );

    // answer_buffer.extend_from_slice(&encrypted_encapsulated_packet);

    let packet = &answer_buffer[..answer_buffer_len];
    // let packet = &answer_buffer;

    println!("Sending: {:?}", packet);

    udp_sock.send_to(packet, peer).await?;

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
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}
