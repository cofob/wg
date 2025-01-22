use crate::crypto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageDecodeError {
    #[error("Invalid message length")]
    InvalidLength,
    #[error("Invalid message type")]
    InvalidMessageType,
}

#[derive(Debug, Error)]
pub enum WgError {
    // Message errors
    #[error("Message decode error: {0}")]
    Decode(#[from] MessageDecodeError),

    // Crypto errors
    #[error("ChaCha20Poly1305 error: {0}")]
    ChaCha20Poly1305(#[from] crypto::chacha20poly1305::ChaCha20Poly1305Error),
    #[error("ChaCha20Poly1305 buffer error: {0}")]
    ChaCha20Poly1305Buffer(#[from] crypto::chacha20poly1305::EncryptionBufferError),
    #[error("X25519 error: {0}")]
    X25519(#[from] crypto::x25519::X25519Error),
    #[error("Tai64N error: {0}")]
    Tai64N(#[from] crypto::tai64::Tai64NError),
}
