use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionBufferError {}

/// A trait for ChaCha20Poly1305 AEAD in-place encryption buffer.
pub trait EncryptionBuffer<'a>: AsRef<[u8]> + AsMut<[u8]> {
    fn new(data: &'a mut [u8], len: usize) -> Self;

    fn set_poly1305_tag(&mut self, tag: &[u8]) -> Result<(), EncryptionBufferError>;

    fn is_empty(&self) -> bool;

    fn len(&self) -> usize;
}

#[derive(Debug, Error)]
pub enum ChaCha20Poly1305Error {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

/// A trait for ChaCha20Poly1305 AEAD encryption.
pub trait ChaCha20Poly1305 {
    /// Encrypt buffer in place using the given key, counter, and associated data.
    fn aead_encrypt_in_place<'a>(
        buffer: impl EncryptionBuffer<'a> + 'a,
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), ChaCha20Poly1305Error>;

    /// Decrypt buffer in place using the given key, counter, and associated data.
    fn aead_decrypt_in_place<'a>(
        buffer: impl EncryptionBuffer<'a> + 'a,
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), ChaCha20Poly1305Error>;
}
