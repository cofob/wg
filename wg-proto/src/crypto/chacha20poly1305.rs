use thiserror::Error;

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
    fn aead_encrypt_in_place(
        buffer: &mut [u8],
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), ChaCha20Poly1305Error>;

    /// Decrypt buffer in place using the given key, counter, and associated data.
    fn aead_decrypt_in_place(
        buffer: &mut [u8],
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), ChaCha20Poly1305Error>;
}
