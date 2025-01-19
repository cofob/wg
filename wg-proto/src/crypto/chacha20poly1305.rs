use std::error::Error;

/// A trait for ChaCha20Poly1305 AEAD in-place encryption buffer.
pub trait EncryptionBuffer<'a>: AsRef<[u8]> + AsMut<[u8]> {
    type Error: Error;

    fn new(data: &'a mut [u8], len: usize) -> Self;

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Self::Error>;

    fn is_empty(&self) -> bool;

    fn len(&self) -> usize;

    fn truncate(&mut self, len: usize);
}

/// A trait for ChaCha20Poly1305 AEAD encryption.
pub trait ChaCha20Poly1305 {
    type Error: Error;

    /// Encrypt plaintext using the given key, counter, and associated data.
    fn aead_encrypt(
        key: &[u8; 32],
        counter: u64,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Decrypt ciphertext using the given key, counter, and associated data.
    fn aead_decrypt(
        key: &[u8; 32],
        counter: u64,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Encrypt buffer in place using the given key, counter, and associated data.
    fn aead_encrypt_in_place<'a>(
        buffer: &'a mut impl EncryptionBuffer<'a>,
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), Self::Error>;

    /// Decrypt buffer in place using the given key, counter, and associated data.
    fn aead_decrypt_in_place<'a>(
        buffer: &'a mut impl EncryptionBuffer<'a>,
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), Self::Error>;
}
