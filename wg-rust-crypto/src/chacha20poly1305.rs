use chacha20poly1305::aead::{self, Aead};
use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{self, Key, Nonce};
use thiserror::Error;
use wg_proto::crypto;

#[derive(Debug, Error)]
pub enum EncryptionBufferError {
    #[error("Encryption buffer is full")]
    Full,
}

pub struct EncryptionBuffer<'a> {
    data: &'a mut [u8],
    len: usize,
}

impl<'a> crypto::chacha20poly1305::EncryptionBuffer<'a> for EncryptionBuffer<'a> {
    type Error = EncryptionBufferError;

    fn new(data: &'a mut [u8], len: usize) -> Self {
        EncryptionBuffer { data, len }
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), Self::Error> {
        let len = self.len();
        self.data[len - 16..].copy_from_slice(&other);
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

impl AsMut<[u8]> for EncryptionBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl AsRef<[u8]> for EncryptionBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl<'a> aead::Buffer for EncryptionBuffer<'a> {
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        <Self as crypto::chacha20poly1305::EncryptionBuffer>::extend_from_slice(self, other)
            .map_err(|_| chacha20poly1305::aead::Error)
    }

    fn is_empty(&self) -> bool {
        <Self as crypto::chacha20poly1305::EncryptionBuffer>::is_empty(self)
    }

    fn len(&self) -> usize {
        <Self as crypto::chacha20poly1305::EncryptionBuffer>::len(self)
    }

    fn truncate(&mut self, len: usize) {
        <Self as crypto::chacha20poly1305::EncryptionBuffer>::truncate(self, len)
    }
}

struct EncryptionBufferProxy<'a, T: crypto::chacha20poly1305::EncryptionBuffer<'a>> {
    _phantom: std::marker::PhantomData<&'a T>,
    buffer: &'a mut T,
}

impl<'a, T: crypto::chacha20poly1305::EncryptionBuffer<'a>> EncryptionBufferProxy<'a, T> {
    fn new(buffer: &'a mut T) -> Self {
        EncryptionBufferProxy {
            _phantom: std::marker::PhantomData,
            buffer,
        }
    }
}

impl<'a, T: crypto::chacha20poly1305::EncryptionBuffer<'a>> aead::Buffer
    for EncryptionBufferProxy<'a, T>
{
    fn extend_from_slice(&mut self, other: &[u8]) -> chacha20poly1305::aead::Result<()> {
        self.buffer
            .extend_from_slice(other)
            .map_err(|_| chacha20poly1305::aead::Error)
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn len(&self) -> usize {
        self.buffer.len()
    }

    fn truncate(&mut self, len: usize) {
        self.buffer.truncate(len)
    }
}

impl<'a, T: crypto::chacha20poly1305::EncryptionBuffer<'a>> AsMut<[u8]>
    for EncryptionBufferProxy<'a, T>
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<'a, T: crypto::chacha20poly1305::EncryptionBuffer<'a>> AsRef<[u8]>
    for EncryptionBufferProxy<'a, T>
{
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum ChaCha20Poly1305Error {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

pub struct ChaCha20Poly1305;

impl crypto::chacha20poly1305::ChaCha20Poly1305 for ChaCha20Poly1305 {
    type Error = ChaCha20Poly1305Error;

    fn aead_encrypt(
        key: &[u8; 32],
        counter: u64,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::from_slice(key));

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
            .map_err(|_| Self::Error::EncryptionFailed)
    }

    fn aead_encrypt_in_place<'a>(
        buffer: &'a mut impl crypto::chacha20poly1305::EncryptionBuffer<'a>,
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), Self::Error> {
        // Wrap the user's buffer in a small local adapter
        let mut proxy = EncryptionBufferProxy::new(buffer);
        let mut cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::from_slice(key));

        // Create nonce with 32 bits of zeros + 64-bit little-endian counter
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce);

        cipher
            .encrypt_in_place(nonce, associated_data, &mut proxy)
            .map_err(move |_| Self::Error::EncryptionFailed)
    }

    fn aead_decrypt(
        key: &[u8; 32],
        counter: u64,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::from_slice(key));

        // Create nonce with 32 bits of zeros followed by 64-bit little-endian counter
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce);

        // Decrypt the ciphertext
        cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(move |_| Self::Error::DecryptionFailed)
    }

    fn aead_decrypt_in_place<'a>(
        buffer: &'a mut impl crypto::chacha20poly1305::EncryptionBuffer<'a>,
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), Self::Error> {
        let mut proxy = EncryptionBufferProxy::new(buffer);
        let mut cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::from_slice(key));

        // Create nonce (32 bits zeros + 64-bit little-endian counter)
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce);

        cipher
            .decrypt_in_place(nonce, associated_data, &mut proxy)
            .map_err(move |_| Self::Error::DecryptionFailed)
    }
}
