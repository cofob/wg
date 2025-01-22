use chacha20poly1305::aead::{AeadMutInPlace, KeyInit};
use chacha20poly1305::{self, Key, Nonce};
use thiserror::Error;
use wg_proto::crypto;

#[derive(Debug, Error)]
pub enum ChaCha20Poly1305Error {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

pub struct ChaCha20Poly1305;

impl crypto::chacha20poly1305::ChaCha20Poly1305 for ChaCha20Poly1305 {
    fn aead_encrypt_in_place<'a>(
        buf: &'a mut [u8],
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), crypto::chacha20poly1305::ChaCha20Poly1305Error> {
        let mut cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::from_slice(key));

        // Create nonce with 32 bits of zeros + 64-bit little-endian counter
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce);

        let len = buf.len();

        let tag = cipher
            .encrypt_in_place_detached(nonce, associated_data, &mut buf[..len - 16])
            .map_err(move |_| crypto::chacha20poly1305::ChaCha20Poly1305Error::EncryptionFailed)?;

        buf[len - 16..].copy_from_slice(&tag);

        Ok(())
    }

    fn aead_decrypt_in_place<'a>(
        buf: &'a mut [u8],
        key: &[u8; 32],
        counter: u64,
        associated_data: &[u8],
    ) -> Result<(), crypto::chacha20poly1305::ChaCha20Poly1305Error> {
        let mut cipher = chacha20poly1305::ChaCha20Poly1305::new(Key::from_slice(key));

        // Create nonce (32 bits zeros + 64-bit little-endian counter)
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce);

        let len = buf.len();

        let (msg, tag) = buf.split_at_mut(len - 16);
        cipher
            .decrypt_in_place_detached(nonce, associated_data, msg, tag.as_ref().into())
            .map_err(move |_| crypto::chacha20poly1305::ChaCha20Poly1305Error::DecryptionFailed)
    }
}
