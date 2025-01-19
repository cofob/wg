use thiserror::Error;
use wg_proto::crypto;
use x25519_dalek;

#[derive(Debug, Error)]
pub enum X25519Error {
    #[error("Invalid key length")]
    InvalidKeyLength,
}

pub struct X25519PublicKey(x25519_dalek::PublicKey);

impl X25519PublicKey {
    pub fn public_key(&self) -> &x25519_dalek::PublicKey {
        &self.0
    }
}

impl crypto::x25519::X25519PublicKey for X25519PublicKey {
    type Error = X25519Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(X25519Error::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(X25519PublicKey(x25519_dalek::PublicKey::from(arr)))
    }

    fn to_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

pub struct X25519EphemeralSecret(x25519_dalek::ReusableSecret);

impl crypto::x25519::X25519OperableSecretKey for X25519EphemeralSecret {
    type Error = X25519Error;

    fn generate() -> Self {
        X25519EphemeralSecret(x25519_dalek::ReusableSecret::random_from_rng(
            &mut rand::thread_rng(),
        ))
    }

    fn public_key(&self) -> Result<impl crypto::x25519::X25519PublicKey, Self::Error> {
        Ok(X25519PublicKey(x25519_dalek::PublicKey::from(&self.0)))
    }

    fn diffie_hellman(
        &self,
        public_key: &impl crypto::x25519::X25519PublicKey,
    ) -> Result<[u8; 32], Self::Error> {
        let public_key = public_key.to_bytes();
        let public_key = x25519_dalek::PublicKey::from(*public_key);
        let shared_secret = self.0.diffie_hellman(&public_key);
        let mut out = [0u8; 32];
        out.copy_from_slice(shared_secret.as_bytes());
        Ok(out)
    }
}

impl crypto::x25519::X25519EphemeralSecret for X25519EphemeralSecret {}

pub struct X25519StaticSecret(x25519_dalek::StaticSecret);

impl crypto::x25519::X25519OperableSecretKey for X25519StaticSecret {
    type Error = X25519Error;

    fn generate() -> Self {
        X25519StaticSecret(x25519_dalek::StaticSecret::random_from_rng(
            &mut rand::thread_rng(),
        ))
    }

    fn public_key(&self) -> Result<impl crypto::x25519::X25519PublicKey, Self::Error> {
        Ok(X25519PublicKey(x25519_dalek::PublicKey::from(&self.0)))
    }

    fn diffie_hellman(
        &self,
        public_key: &impl crypto::x25519::X25519PublicKey,
    ) -> Result<[u8; 32], X25519Error> {
        let public_key = public_key.to_bytes();
        let public_key = x25519_dalek::PublicKey::from(*public_key);
        let shared_secret = self.0.diffie_hellman(&public_key);
        let mut out = [0u8; 32];
        out.copy_from_slice(shared_secret.as_bytes());
        Ok(out)
    }
}

impl crypto::x25519::X25519StaticSecret for X25519StaticSecret {
    type Error = X25519Error;

    fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, <Self as crypto::x25519::X25519StaticSecret>::Error> {
        if bytes.len() != 32 {
            return Err(X25519Error::InvalidKeyLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(X25519StaticSecret(x25519_dalek::StaticSecret::from(arr)))
    }

    fn to_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
