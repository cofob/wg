use thiserror::Error;

#[derive(Debug, Error)]
pub enum X25519Error {
    #[error("Invalid key length")]
    InvalidKeyLength,
}

/// A trait for X25519 public keys.
///
/// Public keys are used for key exchange and are meant to be shared.
pub trait X25519PublicKey: Sized {
    /// Create a new X25519 public key from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self, X25519Error>;

    /// Convert the X25519 public key to a byte array.
    fn to_bytes(&self) -> &[u8; 32];
}

/// A trait for X25519 secret keys.
pub trait X25519OperableSecretKey: Sized {
    /// Generate a new X25519 secret key.
    fn generate() -> Self;

    /// Get the public key corresponding to this secret key.
    fn public_key(&self) -> Result<impl X25519PublicKey, X25519Error>;

    /// Perform a Diffie-Hellman key exchange with the given public key.
    fn diffie_hellman(&self, public_key: &impl X25519PublicKey) -> Result<[u8; 32], X25519Error>;
}

/// A trait for ephemeral X25519 secret keys.
///
/// Ephemeral keys are used for key exchange and are not meant to be stored or reused.
pub trait X25519EphemeralSecret: X25519OperableSecretKey + Sized {}

/// A trait for static X25519 secret keys.
///
/// Static keys are used for long-term key storage and are meant to be reused.
pub trait X25519StaticSecret: X25519OperableSecretKey + Sized {
    /// Load a new X25519 static secret key from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self, X25519Error>;

    /// Load the X25519 static secret key to a byte array.
    fn to_bytes(&self) -> &[u8; 32];
}
