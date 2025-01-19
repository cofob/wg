use std::error::Error;

/// A trait for blake2s HMAC.
pub trait Blake2sHmac {
    type Error: Error;

    /// Compute the HMAC of `data` using `key`.
    fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; 32], Self::Error>;
}

/// A trait for blake2s keyed MAC.
pub trait Blake2sMac {
    type Error: Error;

    /// Compute the MAC of `data` using `key`.
    fn mac(key: &[u8], data: &[u8]) -> Result<[u8; 16], Self::Error>;
}

/// A trait for blake2s hash.
pub trait Blake2sHash {
    type Error: Error;

    /// Compute the hash of `data`.
    fn hash(data: &[u8]) -> Result<[u8; 32], Self::Error>;
}
