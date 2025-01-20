/// A trait for blake2s hash.
pub trait Blake2s {
    /// Compute the HMAC of `data` using `key`.
    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32];

    /// Compute the MAC of `data` using `key`.
    fn mac(key: &[u8], data: &[u8]) -> [u8; 16];

    /// Compute the hash of `data`.
    fn hash(data: &[u8]) -> [u8; 32];
}
