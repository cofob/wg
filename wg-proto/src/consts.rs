//! Constants used in the WireGuard protocol.

pub const CONSTRUCTION: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &str = "WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &str = "mac1----";
pub const LABEL_COOKIE: &str = "cookie--";
pub const AEAD_OVERHEAD: usize = 16;
