use std::error::Error;

/// A trait for TAI64N timestamps.
pub trait Tai64N: Sized + PartialOrd {
    type Error: Error;

    /// Create a new TAI64N timestamp representing the current time.
    fn now() -> Self;

    /// Create a new TAI64N timestamp from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;

    /// Convert the TAI64N timestamp to a byte array.
    fn to_bytes(&self) -> [u8; 12];
}
