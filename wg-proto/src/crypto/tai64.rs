use thiserror::Error;

#[derive(Debug, Error)]
pub enum Tai64NError {
    #[error("Invalid timestamp length")]
    InvalidLength,
    #[error("Nanosecond part must be <= 999999999")]
    NanosInvalid,
}

/// A trait for TAI64N timestamps.
pub trait Tai64N: Sized + PartialOrd {
    /// Create a new TAI64N timestamp representing the current time.
    fn now() -> Self;

    /// Create a new TAI64N timestamp from a byte slice.
    fn from_bytes(bytes: &[u8]) -> Result<Self, Tai64NError>;

    /// Convert the TAI64N timestamp to a byte array.
    fn to_bytes(&self) -> [u8; 12];
}
