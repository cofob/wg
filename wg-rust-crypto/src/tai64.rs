use std::fmt::Debug;

use tai64;
use wg_proto::crypto;

pub type Tai64Error = tai64::Error;

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub struct Tai64N(tai64::Tai64N);

impl crypto::tai64::Tai64N for Tai64N {
    fn now() -> Self {
        Tai64N(tai64::Tai64N::now())
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, crypto::tai64::Tai64NError> {
        Ok(Tai64N(tai64::Tai64N::from_slice(bytes).map_err(
            |e| match e {
                tai64::Error::LengthInvalid => crypto::tai64::Tai64NError::InvalidLength,
                tai64::Error::NanosInvalid => crypto::tai64::Tai64NError::NanosInvalid,
            },
        )?))
    }

    fn to_bytes(&self) -> [u8; 12] {
        self.0.to_bytes()
    }
}

impl Debug for Tai64N {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
