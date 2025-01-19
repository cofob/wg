pub trait ToLEArray<T, const N: usize> {
    fn to_le_array(&self) -> [u8; N];
}

impl ToLEArray<u32, 4> for u32 {
    fn to_le_array(&self) -> [u8; 4] {
        u32::to_le_bytes(*self)
    }
}

impl ToLEArray<u64, 8> for u64 {
    fn to_le_array(&self) -> [u8; 8] {
        u64::to_le_bytes(*self)
    }
}

impl ToLEArray<&[u8; 4], 4> for [u8; 4] {
    fn to_le_array(&self) -> [u8; 4] {
        *self
    }
}

impl ToLEArray<&[u8; 4], 4> for &[u8] {
    fn to_le_array(&self) -> [u8; 4] {
        (*self).try_into().unwrap()
    }
}

impl ToLEArray<&[u8; 8], 8> for [u8; 8] {
    fn to_le_array(&self) -> [u8; 8] {
        *self
    }
}

impl ToLEArray<&[u8; 8], 8> for &[u8] {
    fn to_le_array(&self) -> [u8; 8] {
        (*self).try_into().unwrap()
    }
}

pub trait FromLEArray<const N: usize> {
    fn from_le_array(bytes: &[u8; N]) -> Self;
}

impl FromLEArray<4> for u32 {
    fn from_le_array(bytes: &[u8; 4]) -> Self {
        u32::from_le_bytes(*bytes)
    }
}

impl FromLEArray<8> for u64 {
    fn from_le_array(bytes: &[u8; 8]) -> Self {
        u64::from_le_bytes(*bytes)
    }
}

impl FromLEArray<4> for [u8; 4] {
    fn from_le_array(bytes: &[u8; 4]) -> Self {
        *bytes
    }
}

impl FromLEArray<8> for [u8; 8] {
    fn from_le_array(bytes: &[u8; 8]) -> Self {
        *bytes
    }
}
