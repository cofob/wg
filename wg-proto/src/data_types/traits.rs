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

/// A trait for a counter that can be incremented.
pub trait Counter {
    /// Increment the counter and return the new value.
    fn next_counter(&mut self) -> u64;
}

/// Trait to get buffer chunks.
pub trait Buffer: AsRef<[u8]> + AsMut<[u8]> {
    type FullChunk: Chunk;

    fn get_chunk(&mut self) -> Option<Self::FullChunk>;
    fn return_chunk(&mut self, chunk: &mut Self::FullChunk);
    fn get_available_chunks(&self) -> usize;
    fn get_chunk_size(&self) -> usize;
    fn as_mut_ptr(&mut self) -> *mut u8;
}

pub trait Chunk: AsRef<[u8]> + AsMut<[u8]> {
    fn len(&self) -> usize;
    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;
}
