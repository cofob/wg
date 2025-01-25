/// Marker struct for read chunk size contained in the full chunk.
///
/// 32 bytes are reserved for the header and footer in the full chunk.
#[derive(Debug)]
pub struct Read;

impl ChunkSize for Full {}

/// Marker struct for full chunk size.
#[derive(Debug)]
pub struct Full;

impl ChunkSize for Read {}

pub trait ChunkSize {}

/// Chunk struct to hold the buffer data and length.
#[derive(Debug)]
pub struct Chunk<S: ChunkSize> {
    _phantom: std::marker::PhantomData<S>,
    ptr: usize,
    len: usize,
}

impl<S: ChunkSize> Chunk<S> {
    pub fn new(slice: &mut [u8]) -> Self {
        let ptr = slice.as_ptr() as usize;
        let len = slice.len();
        Self {
            _phantom: std::marker::PhantomData,
            ptr,
            len,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr as *mut u8
    }
}

impl<S: ChunkSize> AsMut<[u8]> for Chunk<S> {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

impl<S: ChunkSize> AsRef<[u8]> for Chunk<S> {
    fn as_ref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

impl From<Chunk<Read>> for Chunk<Full> {
    fn from(chunk: Chunk<Read>) -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            ptr: chunk.ptr - 16,
            len: chunk.len + 32,
        }
    }
}

impl From<Chunk<Full>> for Chunk<Read> {
    fn from(chunk: Chunk<Full>) -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            ptr: chunk.ptr + 16,
            len: chunk.len - 32,
        }
    }
}
