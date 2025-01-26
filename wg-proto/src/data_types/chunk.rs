use super::traits::Chunk;

/// Defines buffer chunk dimensions using prefix (S) and suffix (E) sizes
///
/// Implementations should specify:
/// - `S`: Bytes reserved before payload (prefix)
/// - `E`: Bytes reserved after payload (suffix)
pub trait ChunkSize {
    const S: usize;
    const E: usize;
}

/// Read chunk configuration with header/footer space
///
/// Contains 44 bytes prefix (S) and 16 bytes suffix (E), typically used for:
/// - 32-byte WG header structures
/// - 44-byte msghdr structure in header for UDP
/// - 16-byte poly1305 tag
#[derive(Debug)]
pub struct Read;

impl ChunkSize for Read {
    const S: usize = 44;
    const E: usize = 16;
}

/// Full buffer chunk without additional reservations
///
/// Direct access to complete buffer space (S=0, E=0)
#[derive(Debug)]
pub struct Full;

impl ChunkSize for Full {
    const S: usize = 0;
    const E: usize = 0;
}

/// Buffer chunk reference with type-tagged dimensions
///
/// # Generic Parameters
/// - `C`: ChunkSize implementation defining prefix/suffix sizes
///
/// # Safety
/// - All operations assume valid ptr/len combination
/// - Lifetime management must be handled externally
#[derive(Debug)]
pub struct RefChunk<C: ChunkSize> {
    /// Type marker for compile-time size configuration
    _phantom: core::marker::PhantomData<C>,
    /// Start of payload section (after prefix)
    ptr: usize,
    /// Length of payload section (excluding prefix/suffix)
    len: usize,
}

impl<C: ChunkSize> RefChunk<C> {
    /// Creates a chunk from mutable slice
    ///
    /// # Parameters
    /// - `slice`: Mutable reference to chunk payload section
    ///
    /// # Notes
    /// - Capture current pointer address and slice length
    pub fn new(slice: &mut [u8]) -> Self {
        let ptr = slice.as_ptr() as usize;
        let len = slice.len();
        Self {
            _phantom: core::marker::PhantomData,
            ptr,
            len,
        }
    }

    /// Converts between chunk types with different size configurations
    ///
    /// # Generic Parameters
    /// - `C2`: Target chunk size configuration
    ///
    /// # Algorithm
    /// 1. Calculate original buffer start (current ptr - source prefix)
    /// 2. Calculate total buffer length (payload + source prefix + source suffix)
    /// 3. Calculate new payload start (buffer start + target prefix)
    /// 4. Calculate new payload length (total length - target prefix/suffix)
    pub fn into_chunk<C2: ChunkSize>(self) -> RefChunk<C2> {
        let base = self.ptr - C::S;
        let full_len = self.len + C::S + C::E;
        let new_ptr = base + C2::S;
        let new_len = full_len - (C2::S + C2::E);

        RefChunk {
            _phantom: core::marker::PhantomData,
            ptr: new_ptr,
            len: new_len,
        }
    }
}

impl<C: ChunkSize> Chunk for RefChunk<C> {
    fn len(&self) -> usize {
        self.len
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr as *mut u8
    }
}

impl<C: ChunkSize> AsMut<[u8]> for RefChunk<C> {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

impl<C: ChunkSize> AsRef<[u8]> for RefChunk<C> {
    fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.len) }
    }
}

/// Chunk that owns the buffer data.
pub struct OwnedChunk {
    data: Vec<u8>,
}

impl OwnedChunk {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
        }
    }
}

impl Chunk for OwnedChunk {
    fn len(&self) -> usize {
        self.data.len()
    }

    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

impl AsMut<[u8]> for OwnedChunk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl AsRef<[u8]> for OwnedChunk {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<&mut OwnedChunk> for RefChunk<Full> {
    fn from(chunk: &mut OwnedChunk) -> RefChunk<Full> {
        RefChunk::new(&mut chunk.data)
    }
}
