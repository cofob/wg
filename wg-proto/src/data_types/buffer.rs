use super::chunk;
use super::traits::{Buffer, Chunk};
use core::pin::Pin;

/// Struct to hold the buffer data and get buffer chunks from it.
///
/// Suitable for no_std environments, where the buffer is a static array.
pub struct StaticBuffer<const N: usize, const M: usize> {
    data: [u8; N],
    chunk_size: usize,
    available_ptrs: [Option<usize>; M],
}

impl<const N: usize, const M: usize> StaticBuffer<N, M> {
    /// Create a new StaticBuffer with the given chunk size.
    pub fn new(chunk_size: usize) -> Self {
        let available_ptrs = Self::get_available_ptrs(chunk_size);
        Self {
            data: [0; N],
            chunk_size,
            available_ptrs,
        }
    }

    fn get_available_ptrs(chunk_size: usize) -> [Option<usize>; M] {
        let start_ptr = &0 as *const _ as usize;
        let mut ptrs = [None; M];
        for (i, _) in ptrs.into_iter().enumerate() {
            ptrs[i] = Some(start_ptr + i * chunk_size);
        }
        ptrs
    }
}

impl<const N: usize, const M: usize> Buffer for StaticBuffer<N, M> {
    type FullChunk = chunk::RefChunk<chunk::Full>;

    fn get_chunk(&mut self) -> Option<chunk::RefChunk<chunk::Full>> {
        if let Some(ptr) = self.available_ptrs.iter_mut().find(|ptr| ptr.is_some()) {
            Some(chunk::RefChunk::new(unsafe {
                core::slice::from_raw_parts_mut(ptr.take().unwrap() as *mut u8, self.chunk_size)
            }))
        } else {
            None
        }
    }

    fn return_chunk(&mut self, chunk: &mut chunk::RefChunk<chunk::Full>) {
        self.available_ptrs
            .iter_mut()
            .find(|ptr| ptr.is_none())
            .unwrap()
            .replace(chunk.as_ptr() as usize);
    }

    fn get_available_chunks(&self) -> usize {
        self.available_ptrs
            .iter()
            .filter(|ptr| ptr.is_some())
            .count()
    }

    fn get_chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

impl<const N: usize, const M: usize> AsRef<[u8]> for StaticBuffer<N, M> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl<const N: usize, const M: usize> AsMut<[u8]> for StaticBuffer<N, M> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl<const N: usize, const M: usize> core::fmt::Debug for StaticBuffer<N, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeInitiationMessage")
            .field("chunk_size", &self.chunk_size)
            .field("available_chunks", &self.get_available_chunks())
            .finish()
    }
}

/// Struct to hold the buffer data and get buffer chunks from it.
#[cfg(feature = "std")]
pub struct AllocBuffer {
    _data: Pin<Vec<u8>>,
    chunk_size: usize,
    available_ptrs: Vec<usize>,
}

#[cfg(feature = "std")]
impl AllocBuffer {
    pub fn new(data: Vec<u8>, chunk_size: usize) -> Self {
        let available_ptrs = Self::get_available_ptrs(&data, chunk_size);
        Self {
            _data: Pin::new(data),
            chunk_size,
            available_ptrs,
        }
    }

    pub fn new_with_size(chunk_size: usize, chunks_count: usize) -> Self {
        let data = vec![0; chunk_size * chunks_count];
        Self::new(data, chunk_size)
    }

    fn get_available_ptrs(data: &[u8], chunk_size: usize) -> Vec<usize> {
        let start_ptr = data.as_ptr() as usize;
        (0..data.len())
            .step_by(chunk_size)
            .map(|i| start_ptr + i)
            .collect()
    }
}

#[cfg(feature = "std")]
impl Buffer for AllocBuffer {
    type FullChunk = chunk::RefChunk<chunk::Full>;

    fn get_chunk(&mut self) -> Option<chunk::RefChunk<chunk::Full>> {
        if let Some(ptr) = self.available_ptrs.pop() {
            Some(chunk::RefChunk::new(unsafe {
                std::slice::from_raw_parts_mut(ptr as *mut u8, self.chunk_size)
            }))
        } else {
            None
        }
    }

    fn return_chunk(&mut self, chunk: &mut chunk::RefChunk<chunk::Full>) {
        self.available_ptrs.push(chunk.as_ptr() as usize);
    }

    fn get_available_chunks(&self) -> usize {
        self.available_ptrs.len()
    }

    fn get_chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self._data.as_mut_ptr()
    }
}

#[cfg(feature = "std")]
impl AsRef<[u8]> for AllocBuffer {
    fn as_ref(&self) -> &[u8] {
        &self._data
    }
}

#[cfg(feature = "std")]
impl AsMut<[u8]> for AllocBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self._data
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for AllocBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeInitiationMessage")
            .field("chunk_size", &self.chunk_size)
            .field("available_chunks", &self.available_ptrs.len())
            .finish()
    }
}
