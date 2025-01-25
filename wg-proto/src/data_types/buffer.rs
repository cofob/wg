use super::chunk;
use super::traits::Buffer;
use core::pin::Pin;

/// Struct to hold the buffer data and get buffer chunks from it.
///
/// Suitable for no_std environments, where the buffer is a static array.
pub struct StaticBuffer<const N: usize, const M: usize> {
    _data: [u8; N],
    chunk_size: usize,
    available_ptrs: [Option<usize>; M],
}

impl<const N: usize, const M: usize> StaticBuffer<N, M> {
    /// Create a new StaticBuffer with the given chunk size.
    pub fn new(chunk_size: usize) -> Self {
        let available_ptrs = Self::get_available_ptrs(chunk_size);
        Self {
            _data: [0; N],
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
    fn get_chunk(&mut self) -> Option<chunk::Chunk<chunk::Full>> {
        if let Some(ptr) = self.available_ptrs.iter_mut().find(|ptr| ptr.is_some()) {
            Some(chunk::Chunk::new(unsafe {
                std::slice::from_raw_parts_mut(ptr.take().unwrap() as *mut u8, self.chunk_size)
            }))
        } else {
            None
        }
    }

    fn return_chunk(&mut self, chunk: &mut chunk::Chunk<chunk::Full>) {
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
    fn get_chunk(&mut self) -> Option<chunk::Chunk<chunk::Full>> {
        if let Some(ptr) = self.available_ptrs.pop() {
            Some(chunk::Chunk::new(unsafe {
                std::slice::from_raw_parts_mut(ptr as *mut u8, self.chunk_size)
            }))
        } else {
            None
        }
    }

    fn return_chunk(&mut self, chunk: &mut chunk::Chunk<chunk::Full>) {
        self.available_ptrs.push(chunk.as_ptr() as usize);
    }

    fn get_available_chunks(&self) -> usize {
        self.available_ptrs.len()
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
