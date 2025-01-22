/// Generic function to concatenate byte slices
#[inline(always)]
pub fn concat_slices<'a, const N: usize>(slices: impl IntoIterator<Item = &'a [u8]>) -> [u8; N] {
    let mut buffer = [0u8; N];
    let mut offset = 0;

    for slice in slices.into_iter() {
        buffer[offset..offset + slice.len()].copy_from_slice(slice);
        offset += slice.len();
    }

    if offset != N {
        panic!("concat_slices: invalid slice length");
    }

    buffer
}
