use blake2::{digest::Mac, Blake2s256, Blake2sMac, Digest};
use thiserror::Error;
use wg_proto::crypto;

pub struct Blake2s();

impl crypto::blake2::Blake2s for Blake2s {
    fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
        // BLAKE2s has a 64-byte internal block size:
        const BLOCK_SIZE: usize = 64;

        // 1) If `key` is longer than BLOCK_SIZE, reduce it by hashing once with BLAKE2s.
        let mut shortened_key = if key.len() > BLOCK_SIZE {
            let mut hasher = Blake2s256::new();
            hasher.update(key);
            hasher.finalize().to_vec() // 32-byte digest
        } else {
            key.to_vec()
        };

        // 2) Pad `shortened_key` to exactly BLOCK_SIZE bytes with zeros.
        shortened_key.resize(BLOCK_SIZE, 0);

        // 3) Create the inner (ipad) and outer (opad) padded keys.
        let mut i_key_pad = [0u8; BLOCK_SIZE];
        let mut o_key_pad = [0u8; BLOCK_SIZE];

        for i in 0..BLOCK_SIZE {
            i_key_pad[i] = shortened_key[i] ^ 0x36; // 0x36 = ipad
            o_key_pad[i] = shortened_key[i] ^ 0x5C; // 0x5C = opad
        }

        // 4) Inner hash: H(i_key_pad || message)
        let inner_hash = Blake2s256::new()
            .chain_update(&i_key_pad)
            .chain_update(data)
            .finalize();

        // 5) Outer hash: H(o_key_pad || inner_hash)
        let result = Blake2s256::new()
            .chain_update(&o_key_pad)
            .chain_update(&inner_hash)
            .finalize();

        // 6) Produce final 32-byte HMAC value
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    fn mac(key: &[u8], data: &[u8]) -> [u8; 16] {
        let result = Blake2sMac::<blake2::digest::consts::U16>::new_from_slice(key)
            .expect("Invalid key length")
            .chain_update(data)
            .finalize()
            .into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&result);
        out
    }

    fn hash(data: &[u8]) -> [u8; 32] {
        let result = Blake2s256::new().chain_update(data).finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}
