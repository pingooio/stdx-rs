use sha2::Digest;

use crate::{Hash, Hasher, MAX_HASH_LENGTH};

#[derive(Clone)]
pub struct Sha256(sha2::Sha256);

impl Hasher for Sha256 {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;

    #[inline]
    fn new() -> Self {
        return Sha256(sha2::Sha256::new());
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    fn sum(self) -> Hash {
        let mut hash = [0u8; MAX_HASH_LENGTH];
        hash[..32].copy_from_slice(&self.0.finalize());
        return Hash {
            hash,
            length: 32,
        };
    }
}
