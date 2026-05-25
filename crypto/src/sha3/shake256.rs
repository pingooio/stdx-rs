use super::keccak::Keccak;
use crate::{Hash, Hasher, MAX_HASH_LENGTH, Xof};

const SHAKE256_RATE: usize = 136;
const SHAKE256_DOMAIN_SEPARATOR: u8 = 0x1f;

#[derive(Clone)]
pub struct Shake256 {
    keccak: Keccak,
}

impl Shake256 {
    #[inline]
    pub fn hash(data: &[u8], output: &mut [u8]) {
        let mut hasher = Shake256::new();
        hasher.write(data);
        hasher.read(output);
    }

    #[inline]
    pub fn new() -> Self {
        return Shake256 {
            keccak: Keccak::new(SHAKE256_RATE, SHAKE256_DOMAIN_SEPARATOR),
        };
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    #[inline]
    pub fn read(&mut self, output: &mut [u8]) {
        self.keccak.squeeze(output);
    }
}

impl Xof for Shake256 {
    #[inline]
    fn new() -> Self {
        return Shake256::new();
    }

    #[inline]
    fn absobrd(&mut self, data: &[u8]) {
        self.write(data);
    }

    #[inline]
    fn squeeze(&mut self, out: &mut [u8]) {
        self.read(out);
    }
}

impl Hasher for Shake256 {
    const BLOCK_SIZE: usize = SHAKE256_RATE;
    const OUTPUT_SIZE: usize = 64;

    #[inline]
    fn new() -> Self {
        return Shake256::new();
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.write(data);
    }

    #[inline]
    fn sum(mut self) -> Hash {
        let mut hash = [0u8; MAX_HASH_LENGTH];
        self.keccak.squeeze(&mut hash[..Self::OUTPUT_SIZE]);
        return Hash {
            hash,
            length: Self::OUTPUT_SIZE,
        };
    }
}
