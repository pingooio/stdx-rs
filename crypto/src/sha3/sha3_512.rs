use super::keccak::Keccak;
use crate::{Hash, Hasher, MAX_HASH_LENGTH};

const SHA3_512_RATE: usize = 72;
const SHA3_512_DOMAIN_SEPARATOR: u8 = 0x06;

#[derive(Clone)]
pub struct Sha3_512 {
    keccak: Keccak,
}

#[inline]
pub fn hash_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.write(data);
    return hasher.sum();
}

impl Sha3_512 {
    #[inline]
    pub fn new() -> Self {
        return Sha3_512 {
            keccak: Keccak::new(SHA3_512_RATE, SHA3_512_DOMAIN_SEPARATOR),
        };
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    #[inline]
    pub fn sum(mut self) -> [u8; 64] {
        let mut output = [0u8; 64];
        self.keccak.squeeze(&mut output);
        return output;
    }
}

impl Hasher for Sha3_512 {
    const BLOCK_SIZE: usize = SHA3_512_RATE;
    const OUTPUT_SIZE: usize = 64;

    #[inline]
    fn new() -> Self {
        return Sha3_512::new();
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
