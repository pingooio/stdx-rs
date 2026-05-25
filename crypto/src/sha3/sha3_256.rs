use super::keccak::Keccak;

const SHA3_256_RATE: usize = 136;
const SHA3_256_DOMAIN_SEPARATOR: u8 = 0x06;

pub struct Sha3_256 {
    keccak: Keccak,
}

#[inline]
pub fn hash_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.write(data);
    return hasher.sum();
}

impl Sha3_256 {
    #[inline]
    pub fn new() -> Self {
        return Sha3_256 {
            keccak: Keccak::new(SHA3_256_RATE, SHA3_256_DOMAIN_SEPARATOR),
        };
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.keccak.update(data);
    }

    #[inline]
    pub fn sum(mut self) -> [u8; 32] {
        let mut output = [0u8; 32];
        self.keccak.squeeze(&mut output);
        return output;
    }
}
