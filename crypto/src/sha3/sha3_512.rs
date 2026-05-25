use super::keccak::Keccak;

const SHA3_512_RATE: usize = 72;
const SHA3_512_DOMAIN_SEPARATOR: u8 = 0x06;

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
