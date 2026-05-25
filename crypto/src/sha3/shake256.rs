use super::keccak::Keccak;

const SHAKE256_RATE: usize = 136;
const SHAKE256_DOMAIN_SEPARATOR: u8 = 0x1f;

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
