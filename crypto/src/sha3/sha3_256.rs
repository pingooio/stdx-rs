use super::keccak::Keccak;
use crate::{Hash, Hasher};

const SHA3_256_RATE: usize = 136;
const SHA3_256_DOMAIN_SEPARATOR: u8 = 0x06;

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub struct Sha3_256 {
    keccak: Keccak<24>,
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
        self.keccak.absorb(data);
    }

    #[inline]
    pub fn sum(mut self) -> [u8; 32] {
        let mut output = [0u8; 32];
        self.keccak.squeeze(&mut output);
        return output;
    }
}

impl Hasher for Sha3_256 {
    const BLOCK_SIZE: usize = SHA3_256_RATE;
    const OUTPUT_SIZE: usize = 32;

    #[inline]
    fn new() -> Self {
        return Sha3_256::new();
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.write(data);
    }

    #[inline]
    fn sum(mut self) -> Hash {
        let mut hash = Hash::with_length(Self::OUTPUT_SIZE);
        self.keccak.squeeze(hash.as_mut());
        return hash;
    }
}

#[cfg(test)]
mod tests {
    use super::Sha3_256;
    use crate::Hasher;

    fn vectors_sha3_256() -> Vec<(Vec<u8>, &'static str)> {
        vec![
            (b"".to_vec(), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            (
                b"abc".to_vec(),
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            ),
            (
                b"hello world".to_vec(),
                "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
            ),
            (
                b"The quick brown fox jumps over the lazy dog".to_vec(),
                "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04",
            ),
            (
                b"The quick brown fox jumps over the lazy dog.".to_vec(),
                "a80f839cd4f83f6c3dafc87feae470045e4eb0d366397d5c6ce34ba1739f734d",
            ),
            (
                vec![b'a'; 1_000_000],
                "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
            ),
        ]
    }

    #[test]
    fn known_vectors_single_update() {
        for (input, expected) in vectors_sha3_256() {
            assert_eq!(hex::encode(Sha3_256::hash(&input)), expected);
        }
    }

    #[test]
    fn known_vectors_incremental() {
        for (input, expected) in vectors_sha3_256() {
            let mut sha3_256 = Sha3_256::new();
            for chunk in input.chunks(7) {
                sha3_256.write(chunk);
            }
            assert_eq!(hex::encode(sha3_256.sum()), expected);
        }
    }

    #[test]
    fn hasher_trait_impl() {
        for (input, expected) in vectors_sha3_256() {
            let digest = <Sha3_256 as Hasher>::hash(&input);
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }
}
