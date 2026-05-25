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

#[cfg(test)]
mod tests {
    use super::Shake256;
    use crate::{Hasher, Xof};

    fn vectors_shake256() -> Vec<(Vec<u8>, usize, &'static str)> {
        vec![
            (
                b"".to_vec(),
                64,
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
            ),
            (
                b"".to_vec(),
                128,
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86",
            ),
            (
                b"abc".to_vec(),
                64,
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
            ),
            (
                b"hello world".to_vec(),
                64,
                "369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527f4f3c2d55c2d46a29f2e945d469c3df27853a8735271f5cc2d9e889544357116",
            ),
            (
                b"The quick brown fox jumps over the lazy dog".to_vec(),
                64,
                "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442",
            ),
            (
                b"The quick brown fox jumps over the lazy dog.".to_vec(),
                64,
                "bd225bfc8b255f3036f0c8866010ed0053b5163a3cae111e723c0c8e704eca4e5d0f1e2a2fa18c8a219de6b88d5917ff5dd75b5fb345e7409a3b333b508a65fb",
            ),
            (
                vec![b'a'; 1_000_000],
                64,
                "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a3fd124d4df76c0a539ee7dd2f6e1ec346124c815d9410e145eb561bcd97b18ab",
            ),
        ]
    }

    #[test]
    fn known_vectors() {
        for (input, output_len, expected) in vectors_shake256() {
            let mut output = vec![0u8; output_len];
            Shake256::hash(&input, &mut output);
            assert_eq!(hex::encode(output), expected);
        }
    }

    #[test]
    fn incremental_and_streaming_read() {
        let mut one_shot = vec![0u8; 128];
        Shake256::hash(b"", &mut one_shot);

        let mut shake = Shake256::new();
        shake.write(b"");
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        shake.read(&mut first);
        shake.read(&mut second);

        let mut combined = vec![0u8; 128];
        combined[..64].copy_from_slice(&first);
        combined[64..].copy_from_slice(&second);

        assert_eq!(combined, one_shot);
    }

    #[test]
    fn hasher_trait_impl() {
        let expected = "369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527f4f3c2d55c2d46a29f2e945d469c3df27853a8735271f5cc2d9e889544357116";
        let digest = <Shake256 as Hasher>::hash(b"hello world");
        assert_eq!(hex::encode(digest.as_ref()), expected);
    }

    #[test]
    fn xof_trait_impl() {
        let mut xof = <Shake256 as Xof>::new();
        xof.absobrd(b"abc");
        let mut out = [0u8; 64];
        xof.squeeze(&mut out);
        assert_eq!(
            hex::encode(out),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }
}
