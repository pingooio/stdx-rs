pub mod md5;
mod sha256;
pub mod sha3;
mod sha512;
pub use sha256::Sha256;
pub use sha512::Sha512;

#[cfg(target_arch = "x86_64")]
mod sha256_amd64;
#[cfg(target_arch = "aarch64")]
mod sha256_arm64;
#[cfg(target_arch = "x86_64")]
mod sha512_amd64;
#[cfg(target_arch = "aarch64")]
mod sha512_arm64;

const MAX_HASH_LENGTH: usize = 64;
const MAX_HASH_BLOCK_SIZE: usize = 128;

pub struct Hash {
    hash: [u8; MAX_HASH_LENGTH],
    length: usize,
}

impl AsRef<[u8]> for Hash {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.hash[..self.length]
    }
}

pub trait Hasher: Sized + Clone {
    /// The internal block size of the hash function
    const BLOCK_SIZE: usize;
    /// The output size of the hash function
    const OUTPUT_SIZE: usize;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn sum(self) -> Hash;

    #[inline]
    fn hash(data: &[u8]) -> Hash {
        let mut hasher = Self::new();
        hasher.update(data);
        return hasher.sum();
    }
}

#[derive(Clone)]
pub struct Hmac<H: Hasher> {
    hash: H,
    opad: [u8; MAX_HASH_BLOCK_SIZE],
}

impl<H: Hasher> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; MAX_HASH_BLOCK_SIZE];

        // normalize key to block size
        if key.len() > H::BLOCK_SIZE {
            let mut h = H::new();
            h.update(key);
            let hashed = h.sum();
            let hashed_bytes = hashed.as_ref();
            key_block[..hashed_bytes.len()].copy_from_slice(hashed_bytes);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // inner pad = key ^ 0x36
        let mut inner_key = [0u8; MAX_HASH_BLOCK_SIZE];
        for i in 0..H::BLOCK_SIZE {
            inner_key[i] = key_block[i] ^ 0x36;
        }

        // outer pad = key ^ 0x5c
        let mut opad = [0u8; MAX_HASH_BLOCK_SIZE];
        for i in 0..H::BLOCK_SIZE {
            opad[i] = key_block[i] ^ 0x5c;
        }

        // initialize inner hash: create a fresh instance and feed inner pad
        let mut hash = H::new();
        hash.update(&inner_key[..H::BLOCK_SIZE]);

        Hmac {
            hash,
            opad,
        }
    }

    /// Feed message data to HMAC (can be called multiple times)
    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    /// Finalize and return HMAC tag. This consumes the Hmac state.
    pub fn finalize(self) -> Hash {
        let inner_sum = self.hash.sum();

        // compute outer hash using a fresh instance
        let mut outer = H::new();
        outer.update(&self.opad[..H::BLOCK_SIZE]);
        outer.update(inner_sum.as_ref());
        outer.sum()
    }
}

#[cfg(test)]
mod hmac_tests {
    use super::{Hmac, Sha256, Sha512};

    fn hmac256(key: &[u8], data: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new(key);
        mac.update(data);
        hex::encode(mac.finalize().as_ref())
    }

    fn hmac512(key: &[u8], data: &[u8]) -> String {
        let mut mac = Hmac::<Sha512>::new(key);
        mac.update(data);
        hex::encode(mac.finalize().as_ref())
    }

    // RFC 4231 test vectors

    #[test]
    fn rfc4231_tc1_sha256() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac256(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rfc4231_tc1_sha512() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac512(&key, b"Hi There"),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn rfc4231_tc2_sha256() {
        assert_eq!(
            hmac256(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn rfc4231_tc2_sha512() {
        assert_eq!(
            hmac512(b"Jefe", b"what do ya want for nothing?"),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    #[test]
    fn rfc4231_tc3_sha256() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        assert_eq!(
            hmac256(&key, &data),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    #[test]
    fn rfc4231_tc3_sha512() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        assert_eq!(
            hmac512(&key, &data),
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb"
        );
    }

    #[test]
    fn rfc4231_tc4_sha256() {
        let key: Vec<u8> = (0x01u8..=0x19).collect();
        let data: Vec<u8> = (0..50).map(|_| 0xcdu8).collect();
        assert_eq!(
            hmac256(&key, &data),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    #[test]
    fn rfc4231_tc4_sha512() {
        let key: Vec<u8> = (0x01u8..=0x19).collect();
        let data: Vec<u8> = (0..50).map(|_| 0xcdu8).collect();
        assert_eq!(
            hmac512(&key, &data),
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd"
        );
    }

    // TC5 uses truncated output, skip

    #[test]
    fn rfc4231_tc6_sha256_long_key() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hmac256(&key, data),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn rfc4231_tc6_sha512_long_key() {
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hmac512(&key, data),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
        );
    }

    #[test]
    fn rfc4231_tc7_sha256_long_key_and_data() {
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        assert_eq!(
            hmac256(&key, data),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn rfc4231_tc7_sha512_long_key_and_data() {
        let key = [0xaau8; 131];
        let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        assert_eq!(
            hmac512(&key, data),
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"
        );
    }

    #[test]
    fn hmac_sha256_incremental_matches_single() {
        let key = b"secret key";
        let data = b"hello world this is a test message that spans multiple updates";

        let mut mac1 = Hmac::<Sha256>::new(key);
        mac1.update(data);
        let out1 = hex::encode(mac1.finalize().as_ref());

        let mut mac2 = Hmac::<Sha256>::new(key);
        for chunk in data.chunks(7) {
            mac2.update(chunk);
        }
        let out2 = hex::encode(mac2.finalize().as_ref());

        assert_eq!(out1, out2);
    }

    #[test]
    fn hmac_sha512_incremental_matches_single() {
        let key = b"another secret key";
        let data = b"hello world this is a test message that spans multiple updates";

        let mut mac1 = Hmac::<Sha512>::new(key);
        mac1.update(data);
        let out1 = hex::encode(mac1.finalize().as_ref());

        let mut mac2 = Hmac::<Sha512>::new(key);
        for chunk in data.chunks(13) {
            mac2.update(chunk);
        }
        let out2 = hex::encode(mac2.finalize().as_ref());

        assert_eq!(out1, out2);
    }
}
