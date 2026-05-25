pub mod sha2;
pub mod sha3;

const MAX_HASH_LENGTH: usize = 64;
const MAX_HASH_BLOCK_SIZE: usize = 64;

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
}

#[derive(Clone)]
pub struct Hmac<H: Hasher> {
    hash: H,
    opad: [u8; MAX_HASH_BLOCK_SIZE],
}

impl<H: Hasher> Hmac<H> {
    pub fn new(key: &[u8]) -> Self {
        let block_size = H::BLOCK_SIZE;
        let mut key_block = [0u8; MAX_HASH_BLOCK_SIZE];

        // normalize key to block size
        if key.len() > H::BLOCK_SIZE {
            let mut h = H::new();
            h.update(key);
            let hashed = h.sum();
            key_block[..block_size].copy_from_slice(hashed.as_ref());
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
        hash.update(&inner_key);

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
        outer.update(&self.opad);
        outer.update(inner_sum.as_ref());
        outer.sum()
    }
}
