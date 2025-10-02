use sha2::{Digest, digest::ExtendableOutput};

pub struct Sha3_256(sha3::Sha3_256);

#[inline]
pub fn hash_256(data: &[u8]) -> [u8; 32] {
    return sha3::Sha3_256::digest(data).into();
}

impl Sha3_256 {
    #[inline]
    pub fn new() -> Self {
        return Sha3_256(sha3::Sha3_256::new());
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    pub fn sum(self) -> [u8; 32] {
        return self.0.finalize().into();
    }
}

pub struct Sha3_512(sha3::Sha3_512);

#[inline]
pub fn hash_512(data: &[u8]) -> [u8; 64] {
    return sha3::Sha3_512::digest(data).into();
}

impl Sha3_512 {
    #[inline]
    pub fn new() -> Self {
        return Sha3_512(sha3::Sha3_512::new());
    }

    #[inline]
    pub fn write(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    #[inline]
    pub fn sum(self) -> [u8; 64] {
        return self.0.finalize().into();
    }
}

pub struct Shake256;

impl Shake256 {
    pub fn hash(data: &[u8], output: &mut [u8]) {
        sha3::Shake256::digest_xof(data, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_WORLD_HASH_256: &str = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
    const HELLO_WORLD_HASH_512: &str = "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";

    #[test]
    fn hello_world_hash() {
        let hash = hash_256(b"hello world");
        assert_eq!(hex::encode(&hash), HELLO_WORLD_HASH_256);

        let hash = hash_512(b"hello world");
        assert_eq!(hex::encode(&hash), HELLO_WORLD_HASH_512);
    }

    #[test]
    fn hello_world_hasher() {
        let mut hasher = Sha3_256::new();
        hasher.write(b"hello ");
        hasher.write(b"world");
        let hash = hasher.sum();
        assert_eq!(hex::encode(&hash), HELLO_WORLD_HASH_256);

        let mut hasher = Sha3_512::new();
        hasher.write(b"hello ");
        hasher.write(b"world");
        let hash = hasher.sum();
        assert_eq!(hex::encode(&hash), HELLO_WORLD_HASH_512);
    }
}
