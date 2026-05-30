#[cfg(feature = "alloc")]
extern crate alloc;

pub mod aes;
#[cfg(feature = "alloc")]
pub mod argon2;
pub mod blake2;
pub mod chacha;
pub mod curve25519;
pub mod hkdf;
pub mod hmac;
#[cfg(not(target_arch = "wasm32"))]
pub mod mlkem;
pub mod poly1305;
pub mod sha2;
pub mod sha3;
#[cfg(not(target_arch = "wasm32"))]
pub mod xwing;

mod bytes;

#[cfg(feature = "alloc")]
pub mod encoding;
pub mod p256;
pub use aes::Aes256Gcm;
pub use bytes::Bytes;

pub use crate::hkdf::HkdfError;

const MAX_HASH_BLOCK_SIZE: usize = 128;

pub type Hash = Bytes<64>;
pub type Tag = Bytes<32>;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("{0}")]
    Hkdf(HkdfError),
    #[error("{0}")]
    Aead(AeadError),
    #[error("{0}")]
    EllipticCurve(EllipticCurveError),
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    #[error("key is not valid")]
    InvalidKey,
    #[error("nonce is not valid")]
    InvalidNonce,
    #[error("ciphertext is not valid")]
    InvalidCiphertext,
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum EllipticCurveError {
    #[error("key is not valid")]
    InvalidKey,
    #[error("unknown")]
    Unspecified,
}

pub trait StreamCipher: Sized {
    fn xor_keystream(&mut self, in_out: &mut [u8]);
}

pub trait Aead: Sized {
    const TAG_SIZE: usize;
    const NONCE_SIZE: usize;

    fn encrypt_in_place_detached(&self, in_out: &mut [u8], nonce: &[u8], aad: &[u8]) -> Tag;
    fn decrypt_in_place_detached(
        &self,
        in_out: &mut [u8],
        nonce: &[u8],
        aad: &[u8],
        tag: &[u8],
    ) -> Result<(), AeadError>;

    #[cfg(feature = "alloc")]
    fn encrypt(&self, plaintext: &[u8], nonce: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut ciphertext = alloc::vec::Vec::with_capacity(plaintext.len() + Self::TAG_SIZE);
        ciphertext.extend_from_slice(plaintext);

        let tag = self.encrypt_in_place_detached(&mut ciphertext, nonce, aad);
        ciphertext.extend_from_slice(tag.as_ref());

        return ciphertext;
    }

    #[cfg(feature = "alloc")]
    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        if ciphertext.len() < Self::TAG_SIZE {
            return Err(AeadError::InvalidCiphertext);
        }

        let plaintext_length = ciphertext.len() - Self::TAG_SIZE;
        let mut plaintext = alloc::vec::Vec::with_capacity(plaintext_length);
        plaintext.extend_from_slice(&ciphertext[..plaintext_length]);

        self.decrypt_in_place_detached(&mut plaintext, &nonce, aad, &ciphertext[plaintext_length..])?;

        return Ok(plaintext);
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

pub trait Xof: Sized + Send + Sync {
    fn absorb(&mut self, data: &[u8]);
    fn squeeze(&mut self, out: &mut [u8]);
}
