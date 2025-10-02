mod aes;
pub use aes::Aes256Gcm;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidKey,
    InvalidNonce,
    InvalidCiphertext,
    Unspecified,
}

pub trait Cipher {
    // const TAG_SIZE: usize;
    const NONCE_SIZE: usize;
    // const KEY_SIZE: usize;

    // /// encrypt returns `plaintext || tag`
    // fn encrypt(&self, plaintext: &[u8], nonce: &[u8], additional_data: &[u8]) -> Vec<u8>;
    // fn encrypt_in_place_detached(
    //     &self,
    //     in_out: &mut Vec<u8>,
    //     nonce: &[u8],
    //     additional_data: &[u8],
    // ) -> [u8; Self::TAG_SIZE];
}
