// use aws_lc_rs::aead::{self, LessSafeKey, UnboundKey};

// use super::Error;

// pub struct Aes256Gcm {
//     ctx: LessSafeKey,
// }

// impl Aes256Gcm {
//     pub const KEY_SIZE: usize = 32;
//     pub const TAG_SIZE: usize = 16;
//     pub const NONCE_SIZE: usize = 12;

//     pub fn new(key: &[u8]) -> Result<Aes256Gcm, Error> {
//         if key.len() != Aes256Gcm::KEY_SIZE {
//             return Err(Error::InvalidKey);
//         }

//         let ctx =
//             LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key).expect("crypto: error initializing Aes256Gcm"));
//         return Ok(Aes256Gcm { ctx });
//     }

//     #[inline]
//     pub fn encrypt(&self, plaintext: &[u8], nonce: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, Error> {
//         if nonce.len() != Aes256Gcm::NONCE_SIZE {
//             return Err(Error::InvalidNonce);
//         }

//         // let mut dest = vec![0u8; plaintext.len() + Aes256Gcm::TAG_SIZE];

//         // dest[0..plaintext.len()].copy_from_slice(plaintext);

//         // let tag = self
//         //     .ctx
//         //     .seal_in_place_separate_tag(
//         //         aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//         //         aead::Aad::from(additional_data),
//         //         &mut dest[0..plaintext.len()],
//         //     )
//         //     .unwrap();

//         // dest[plaintext.len()..].copy_from_slice(tag.as_ref());

//         let mut dest = Vec::with_capacity(plaintext.len() + Aes256Gcm::TAG_SIZE);

//         // When optimized by the compiler `extend` does basically a memcopy
//         // https://users.rust-lang.org/t/pearl-extending-a-vec-via-append-or-extend/73456
//         dest.extend(plaintext);

//         self.ctx
//             .seal_in_place_append_tag(
//                 aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//                 aead::Aad::from(additional_data),
//                 &mut dest,
//             )
//             .map_err(|_| Error::Unspecified)?;

//         return Ok(dest);
//     }

//     #[inline]
//     pub fn encrypt_in_place(&self, in_out: &mut Vec<u8>, nonce: &[u8], additional_data: &[u8]) {
//         self.ctx
//             .seal_in_place_append_tag(
//                 aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//                 aead::Aad::from(additional_data),
//                 in_out,
//             )
//             .unwrap();
//     }

//     #[inline]
//     pub fn encrypt_in_place_detached(
//         &self,
//         in_out: &mut Vec<u8>,
//         nonce: &[u8],
//         additional_data: &[u8],
//     ) -> [u8; Aes256Gcm::TAG_SIZE] {
//         let tag = self
//             .ctx
//             .seal_in_place_separate_tag(
//                 aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//                 aead::Aad::from(additional_data),
//                 in_out,
//             )
//             .unwrap();

//         return tag.as_ref().try_into().unwrap();
//     }

//     // #[inline]
//     // pub fn encrypt_detached(
//     //     &self,
//     //     dest: &mut [u8],
//     //     nonce: &[u8],
//     //     plaintext: &[u8],
//     //     additional_data: &[u8],
//     // ) -> [u8; Aes256Gcm::TAG_SIZE] {
//     //     assert_eq!(nonce.len(), Aes256Gcm::NONCE_SIZE);
//     //     assert_eq!(dest.len(), plaintext.len());

//     //     dest.copy_from_slice(plaintext);

//     //     let tag = self
//     //         .ctx
//     //         .seal_in_place_separate_tag(
//     //             aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//     //             aead::Aad::from(additional_data),
//     //             dest,
//     //         )
//     //         .unwrap();

//     //     return tag.as_ref().try_into().unwrap();
//     // }

//     #[inline]
//     pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], additional_data: &[u8]) -> Result<Vec<u8>, Error> {
//         if nonce.len() != Aes256Gcm::NONCE_SIZE {
//             return Err(Error::InvalidNonce);
//         }
//         if ciphertext.len() < Aes256Gcm::TAG_SIZE {
//             return Err(Error::InvalidCiphertext);
//         }

//         let mut ret = ciphertext.to_vec();

//         self.ctx
//             .open_in_place(
//                 aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//                 aead::Aad::from(additional_data),
//                 &mut ret,
//             )
//             .map_err(|_| Error::Unspecified)?;

//         ret.truncate(ciphertext.len() - Aes256Gcm::TAG_SIZE);

//         return Ok(ret);
//     }

//     #[inline]
//     pub fn decrypt_in_place<'io>(&self, in_out: &'io mut [u8], nonce: &[u8], additional_data: &[u8]) -> &'io mut [u8] {
//         assert_eq!(nonce.len(), Aes256Gcm::NONCE_SIZE, "nonce size is not valid");
//         assert!(in_out.len() >= Aes256Gcm::TAG_SIZE, "ciphertext is not valid");

//         return self
//             .ctx
//             .open_in_place(
//                 aead::Nonce::assume_unique_for_key(nonce.try_into().unwrap()),
//                 aead::Aad::from(additional_data),
//                 in_out,
//             )
//             .unwrap();
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::Aes256Gcm;

//     #[test]
//     fn encrypt_decrypt() {
//         let message = b"hello world";

//         let insecure_nonce = [0u8; Aes256Gcm::NONCE_SIZE];
//         let insecure_key = [0u8; Aes256Gcm::KEY_SIZE];
//         let additional_data = [0u8; 0];
//         let cipher = Aes256Gcm::new(&insecure_key).unwrap();

//         let ciphertext = cipher.encrypt(message, &insecure_nonce, &additional_data).unwrap();
//         let decrypted_message = cipher.decrypt(&ciphertext, &insecure_nonce, &additional_data).unwrap();

//         assert_eq!(*message, *decrypted_message);
//     }
// }
