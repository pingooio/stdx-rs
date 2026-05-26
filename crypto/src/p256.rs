use crate::Error;
use ::p256::{
    EncodedPoint, PublicKey, SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    elliptic_curve::sec1::ToEncodedPoint,
};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const SIGNATURE_SIZE: usize = 64;

fn parse_secret_key(private_key: &[u8; PRIVATE_KEY_SIZE]) -> Result<SecretKey, Error> {
    SecretKey::from_slice(private_key).map_err(|_| Error::InvalidKey)
}

pub fn derive_public_key_uncompressed(
    private_key: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_UNCOMPRESSED_SIZE], Error> {
    let secret_key = parse_secret_key(private_key)?;
    let encoded = secret_key.public_key().to_encoded_point(false);
    let mut out = [0u8; PUBLIC_KEY_UNCOMPRESSED_SIZE];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

pub fn derive_public_key_compressed(
    private_key: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_COMPRESSED_SIZE], Error> {
    let secret_key = parse_secret_key(private_key)?;
    let encoded = secret_key.public_key().to_encoded_point(true);
    let mut out = [0u8; PUBLIC_KEY_COMPRESSED_SIZE];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

pub fn ecdsa_sign(
    private_key: &[u8; PRIVATE_KEY_SIZE],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], Error> {
    let signing_key = SigningKey::from_bytes(private_key.into()).map_err(|_| Error::InvalidKey)?;
    let signature: Signature = signing_key.sign(message);
    let mut out = [0u8; SIGNATURE_SIZE];
    out.copy_from_slice(signature.to_bytes().as_slice());
    Ok(out)
}

pub fn ecdsa_verify(public_key: &[u8], message: &[u8], signature: &[u8; SIGNATURE_SIZE]) -> Result<(), Error> {
    let encoded = EncodedPoint::from_bytes(public_key).map_err(|_| Error::InvalidKey)?;
    let verifying_key = VerifyingKey::from_encoded_point(&encoded).map_err(|_| Error::InvalidKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Unspecified)?;
    verifying_key.verify(message, &signature).map_err(|_| Error::Unspecified)
}

pub fn is_valid_public_key(public_key: &[u8]) -> bool {
    PublicKey::from_sec1_bytes(public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(hex_bytes: &str) -> [u8; N] {
        let bytes = hex::decode(hex_bytes).unwrap();
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn uncompressed_public_key(x: &str, y: &str) -> [u8; PUBLIC_KEY_UNCOMPRESSED_SIZE] {
        let mut out = [0u8; PUBLIC_KEY_UNCOMPRESSED_SIZE];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&decode_hex::<32>(x));
        out[33..65].copy_from_slice(&decode_hex::<32>(y));
        out
    }

    #[test]
    fn derive_public_key_generator_matches_sec1_base_point() {
        let mut private_key = [0u8; 32];
        private_key[31] = 1;
        let derived = derive_public_key_uncompressed(&private_key).unwrap();
        let expected = decode_hex::<65>(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        );
        assert_eq!(derived, expected);
    }

    #[test]
    fn derive_public_key_matches_rfc6979_vector() {
        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let expected = uncompressed_public_key(
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        );
        let derived = derive_public_key_uncompressed(&private_key).unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn ecdsa_sign_matches_rfc6979_vectors() {
        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");

        let sample_signature = ecdsa_sign(&private_key, b"sample").unwrap();
        let expected_sample = decode_hex::<64>(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
             f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        );
        assert_eq!(sample_signature, expected_sample);

        let test_signature = ecdsa_sign(&private_key, b"test").unwrap();
        let expected_test = decode_hex::<64>(
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367\
             019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
        );
        assert_eq!(test_signature, expected_test);
    }

    #[test]
    fn ecdsa_verify_accepts_valid_and_rejects_invalid_signatures() {
        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let public_key = derive_public_key_uncompressed(&private_key).unwrap();
        let signature = ecdsa_sign(&private_key, b"sample").unwrap();

        assert!(ecdsa_verify(&public_key, b"sample", &signature).is_ok());
        assert!(ecdsa_verify(&public_key, b"tampered", &signature).is_err());

        let mut tampered_signature = signature;
        tampered_signature[10] ^= 0x80;
        assert!(ecdsa_verify(&public_key, b"sample", &tampered_signature).is_err());
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        let invalid_private_key = [0u8; PRIVATE_KEY_SIZE];
        assert!(derive_public_key_uncompressed(&invalid_private_key).is_err());
        assert!(ecdsa_sign(&invalid_private_key, b"msg").is_err());

        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let signature = ecdsa_sign(&private_key, b"msg").unwrap();
        assert!(ecdsa_verify(&[0x01; PUBLIC_KEY_UNCOMPRESSED_SIZE], b"msg", &signature).is_err());
        assert!(!is_valid_public_key(&[0x00; PUBLIC_KEY_UNCOMPRESSED_SIZE]));
    }
}
