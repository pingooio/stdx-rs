use aws_lc_rs::{
    error::{KeyRejected, Unspecified},
    kem::{Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024, ML_KEM_768},
};

pub const SHARED_SECRET_SIZE: usize = 32;

pub const ML_KEM_768_PUBLIC_KEY_SIZE: usize = 1184;
pub const ML_KEM_768_SECRET_KEY_SIZE: usize = 2400;
pub const ML_KEM_768_CIPHERTEXT_SIZE: usize = 1088;

pub const ML_KEM_1024_PUBLIC_KEY_SIZE: usize = 1568;
pub const ML_KEM_1024_SECRET_KEY_SIZE: usize = 3168;
pub const ML_KEM_1024_CIPHERTEXT_SIZE: usize = 1568;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemError {
    #[error("key is not valid")]
    InvalidKey,
    #[error("ciphertext is not valid")]
    InvalidCiphertext,
    #[error("unknown")]
    Unspecified,
}

impl From<KeyRejected> for MlKemError {
    fn from(_value: KeyRejected) -> Self {
        MlKemError::InvalidKey
    }
}

impl From<Unspecified> for MlKemError {
    fn from(_value: Unspecified) -> Self {
        MlKemError::Unspecified
    }
}

#[inline]
pub fn ml_kem_768_generate_keypair(
) -> Result<([u8; ML_KEM_768_SECRET_KEY_SIZE], [u8; ML_KEM_768_PUBLIC_KEY_SIZE]), MlKemError> {
    generate_keypair(&ML_KEM_768)
}

#[inline]
pub fn ml_kem_768_encapsulate(
    public_key: &[u8; ML_KEM_768_PUBLIC_KEY_SIZE],
) -> Result<([u8; ML_KEM_768_CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]), MlKemError> {
    encapsulate::<ML_KEM_768_PUBLIC_KEY_SIZE, ML_KEM_768_CIPHERTEXT_SIZE>(&ML_KEM_768, public_key)
}

#[inline]
pub fn ml_kem_768_decapsulate(
    private_key: &[u8; ML_KEM_768_SECRET_KEY_SIZE],
    ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
    decapsulate::<ML_KEM_768_SECRET_KEY_SIZE, ML_KEM_768_CIPHERTEXT_SIZE>(&ML_KEM_768, private_key, ciphertext)
}

#[inline]
pub fn ml_kem_1024_generate_keypair(
) -> Result<([u8; ML_KEM_1024_SECRET_KEY_SIZE], [u8; ML_KEM_1024_PUBLIC_KEY_SIZE]), MlKemError> {
    generate_keypair(&ML_KEM_1024)
}

#[inline]
pub fn ml_kem_1024_encapsulate(
    public_key: &[u8; ML_KEM_1024_PUBLIC_KEY_SIZE],
) -> Result<([u8; ML_KEM_1024_CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]), MlKemError> {
    encapsulate::<ML_KEM_1024_PUBLIC_KEY_SIZE, ML_KEM_1024_CIPHERTEXT_SIZE>(&ML_KEM_1024, public_key)
}

#[inline]
pub fn ml_kem_1024_decapsulate(
    private_key: &[u8; ML_KEM_1024_SECRET_KEY_SIZE],
    ciphertext: &[u8; ML_KEM_1024_CIPHERTEXT_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
    decapsulate::<ML_KEM_1024_SECRET_KEY_SIZE, ML_KEM_1024_CIPHERTEXT_SIZE>(&ML_KEM_1024, private_key, ciphertext)
}

#[inline]
fn generate_keypair<const SECRET_KEY_SIZE: usize, const PUBLIC_KEY_SIZE: usize>(
    algorithm: &'static Algorithm,
) -> Result<([u8; SECRET_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]), MlKemError> {
    let decapsulation_key = DecapsulationKey::generate(algorithm)?;
    let encapsulation_key = decapsulation_key.encapsulation_key()?;

    let private_key = to_fixed_size(decapsulation_key.key_bytes()?.as_ref());
    let public_key = to_fixed_size(encapsulation_key.key_bytes()?.as_ref());

    return Ok((private_key, public_key));
}

#[inline]
fn encapsulate<const PUBLIC_KEY_SIZE: usize, const CIPHERTEXT_SIZE: usize>(
    algorithm: &'static Algorithm,
    public_key: &[u8; PUBLIC_KEY_SIZE],
) -> Result<([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]), MlKemError> {
    let encapsulation_key = EncapsulationKey::new(algorithm, public_key)?;
    let (ciphertext, shared_secret) = encapsulation_key.encapsulate()?;

    let ciphertext_bytes = to_fixed_size(ciphertext.as_ref());
    let shared_secret_bytes = to_fixed_size(shared_secret.as_ref());

    return Ok((ciphertext_bytes, shared_secret_bytes));
}

#[inline]
fn decapsulate<const SECRET_KEY_SIZE: usize, const CIPHERTEXT_SIZE: usize>(
    algorithm: &'static Algorithm,
    private_key: &[u8; SECRET_KEY_SIZE],
    ciphertext: &[u8; CIPHERTEXT_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
    let decapsulation_key = DecapsulationKey::new(algorithm, private_key)?;
    let shared_secret = decapsulation_key
        .decapsulate(Ciphertext::from(ciphertext.as_ref()))
        .map_err(|_| MlKemError::InvalidCiphertext)?;

    return Ok(to_fixed_size(shared_secret.as_ref()));
}

#[inline]
fn to_fixed_size<const SIZE: usize>(input: &[u8]) -> [u8; SIZE] {
    debug_assert_eq!(input.len(), SIZE);
    let mut out = [0u8; SIZE];
    out.copy_from_slice(input);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_kem_768_round_trip() {
        let (private_key, public_key) = ml_kem_768_generate_keypair().unwrap();
        let (ciphertext, encapsulated_secret) = ml_kem_768_encapsulate(&public_key).unwrap();
        let decapsulated_secret = ml_kem_768_decapsulate(&private_key, &ciphertext).unwrap();

        assert_eq!(encapsulated_secret, decapsulated_secret);
    }

    #[test]
    fn ml_kem_1024_round_trip() {
        let (private_key, public_key) = ml_kem_1024_generate_keypair().unwrap();
        let (ciphertext, encapsulated_secret) = ml_kem_1024_encapsulate(&public_key).unwrap();
        let decapsulated_secret = ml_kem_1024_decapsulate(&private_key, &ciphertext).unwrap();

        assert_eq!(encapsulated_secret, decapsulated_secret);
    }

    #[test]
    fn ml_kem_768_decapsulation_rejects_tampered_ciphertext() {
        let (private_key, public_key) = ml_kem_768_generate_keypair().unwrap();
        let (mut ciphertext, encapsulated_secret) = ml_kem_768_encapsulate(&public_key).unwrap();

        ciphertext[0] ^= 0x80;

        let decapsulated_secret = ml_kem_768_decapsulate(&private_key, &ciphertext).unwrap();

        assert_ne!(encapsulated_secret, decapsulated_secret);
    }
}
