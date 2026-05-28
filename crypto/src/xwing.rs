use crate::{
    mlkem,
    sha3::{Sha3_256, Shake256},
    x25519,
};

pub const XWING_SECRET_KEY_SIZE: usize = 32;
pub const XWING_PUBLIC_KEY_SIZE: usize = 1216;
pub const XWING_CIPHERTEXT_SIZE: usize = 1120;
pub const XWING_SHARED_SECRET_SIZE: usize = 32;
pub const XWING_MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
pub const XWING_MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const XWING_X25519_KEY_SIZE: usize = 32;

const XWING_LABEL: &[u8; 6] = b"\\.//^\\";

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum XWingError {
    #[error("invalid public key length")]
    InvalidPublicKey,
    #[error("invalid ciphertext length")]
    InvalidCiphertext,
    #[error("invalid secret key length")]
    InvalidSecretKey,
    #[error("ML-KEM error")]
    MlKem,
}

fn expand_decapsulation_key(
    sk: &[u8; XWING_SECRET_KEY_SIZE],
) -> (
    [u8; mlkem::ML_KEM_768_SECRET_KEY_SIZE],
    [u8; XWING_X25519_KEY_SIZE],
    [u8; mlkem::ML_KEM_768_PUBLIC_KEY_SIZE],
    [u8; XWING_X25519_KEY_SIZE],
) {
    let mut expanded = [0u8; 96];
    Shake256::hash(sk, &mut expanded);

    let mut coins = [0u8; 64];
    coins[..32].copy_from_slice(&expanded[..32]);
    coins[32..].copy_from_slice(&expanded[32..64]);
    let (sk_m, pk_m) = mlkem::ml_kem_768_keypair_derand(&coins);

    let mut sk_x = [0u8; XWING_X25519_KEY_SIZE];
    sk_x.copy_from_slice(&expanded[64..96]);
    let pk_x = x25519::x25519_derive_public_key(&sk_x);

    (sk_m, sk_x, pk_m, pk_x)
}

fn combiner(
    ss_m: &[u8; mlkem::SHARED_SECRET_SIZE],
    ss_x: &[u8; XWING_X25519_KEY_SIZE],
    ct_x: &[u8; XWING_X25519_KEY_SIZE],
    pk_x: &[u8; XWING_X25519_KEY_SIZE],
) -> [u8; XWING_SHARED_SECRET_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.write(ss_m);
    hasher.write(ss_x);
    hasher.write(ct_x);
    hasher.write(pk_x);
    hasher.write(XWING_LABEL);
    hasher.sum()
}

pub fn generate_keypair() -> ([u8; XWING_SECRET_KEY_SIZE], [u8; XWING_PUBLIC_KEY_SIZE]) {
    let sk: [u8; XWING_SECRET_KEY_SIZE] = rand::random();
    generate_keypair_derand(&sk)
}

pub fn generate_keypair_derand(
    sk: &[u8; XWING_SECRET_KEY_SIZE],
) -> ([u8; XWING_SECRET_KEY_SIZE], [u8; XWING_PUBLIC_KEY_SIZE]) {
    let (_, _, pk_m, pk_x) = expand_decapsulation_key(sk);
    let mut pk = [0u8; XWING_PUBLIC_KEY_SIZE];
    pk[..mlkem::ML_KEM_768_PUBLIC_KEY_SIZE].copy_from_slice(&pk_m);
    pk[mlkem::ML_KEM_768_PUBLIC_KEY_SIZE..].copy_from_slice(&pk_x);
    (*sk, pk)
}

pub fn encapsulate(pk: &[u8; XWING_PUBLIC_KEY_SIZE]) -> ([u8; XWING_CIPHERTEXT_SIZE], [u8; XWING_SHARED_SECRET_SIZE]) {
    let eseed: [u8; 64] = rand::random();
    encapsulate_derand(pk, &eseed)
}

pub fn encapsulate_derand(
    pk: &[u8; XWING_PUBLIC_KEY_SIZE],
    eseed: &[u8; 64],
) -> ([u8; XWING_CIPHERTEXT_SIZE], [u8; XWING_SHARED_SECRET_SIZE]) {
    let mut pk_m = [0u8; mlkem::ML_KEM_768_PUBLIC_KEY_SIZE];
    pk_m.copy_from_slice(&pk[..mlkem::ML_KEM_768_PUBLIC_KEY_SIZE]);
    let mut pk_x = [0u8; XWING_X25519_KEY_SIZE];
    pk_x.copy_from_slice(&pk[mlkem::ML_KEM_768_PUBLIC_KEY_SIZE..]);

    let mut ek_x = [0u8; XWING_X25519_KEY_SIZE];
    ek_x.copy_from_slice(&eseed[32..64]);
    let ct_x = x25519::x25519_derive_public_key(&ek_x);
    let ss_x = x25519::x25519(&ek_x, &pk_x).expect("X25519 encapsulation should not fail");

    let mut m = [0u8; 32];
    m.copy_from_slice(&eseed[..32]);
    let (ct_m, ss_m) = mlkem::ml_kem_768_enc_derand(&pk_m, &m);

    let ss = combiner(&ss_m, &ss_x, &ct_x, &pk_x);

    let mut ct = [0u8; XWING_CIPHERTEXT_SIZE];
    ct[..mlkem::ML_KEM_768_CIPHERTEXT_SIZE].copy_from_slice(&ct_m);
    ct[mlkem::ML_KEM_768_CIPHERTEXT_SIZE..].copy_from_slice(&ct_x);

    (ct, ss)
}

pub fn decapsulate(
    ct: &[u8; XWING_CIPHERTEXT_SIZE],
    sk: &[u8; XWING_SECRET_KEY_SIZE],
) -> Result<[u8; XWING_SHARED_SECRET_SIZE], XWingError> {
    let (sk_m, sk_x, _, pk_x) = expand_decapsulation_key(sk);

    let mut ct_m = [0u8; mlkem::ML_KEM_768_CIPHERTEXT_SIZE];
    ct_m.copy_from_slice(&ct[..mlkem::ML_KEM_768_CIPHERTEXT_SIZE]);
    let mut ct_x = [0u8; XWING_X25519_KEY_SIZE];
    ct_x.copy_from_slice(&ct[mlkem::ML_KEM_768_CIPHERTEXT_SIZE..]);

    let ss_m = mlkem::ml_kem_768_decapsulate(&sk_m, &ct_m).map_err(|_| XWingError::MlKem)?;
    let ss_x = x25519::x25519(&sk_x, &ct_x).expect("X25519 decapsulation should not fail");

    Ok(combiner(&ss_m, &ss_x, &ct_x, &pk_x))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_array<const N: usize>(hex_str: &str) -> [u8; N] {
        let bytes = hex::decode(hex_str).unwrap();
        return bytes.try_into().unwrap();
    }

    struct TestVector {
        seed: &'static str,
        eseed: &'static str,
        ss: &'static str,
    }

    const TEST_VECTORS: [TestVector; 3] = [
        TestVector {
            seed: "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
            eseed: "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
            ss: "f636678933b553753ea6fe894920f818836c960b2bd6957f51cf310180bea9ac",
        },
        TestVector {
            seed: "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea",
            eseed: "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d",
            ss: "79136dee58cc60328091eb53016ee9cd960d89c9e69be1d9b463a899b720b836",
        },
        TestVector {
            seed: "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9",
            eseed: "22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b",
            ss: "310630789988a927583e90f9ed42f013aa874347f8ab1744f035e02ac901af8e",
        },
    ];

    #[test]
    fn test_vectors_from_draft() {
        for (i, tv) in TEST_VECTORS.iter().enumerate() {
            let seed: [u8; 32] = hex_to_array(tv.seed);
            let eseed: [u8; 64] = hex_to_array(tv.eseed);
            let expected_ss: [u8; 32] = hex_to_array(tv.ss);

            let (sk, pk) = generate_keypair_derand(&seed);
            assert_eq!(sk, seed, "vector {i}: sk mismatch");

            let (ct, ss) = encapsulate_derand(&pk, &eseed);
            assert_eq!(ss, expected_ss, "vector {i}: encaps ss mismatch");

            let decapsulated_ss = decapsulate(&ct, &sk).unwrap();
            assert_eq!(decapsulated_ss, expected_ss, "vector {i}: decaps ss mismatch");
        }
    }

    #[test]
    fn round_trip() {
        let (sk, pk) = generate_keypair();
        let (ct, ss) = encapsulate(&pk);
        let decapsulated = decapsulate(&ct, &sk).unwrap();
        assert_eq!(ss, decapsulated);
    }

    #[test]
    fn round_trip_many() {
        for _ in 0..10 {
            let (sk, pk) = generate_keypair();
            let (ct, ss) = encapsulate(&pk);
            let decapsulated = decapsulate(&ct, &sk).unwrap();
            assert_eq!(ss, decapsulated);
        }
    }

    #[test]
    fn decapsulation_with_wrong_key_produces_different_secret() {
        let (_sk_a, pk_a) = generate_keypair();
        let (sk_b, _) = generate_keypair();
        let (ct, ss_a) = encapsulate(&pk_a);
        let ss_b = decapsulate(&ct, &sk_b).unwrap();
        assert_ne!(ss_a, ss_b);
    }

    #[test]
    fn tampered_ciphertext_produces_different_secret() {
        let (sk, pk) = generate_keypair();
        let (mut ct, ss) = encapsulate(&pk);

        ct[0] ^= 0x80;

        let tampered_ss = decapsulate(&ct, &sk).unwrap();
        assert_ne!(ss, tampered_ss);
    }

    #[test]
    fn derandomized_keygen_is_deterministic() {
        let seed: [u8; 32] = hex_to_array("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let (sk1, pk1) = generate_keypair_derand(&seed);
        let (sk2, pk2) = generate_keypair_derand(&seed);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn derandomized_encaps_is_deterministic() {
        let seed: [u8; 32] = hex_to_array("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let eseed: [u8; 64] = hex_to_array(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        );
        let (_, pk) = generate_keypair_derand(&seed);

        let (ct1, ss1) = encapsulate_derand(&pk, &eseed);
        let (ct2, ss2) = encapsulate_derand(&pk, &eseed);
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn key_sizes_are_correct() {
        let (sk, pk) = generate_keypair();
        assert_eq!(sk.len(), XWING_SECRET_KEY_SIZE);
        assert_eq!(pk.len(), XWING_PUBLIC_KEY_SIZE);
        let (ct, _ss) = encapsulate(&pk);
        assert_eq!(ct.len(), XWING_CIPHERTEXT_SIZE);
    }

    #[test]
    fn public_key_structure() {
        let seed: [u8; 32] = hex_to_array("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let (_, pk) = generate_keypair_derand(&seed);

        assert_eq!(pk.len(), XWING_PUBLIC_KEY_SIZE);
        let pk_m = &pk[..mlkem::ML_KEM_768_PUBLIC_KEY_SIZE];
        assert_eq!(pk_m.len(), mlkem::ML_KEM_768_PUBLIC_KEY_SIZE);
        let pk_x = &pk[mlkem::ML_KEM_768_PUBLIC_KEY_SIZE..];
        assert_eq!(pk_x.len(), XWING_X25519_KEY_SIZE);
    }

    #[test]
    fn ciphertext_structure() {
        let seed: [u8; 32] = hex_to_array("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let eseed: [u8; 64] = hex_to_array(
            "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
        );
        let (_, pk) = generate_keypair_derand(&seed);
        let (ct, _) = encapsulate_derand(&pk, &eseed);

        assert_eq!(ct.len(), XWING_CIPHERTEXT_SIZE);
        let ct_m = &ct[..mlkem::ML_KEM_768_CIPHERTEXT_SIZE];
        assert_eq!(ct_m.len(), mlkem::ML_KEM_768_CIPHERTEXT_SIZE);
        let ct_x = &ct[mlkem::ML_KEM_768_CIPHERTEXT_SIZE..];
        assert_eq!(ct_x.len(), XWING_X25519_KEY_SIZE);
    }

    #[test]
    fn xwing_label_is_correct() {
        assert_eq!(XWING_LABEL.len(), 6);
        assert_eq!(hex::encode(XWING_LABEL), "5c2e2f2f5e5c");
    }

    #[test]
    fn expand_decapsulation_key_is_deterministic() {
        let seed: [u8; 32] = hex_to_array("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let (sk_m1, sk_x1, pk_m1, pk_x1) = expand_decapsulation_key(&seed);
        let (sk_m2, sk_x2, pk_m2, pk_x2) = expand_decapsulation_key(&seed);
        assert_eq!(sk_m1, sk_m2);
        assert_eq!(sk_x1, sk_x2);
        assert_eq!(pk_m1, pk_m2);
        assert_eq!(pk_x1, pk_x2);
    }

    #[test]
    fn combiner_is_deterministic() {
        let ss_m = [0x01u8; 32];
        let ss_x = [0x02u8; 32];
        let ct_x = [0x03u8; 32];
        let pk_x = [0x04u8; 32];

        let result1 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
        let result2 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
        assert_eq!(result1, result2);
    }

    #[test]
    fn pk_x_recovered_from_sk_matches_pk() {
        let seed: [u8; 32] = hex_to_array("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        let (_, sk_x, _, pk_x) = expand_decapsulation_key(&seed);
        let recovered_pk_x = x25519::x25519_derive_public_key(&sk_x);
        assert_eq!(recovered_pk_x, pk_x);
    }
}

#[cfg(test)]
mod diag {
    use super::*;
    
    #[test]
    fn dump_intermediates() {
        let seed: [u8; 32] = hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26").unwrap().try_into().unwrap();
        
        // Step 1: SHAKE256 expansion
        let mut expanded = [0u8; 96];
        Shake256::hash(&seed, &mut expanded);
        eprintln!("expanded[0:32]  = {}", hex::encode(&expanded[..32]));
        eprintln!("expanded[32:64] = {}", hex::encode(&expanded[32..64]));
        eprintln!("expanded[64:96] = {}", hex::encode(&expanded[64..96]));
        
        let (sk_m, sk_x, pk_m, pk_x) = expand_decapsulation_key(&seed);
        eprintln!("pk_m[0:36] = {}", hex::encode(&pk_m[..36]));
        eprintln!("pk_x = {}", hex::encode(&pk_x));
        
        // Compare with spec pk start
        // Spec says pk starts with: e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d
        let spec_pk_start = "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d";
        eprintln!("\nspec pk_m start: {}", spec_pk_start);
        eprintln!("our  pk_m start: {}", hex::encode(&pk_m[..36]));
        eprintln!("pk_m matches spec: {}", hex::encode(&pk_m[..36]) == spec_pk_start);
        
        // Check spec pk_x - it's the last 32 bytes of the full pk
        // Full pk = pk_m || pk_x
        // From spec, pk ends with: ...ef6534 then pk_x follows
        // Looking at spec pk: after 1184 bytes of pk_m, we have 32 bytes of pk_x
        // Spec pk hex is very long, let me just check the last 32 bytes
    }
}

#[cfg(test)]
mod diag2 {
    use super::*;

    #[test]
    fn check_pk_m_rho() {
        let seed: [u8; 32] = hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26").unwrap().try_into().unwrap();
        let (_, _, pk_m, _) = expand_decapsulation_key(&seed);
        // In ML-KEM, pk = t_hat || rho, so rho = pk[1152..1184]
        eprintln!("pk_m last 32 bytes (rho) = {}", hex::encode(&pk_m[1152..1184]));
        eprintln!("pk_m first 32 bytes = {}", hex::encode(&pk_m[..32]));
        
        // From spec pk, extract first 36 bytes  
        let spec_pk_hex = "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d";
        eprintln!("spec pk_m first 36 bytes = {}", spec_pk_hex);
    }
}
