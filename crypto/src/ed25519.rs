use big_number::Uint;

use crate::{EllipticCurveError, Hasher, sha2::Sha512};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;

type U256 = Uint<256, 4>;

const MODULUS_P: U256 = U256::from_limbs([
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
]);

const MODULUS_L: U256 = U256::from_limbs([
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
]);

const P_MINUS_TWO: U256 = U256::from_limbs([
    0xffff_ffff_ffff_ffeb,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
]);

const P_PLUS_THREE_OVER_EIGHT: U256 = U256::from_limbs([
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0fff_ffff_ffff_ffff,
]);

const EDWARDS_D: FieldElement = FieldElement(U256::from_limbs([
    0x75eb_4dca_1359_78a3,
    0x0070_0a4d_4141_d8ab,
    0x8cc7_4079_7779_e898,
    0x5203_6cee_2b6f_fe73,
]));

const EDWARDS_2D: FieldElement = FieldElement(U256::from_limbs([
    0xebd6_9b94_26b2_f159,
    0x00e0_149a_8283_b156,
    0x198e_80f2_eef3_d130,
    0x2406_d9dc_56df_fce7,
]));

const SQRT_M1: FieldElement = FieldElement(U256::from_limbs([
    0xc4ee_1b27_4a0e_a0b0,
    0x2f43_1806_ad2f_e478,
    0x2b4d_0099_3dfb_d7a7,
    0x2b83_2480_4fc1_df0b,
]));

const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldElement(U256);

impl FieldElement {
    const ZERO: Self = Self(U256::ZERO);
    const ONE: Self = Self(U256::ONE);

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let value = U256::from_le_slice(bytes);
        if value.ct_ge(&MODULUS_P) {
            None
        } else {
            Some(Self(value))
        }
    }

    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        self.0.to_le_bytes_fixed::<32>()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    #[inline]
    fn is_odd(&self) -> bool {
        self.0.is_odd()
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &MODULUS_P))
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &MODULUS_P))
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod(&rhs.0, &MODULUS_P))
    }

    #[inline]
    fn square(self) -> Self {
        self.mul(self)
    }

    #[inline]
    fn negate(self) -> Self {
        let (diff, _) = MODULUS_P.sub_raw(&self.0);
        Self(U256::ct_select(&U256::ZERO, &diff, self.is_zero()))
    }

    #[inline]
    fn invert(self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow(&P_MINUS_TWO))
        }
    }

    #[inline]
    fn pow(self, exponent: &U256) -> Self {
        let mut result = Self::ONE;
        let mut i = 256usize;
        while i > 0 {
            i -= 1;
            result = result.square();
            let product = result.mul(self);
            result = Self::select(&product, &result, exponent.bit(i));
        }
        result
    }

    #[inline]
    fn sqrt(self) -> Option<Self> {
        let mut candidate = self.pow(&P_PLUS_THREE_OVER_EIGHT);
        if candidate.square() != self {
            candidate = candidate.mul(SQRT_M1);
        }
        if candidate.square() == self {
            Some(candidate)
        } else {
            None
        }
    }

    #[inline]
    fn select(a: &Self, b: &Self, choice: bool) -> Self {
        Self(U256::ct_select(&a.0, &b.0, choice))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scalar(U256);

impl Scalar {
    #[inline]
    fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let value = U256::from_le_slice(bytes);
        if value.ct_ge(&MODULUS_L) {
            None
        } else {
            Some(Self(value))
        }
    }

    #[inline]
    fn reduce_bytes_mod_l(bytes: &[u8]) -> Self {
        let mut acc = U256::ZERO;
        let mut i = bytes.len();
        while i > 0 {
            i -= 1;
            let mut bit = 8usize;
            while bit > 0 {
                bit -= 1;
                acc = acc.double_mod(&MODULUS_L);
                if ((bytes[i] >> bit) & 1) == 1 {
                    acc = acc.add_mod(&U256::ONE, &MODULUS_L);
                }
            }
        }
        Self(acc)
    }

    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        self.0.to_le_bytes_fixed::<32>()
    }

    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.0.bit(index)
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &MODULUS_L))
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod(&rhs.0, &MODULUS_L))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl EdwardsPoint {
    #[inline]
    fn identity() -> Self {
        Self {
            x: FieldElement::ZERO,
            y: FieldElement::ONE,
            z: FieldElement::ONE,
            t: FieldElement::ZERO,
        }
    }

    #[inline]
    fn from_affine(x: FieldElement, y: FieldElement) -> Self {
        Self {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(y),
        }
    }

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let sign = (bytes[31] >> 7) == 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7f;
        let y = FieldElement::from_bytes(&y_bytes)?;
        let y2 = y.square();
        let u = y2.sub(FieldElement::ONE);
        let v = EDWARDS_D.mul(y2).add(FieldElement::ONE);
        let x2 = u.mul(v.invert()?);
        let mut x = x2.sqrt()?;
        if x.is_zero() && sign {
            return None;
        }
        if x.is_odd() != sign {
            x = x.negate();
        }
        Some(Self::from_affine(x, y))
    }

    #[inline]
    fn to_bytes(self) -> Option<[u8; 32]> {
        let inv_z = self.z.invert()?;
        let x = self.x.mul(inv_z);
        let y = self.y.mul(inv_z);
        let mut out = y.to_bytes();
        if x.is_odd() {
            out[31] |= 0x80;
        }
        Some(out)
    }

    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
        let c = self.t.mul(rhs.t).mul(EDWARDS_2D);
        let d = self.z.mul(rhs.z).add(self.z.mul(rhs.z));
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    #[inline]
    fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(self.z.square());
        let d = a.negate();
        let e = self.x.add(self.y).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            t: e.mul(h),
            z: f.mul(g),
        }
    }

    #[inline]
    fn mul_by_cofactor(&self) -> Self {
        self.double().double().double()
    }
}

#[inline]
fn basepoint() -> EdwardsPoint {
    EdwardsPoint::from_bytes(&BASEPOINT_COMPRESSED).expect("ed25519 basepoint must be valid")
}

#[inline]
fn scalar_mul(point: &EdwardsPoint, scalar: &Scalar) -> EdwardsPoint {
    let mut result = EdwardsPoint::identity();
    let mut addend = *point;
    let mut i = 0usize;
    while i < 256 {
        if scalar.bit(i) {
            result = result.add(&addend);
        }
        addend = addend.double();
        i += 1;
    }
    result
}

#[inline]
fn scalar_mul_base(scalar: &Scalar) -> EdwardsPoint {
    scalar_mul(&basepoint(), scalar)
}

#[inline]
fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    let mut i = 0usize;
    while i < parts.len() {
        hasher.update(parts[i]);
        i += 1;
    }
    let digest = hasher.sum();
    Scalar::reduce_bytes_mod_l(digest.as_ref())
}

#[inline]
fn expand_secret(private_key: &[u8; PRIVATE_KEY_SIZE]) -> (Scalar, [u8; 32]) {
    let digest = Sha512::hash(private_key);
    let mut expanded = [0u8; 64];
    expanded.copy_from_slice(digest.as_ref());

    expanded[0] &= 248;
    expanded[31] &= 63;
    expanded[31] |= 64;

    let scalar = Scalar::reduce_bytes_mod_l(&expanded[..32]);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&expanded[32..]);
    (scalar, prefix)
}

pub fn derive_public_key(private_key: &[u8; PRIVATE_KEY_SIZE]) -> [u8; PUBLIC_KEY_SIZE] {
    let (scalar, _) = expand_secret(private_key);
    scalar_mul_base(&scalar)
        .to_bytes()
        .expect("basepoint multiplication must produce a valid point")
}

pub fn ed25519_sign(private_key: &[u8; PRIVATE_KEY_SIZE], message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let (a, prefix) = expand_secret(private_key);
    let public_key = derive_public_key(private_key);

    let r = hash_to_scalar(&[&prefix, message]);
    let r_point = scalar_mul_base(&r)
        .to_bytes()
        .expect("basepoint multiplication must produce a valid point");

    let k = hash_to_scalar(&[&r_point, &public_key, message]);
    let s = r.add(k.mul(a));

    let mut signature = [0u8; SIGNATURE_SIZE];
    signature[..32].copy_from_slice(&r_point);
    signature[32..].copy_from_slice(&s.to_bytes());
    signature
}

pub fn ed25519_verify(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), EllipticCurveError> {
    let a = EdwardsPoint::from_bytes(public_key).ok_or(EllipticCurveError::InvalidKey)?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r = EdwardsPoint::from_bytes(&r_bytes).ok_or(EllipticCurveError::InvalidKey)?;

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s = Scalar::from_canonical_bytes(&s_bytes).ok_or(EllipticCurveError::Unspecified)?;

    let k = hash_to_scalar(&[&r_bytes, public_key, message]);

    let lhs = scalar_mul_base(&s).mul_by_cofactor();
    let rhs = r.add(&scalar_mul(&a, &k)).mul_by_cofactor();

    if lhs.to_bytes() == rhs.to_bytes() {
        Ok(())
    } else {
        Err(EllipticCurveError::Unspecified)
    }
}

pub fn is_valid_public_key(public_key: &[u8; PUBLIC_KEY_SIZE]) -> bool {
    EdwardsPoint::from_bytes(public_key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestVector {
        seed: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    fn decode_hex<const N: usize>(hex_bytes: &str) -> [u8; N] {
        let bytes = hex::decode(hex_bytes).unwrap();
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn decode_hex_vec(hex_bytes: &str) -> Vec<u8> {
        hex::decode(hex_bytes).unwrap()
    }

    fn assert_vector(vector: &TestVector) {
        let seed = decode_hex::<32>(vector.seed);
        let public_key = decode_hex::<32>(vector.public_key);
        let signature = decode_hex::<64>(vector.signature);
        let message = decode_hex_vec(vector.message);

        assert_eq!(derive_public_key(&seed), public_key);

        let actual_signature = ed25519_sign(&seed, &message);
        assert_eq!(actual_signature, signature);

        assert!(ed25519_verify(&public_key, &message, &signature).is_ok());
    }

    #[test]
    fn rfc8032_vectors() {
        let vectors = [
            TestVector {
                seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                message: "",
                signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            },
            TestVector {
                seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                message: "72",
                signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            },
            TestVector {
                seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                message: "af82",
                signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            },
        ];

        for vector in &vectors {
            assert_vector(vector);
        }
    }

    #[test]
    fn go_golden_vectors() {
        let data = include_str!("../testdata/ed25519/sign.input");

        for line in data.lines() {
            let mut parts = line.split(':');
            let private_and_public = parts.next().unwrap();
            let public_key = parts.next().unwrap();
            let message = parts.next().unwrap();
            let signature_with_message = parts.next().unwrap();
            assert!(parts.next().is_some());
            assert!(parts.next().is_none());

            let vector = TestVector {
                seed: &private_and_public[..64],
                public_key,
                message,
                signature: &signature_with_message[..128],
            };
            assert_vector(&vector);
        }
    }

    #[test]
    fn verify_rejects_tampering_and_non_canonical_s() {
        let seed = decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public_key = derive_public_key(&seed);
        let signature = ed25519_sign(&seed, b"message");

        assert!(ed25519_verify(&public_key, b"message", &signature).is_ok());
        assert!(ed25519_verify(&public_key, b"tampered", &signature).is_err());

        let mut bad_signature = signature;
        bad_signature[0] ^= 0x80;
        assert!(ed25519_verify(&public_key, b"message", &bad_signature).is_err());

        let mut non_canonical_s = signature;
        non_canonical_s[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]);
        assert!(ed25519_verify(&public_key, b"message", &non_canonical_s).is_err());
    }

    #[test]
    fn public_key_validation_rejects_invalid_encodings() {
        let valid = decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(is_valid_public_key(&valid));

        let mut invalid = [0xffu8; 32];
        assert!(!is_valid_public_key(&invalid));

        invalid = valid;
        invalid[31] |= 0x80;
        invalid[..31].fill(0);
        assert!(!is_valid_public_key(&invalid));
    }

    /// Test vectors from https://github.com/C2SP/CCTV/tree/main/ed25519
    ///
    /// Our implementation follows RFC 8032 with cofactored verification:
    /// - Rejects non-canonical point encodings (y >= p) for both A and R
    /// - Rejects non-canonical s (s >= L)
    /// - Uses cofactored equation [8][S]B = [8]R + [8][k]A
    ///
    /// Therefore:
    /// - Vectors with `non_canonical_A` or `non_canonical_R` → must REJECT
    /// - All other vectors (including `low_order_residue`) → must ACCEPT
    #[test]
    fn cctv_ed25519_vectors() {
        let data = include_str!("../testdata/ed25519/cctv_vectors.txt");

        for line in data.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            assert_eq!(parts.len(), 5, "malformed line: {line}");
            let number = parts[0];
            let key_hex = parts[1];
            let sig_hex = parts[2];
            let msg_hex = parts[3];
            let flags_str = parts[4];

            let flags: Vec<&str> = if flags_str.is_empty() {
                vec![]
            } else {
                flags_str.split(',').collect()
            };

            let has_non_canonical_a = flags.contains(&"non_canonical_A");
            let has_non_canonical_r = flags.contains(&"non_canonical_R");
            let should_reject = has_non_canonical_a || has_non_canonical_r;

            let public_key = decode_hex::<32>(key_hex);
            let signature = decode_hex::<64>(sig_hex);
            let message = decode_hex_vec(msg_hex);

            let result = ed25519_verify(&public_key, &message, &signature);

            if should_reject {
                assert!(
                    result.is_err(),
                    "vector #{number} should be rejected (flags: {flags_str}) but was accepted",
                );
            } else {
                assert!(
                    result.is_ok(),
                    "vector #{number} should be accepted (flags: {flags_str}) but was rejected",
                );
            }
        }
    }

    /// Additional RFC 8032 test vectors (the longer messages from Section 7.1)
    #[test]
    fn rfc8032_extended_vectors() {
        // SHA(abc) test vector
        let vectors = [TestVector {
            seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            public_key: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        }];
        for vector in &vectors {
            assert_vector(vector);
        }
    }

    /// Wycheproof-style edge case tests
    #[test]
    fn verify_rejects_all_zero_signature() {
        let public_key = decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = [0u8; 64];
        // All-zero signature has R = identity (valid) and s = 0 (valid),
        // but the equation [8][0]B = [8]R + [8][k]A won't hold for arbitrary keys
        let result = ed25519_verify(&public_key, b"test", &signature);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_s_equals_l() {
        // s = L (the group order) should be rejected as non-canonical
        let seed = decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public_key = derive_public_key(&seed);
        let signature = ed25519_sign(&seed, b"test");

        let mut bad_sig = signature;
        // Set s to exactly L
        bad_sig[32..].copy_from_slice(&[
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]);
        assert!(ed25519_verify(&public_key, b"test", &bad_sig).is_err());
    }

    #[test]
    fn verify_rejects_non_canonical_point_encodings() {
        // Public key with y >= p (non-canonical)
        let non_canonical_key = decode_hex::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let signature = [0u8; 64]; // dummy
        assert!(ed25519_verify(&non_canonical_key, b"test", &signature).is_err());

        // Valid public key but R in signature with y >= p
        let seed = decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public_key = derive_public_key(&seed);
        let mut bad_sig = ed25519_sign(&seed, b"test");
        // Set R to a non-canonical encoding (y = p, which is >= p)
        bad_sig[..32].copy_from_slice(&[
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ]);
        assert!(ed25519_verify(&public_key, b"test", &bad_sig).is_err());
    }

    #[test]
    fn sign_verify_roundtrip_various_lengths() {
        let seed = decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public_key = derive_public_key(&seed);

        // Test various message lengths including edge cases
        for len in [0, 1, 2, 16, 32, 64, 128, 255, 256, 1024] {
            let message: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            let signature = ed25519_sign(&seed, &message);
            assert!(
                ed25519_verify(&public_key, &message, &signature).is_ok(),
                "roundtrip failed for message length {len}"
            );
        }
    }
}
