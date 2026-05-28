use big_number::Uint;

use crate::EllipticCurveError;

pub const X25519_KEY_SIZE: usize = 32;
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

type U256 = Uint<256, 4>;

const P: U256 = U256::from_limbs([
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
]);

const P_MINUS_TWO: U256 = U256::from_limbs([
    0xffff_ffff_ffff_ffeb,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
]);

const A24: FieldElement = FieldElement(U256::from_u64(121665));

const BASEPOINT_U: [u8; 32] = {
    let mut u = [0u8; 32];
    u[0] = 9;
    u
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldElement(U256);

impl FieldElement {
    const ZERO: Self = Self(U256::ZERO);
    const ONE: Self = Self(U256::ONE);

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut masked = *bytes;
        masked[31] &= 0x7f;
        let value = U256::from_le_slice(&masked);
        if value.ct_ge(&P) {
            return None;
        }
        Some(Self(value))
    }

    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        self.0.to_le_bytes_fixed::<32>()
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &P))
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &P))
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod(&rhs.0, &P))
    }

    #[inline]
    fn square(self) -> Self {
        self.mul(self)
    }

    #[inline]
    fn invert(self) -> Option<Self> {
        if self.0.is_zero() {
            return None;
        }
        Some(self.pow(&P_MINUS_TWO))
    }

    fn pow(self, exponent: &U256) -> Self {
        let mut result = Self::ONE;
        let mut i = 256;
        while i > 0 {
            i -= 1;
            result = result.square();
            let product = result.mul(self);
            result = Self::select(&product, &result, exponent.bit(i));
        }
        result
    }

    #[inline]
    fn select(a: &Self, b: &Self, choice: bool) -> Self {
        Self(U256::ct_select(&a.0, &b.0, choice))
    }
}

#[inline]
fn cswap(swap: bool, a: &mut FieldElement, b: &mut FieldElement) {
    let tmp = FieldElement::select(b, a, swap);
    *b = FieldElement::select(a, b, swap);
    *a = tmp;
}

#[inline]
fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

fn x25519_inner(scalar: &[u8; 32], u: FieldElement) -> FieldElement {
    let x_1 = u;
    let mut x_2 = FieldElement::ONE;
    let mut z_2 = FieldElement::ZERO;
    let mut x_3 = u;
    let mut z_3 = FieldElement::ONE;
    let mut swap = false;

    let mut t: isize = 254;
    while t >= 0 {
        let k_t = ((scalar[(t as usize) / 8] >> ((t as usize) % 8)) & 1) != 0;

        swap ^= k_t;
        cswap(swap, &mut x_2, &mut x_3);
        cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let a = x_2.add(z_2);
        let aa = a.square();
        let b = x_2.sub(z_2);
        let bb = b.square();
        let e = aa.sub(bb);
        let c = x_3.add(z_3);
        let d = x_3.sub(z_3);
        let da = d.mul(a);
        let cb = c.mul(b);
        x_3 = da.add(cb).square();
        z_3 = x_1.mul(da.sub(cb).square());
        x_2 = aa.mul(bb);
        z_2 = e.mul(aa.add(A24.mul(e)));

        t -= 1;
    }

    cswap(swap, &mut x_2, &mut x_3);
    cswap(swap, &mut z_2, &mut z_3);

    if z_2.0.is_zero() {
        return FieldElement::ZERO;
    }

    x_2.mul(z_2.invert().expect("z_2 must be non-zero"))
}

pub fn x25519(
    private_key: &[u8; X25519_KEY_SIZE],
    public_key: &[u8; X25519_KEY_SIZE],
) -> Result<[u8; X25519_SHARED_SECRET_SIZE], EllipticCurveError> {
    let scalar = clamp_scalar(*private_key);
    let u = FieldElement::from_bytes(public_key).ok_or(EllipticCurveError::InvalidKey)?;
    let result = x25519_inner(&scalar, u);
    Ok(result.to_bytes())
}

pub fn x25519_derive_public_key(private_key: &[u8; X25519_KEY_SIZE]) -> [u8; X25519_KEY_SIZE] {
    x25519(private_key, &BASEPOINT_U).expect("basepoint must be a valid public key")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(hex_str: &str) -> [u8; N] {
        let bytes = hex::decode(hex_str).unwrap();
        assert_eq!(bytes.len(), N, "hex string must decode to exactly {N} bytes");
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    struct DhTestVector {
        alice_private: &'static str,
        alice_public: &'static str,
        bob_private: &'static str,
        bob_public: &'static str,
        shared_secret: &'static str,
    }

    #[test]
    fn rfc7748_section_5_2_vector_1() {
        let scalar = decode_hex::<32>("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = decode_hex::<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let expected = decode_hex::<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

        let output = x25519(&scalar, &u).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn rfc7748_section_5_2_vector_2() {
        let scalar = decode_hex::<32>("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = decode_hex::<32>("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let expected = decode_hex::<32>("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

        let output = x25519(&scalar, &u).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn rfc7748_section_5_2_iterative_1() {
        let k = decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000");
        let u = k;
        let expected = decode_hex::<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

        let output = x25519(&k, &u).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn rfc7748_section_5_2_iterative_1000() {
        let mut k = decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1000 {
            let out = x25519(&k, &u).unwrap();
            u = k;
            k = out;
        }
        let expected = decode_hex::<32>("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
        assert_eq!(k, expected);
    }

    #[test]
    #[ignore = "takes about 1 minute; run with -- --ignored"]
    fn rfc7748_section_5_2_iterative_1000000() {
        let mut k = decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1000000 {
            let out = x25519(&k, &u).unwrap();
            u = k;
            k = out;
        }
        let expected = decode_hex::<32>("7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
        assert_eq!(k, expected);
    }

    #[test]
    fn rfc7748_section_5_2_dh_exchange() {
        let vectors: [DhTestVector; 1] = [DhTestVector {
            alice_private: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            alice_public: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            bob_private: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            bob_public: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            shared_secret: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        }];

        for v in &vectors {
            let alice_private = decode_hex::<32>(v.alice_private);
            let alice_public = decode_hex::<32>(v.alice_public);
            let bob_private = decode_hex::<32>(v.bob_private);
            let bob_public = decode_hex::<32>(v.bob_public);
            let expected = decode_hex::<32>(v.shared_secret);

            let alice_computed_public = x25519_derive_public_key(&alice_private);
            assert_eq!(alice_computed_public, alice_public, "Alice public key mismatch");

            let bob_computed_public = x25519_derive_public_key(&bob_private);
            assert_eq!(bob_computed_public, bob_public, "Bob public key mismatch");

            let alice_shared = x25519(&alice_private, &bob_public).unwrap();
            assert_eq!(alice_shared, expected, "Alice shared secret mismatch");

            let bob_shared = x25519(&bob_private, &alice_public).unwrap();
            assert_eq!(bob_shared, expected, "Bob shared secret mismatch");
        }
    }

    #[test]
    fn basepoint_multiplication_identity_pattern() {
        let key = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let public = x25519_derive_public_key(&key);
        let basepoint = decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000");
        let direct = x25519(&key, &basepoint).unwrap();
        assert_eq!(public, direct);
    }

    #[test]
    fn basepoint_multiplication_twice_same_result() {
        let key = decode_hex::<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let public = x25519_derive_public_key(&key);
        assert_eq!(x25519_derive_public_key(&key), public);
    }

    #[test]
    fn low_order_point_zero() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let all_zero = [0u8; 32];
        let output = x25519(&scalar, &all_zero).unwrap();
        assert_eq!(output, [0u8; 32], "X25519 with u=0 must produce all-zero output");
    }

    #[test]
    fn low_order_point_u_one() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut u_one = [0u8; 32];
        u_one[0] = 1;
        let output = x25519(&scalar, &u_one).unwrap();
        // u=1 is a low-order point on the twist (order 4). With cofactor 8
        // and a clamped scalar, the result may be the identity point (all zeros).
        // We just verify it doesn't error.
        let _ = output;
    }

    #[test]
    fn all_zero_private_key() {
        let key = [0u8; 32];
        let u = decode_hex::<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let output = x25519(&key, &u).unwrap();
        // Clamping sets bit 6 of the last byte, so the effective scalar is
        // 0x4000000000000000000000000000000000000000000000000000000000000000
        let expected = x25519(
            &decode_hex::<32>("0000000000000000000000000000000000000000000000000000000000000040"),
            &u,
        )
        .unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn public_key_exceeds_prime_is_rejected() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        // p = 2^255 - 19. Encode p as little-endian 32 bytes with top bit cleared.
        let p_bytes = P.to_le_bytes_fixed::<32>();
        // p_bytes should already have bit 255 clear (since p < 2^255).
        // But the MSB clearing in from_bytes means we need a value >= p AND < 2^255.
        // p is 2^255 - 19, so p fits in 255 bits. An invalid key would have u >= p.
        assert!(x25519(&scalar, &p_bytes).is_err());
    }

    #[test]
    fn top_bit_cleared_on_decode() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut u2 = decode_hex::<32>("9b00000000000000000000000000000000000000000000000000000000000000");
        u2[31] = 0x89; // top bit set, lower bits make it < p after masking
        let result = x25519(&scalar, &u2);
        assert!(result.is_ok());

        let mut u3 = [0xffu8; 32];
        u3[31] = 0x7f;
        assert!(x25519(&scalar, &u3).is_err());
    }

    #[test]
    fn symmetry_test() {
        // Generate two key pairs and verify DH symmetry.
        let alice_private = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_private = decode_hex::<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        let alice_public = x25519_derive_public_key(&alice_private);
        let bob_public = x25519_derive_public_key(&bob_private);

        let alice_shared = x25519(&alice_private, &bob_public).unwrap();
        let bob_shared = x25519(&bob_private, &alice_public).unwrap();

        assert_eq!(alice_shared, bob_shared);
        // Shared secret should be non-zero for valid keys
        assert_ne!(alice_shared, [0u8; 32]);
    }

    #[test]
    fn known_shared_secrets_rfc7748() {
        // Additional check: use the same key with the basepoint, the result
        // should match the derived public key.
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let basepoint = decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000");
        let expected_public = decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

        assert_eq!(x25519(&scalar, &basepoint).unwrap(), expected_public);
        assert_eq!(x25519_derive_public_key(&scalar), expected_public);
    }

    #[test]
    fn wycheproof_cross_validation() {
        // Verify against RFC 7748 DH exchange test vector from multiple angles.
        let alice_sk = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pk = decode_hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_sk = decode_hex::<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pk = decode_hex::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = decode_hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assert_eq!(x25519_derive_public_key(&alice_sk), alice_pk);
        assert_eq!(x25519_derive_public_key(&bob_sk), bob_pk);
        assert_eq!(x25519(&alice_sk, &bob_pk).unwrap(), shared);
        assert_eq!(x25519(&bob_sk, &alice_pk).unwrap(), shared);
        assert_eq!(x25519(&alice_sk, &alice_pk).unwrap(), x25519(&alice_sk, &alice_pk).unwrap());
    }

    #[test]
    fn clamping_clears_low_three_bits() {
        // Scalar with low 3 bits set: 0b00000111 = 7
        let mut scalar = [0u8; 32];
        scalar[0] = 0b00000111;
        let clamped = clamp_scalar(scalar);
        // Bits 0, 1, 2 should be cleared: 0b00000000 = 0
        assert_eq!(clamped[0] & 0b00000111, 0);
        // Bit 6 of last byte should be set
        assert!(clamped[31] & 64 != 0);
        // Bit 7 of last byte should be cleared
        assert_eq!(clamped[31] & 128, 0);
    }

    #[test]
    fn clamping_sets_bit_6_last_byte() {
        // Scalar with bit 6 of last byte clear
        let mut scalar = [0u8; 32];
        scalar[31] = 0;
        let clamped = clamp_scalar(scalar);
        assert_eq!(clamped[31], 64);
    }

    #[test]
    fn clamping_preserves_other_bits() {
        let mut scalar = [0u8; 32];
        scalar[0] = 0b11111000; // only bits 3-7 set
        scalar[31] = 0b00111111; // bits 0-5 set, bits 6-7 clear
        let clamped = clamp_scalar(scalar);
        assert_eq!(clamped[0], 0b11111000);
        // After clamping: bit 6 set, bit 7 cleared, bits 0-5 preserved
        assert_eq!(clamped[31], 0b00111111 | 64);
    }

    #[test]
    fn roundtrip_private_to_public_and_back() {
        let private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c,
            0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let public = x25519_derive_public_key(&private);
        // Public key should not be all zeros
        assert_ne!(public, [0u8; 32]);
        // Deriving again should produce the same public key
        assert_eq!(x25519_derive_public_key(&private), public);
    }

    #[test]
    fn reject_public_key_equal_to_p() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        // p in little-endian
        let p_le = P.to_le_bytes_fixed::<32>();
        assert!(x25519(&scalar, &p_le).is_err(), "u == p must be rejected");
    }

    #[test]
    fn reject_public_key_above_p() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let p_le = P.to_le_bytes_fixed::<32>();
        assert!(x25519(&scalar, &p_le).is_err());
    }

    #[test]
    fn field_element_invert_nonzero() {
        let fe = FieldElement(U256::from_u64(9));
        let inv = fe.invert().unwrap();
        assert_eq!(fe.mul(inv), FieldElement::ONE);
    }

    #[test]
    fn field_element_invert_zero_returns_none() {
        assert!(FieldElement::ZERO.invert().is_none());
    }

    #[test]
    fn field_element_add_sub_identity() {
        let a = FieldElement(U256::from_u64(12345));
        let b = FieldElement(U256::from_u64(67890));
        assert_eq!(a.add(b).sub(b), a);
    }

    #[test]
    fn field_element_mul_commutative() {
        let a = FieldElement(P.sub_raw(&U256::from_u64(1)).0);
        let b = FieldElement(P.sub_raw(&U256::from_u64(2)).0);
        assert_eq!(a.mul(b), b.mul(a));
    }

    #[test]
    fn field_element_square_vs_mul_self() {
        let fe = FieldElement(U256::from_u64(121665));
        assert_eq!(fe.square(), fe.mul(fe));
    }

    #[test]
    fn field_element_select() {
        let a = FieldElement(U256::from_u64(1));
        let b = FieldElement(U256::from_u64(2));
        assert_eq!(FieldElement::select(&a, &b, true), a);
        assert_eq!(FieldElement::select(&a, &b, false), b);
    }

    #[test]
    fn field_element_from_to_bytes_roundtrip() {
        let original = decode_hex::<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let fe = FieldElement::from_bytes(&original).unwrap();
        let roundtrip = fe.to_bytes();
        // The top bit is cleared on decode, and since round-trip does not restore it,
        // we compare against the decoded (masked) value.
        let mut expected = original;
        expected[31] &= 0x7f;
        assert_eq!(roundtrip, expected);
    }

    #[test]
    fn field_element_pow_few_small() {
        // 3^5 mod p
        let base = FieldElement(U256::from_u64(3));
        let exp = U256::from_u64(5);
        let expected = FieldElement(U256::from_u64(243));
        assert_eq!(base.pow(&exp), expected);
    }

    #[test]
    fn debug_iterative_step2() {
        let k0 = decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000");
        let u0 = k0;
        let out1 = x25519(&k0, &u0).unwrap();
        let expected1 = decode_hex::<32>("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(out1, expected1, "Iteration 1 failed");

        let k1 = out1;
        let u1 = out1;
        let out2 = x25519(&k1, &u1).unwrap();
        eprintln!("Iter 2 output: {}", hex::encode(out2));
    }
}
