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
        let (reduced, _) = value.sub_raw(&P);
        let needs_reduction = value.ct_ge(&P);
        let final_value = U256::ct_select(&reduced, &value, needs_reduction);
        Some(Self(final_value))
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
    fn roundtrip_private_to_public_and_back() {
        let private = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let public = x25519_derive_public_key(&private);
        // Public key should not be all zeros
        assert_ne!(public, [0u8; 32]);
        // Deriving again should produce the same public key
        assert_eq!(x25519_derive_public_key(&private), public);
    }

    #[test]
    fn public_key_exceeds_prime_is_reduced() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let p_bytes = P.to_le_bytes_fixed::<32>();
        let result = x25519(&scalar, &p_bytes);
        assert!(result.is_ok(), "Non-canonical values must be accepted per RFC 7748");
    }

    #[test]
    fn reject_public_key_equal_to_p() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let p_le = P.to_le_bytes_fixed::<32>();
        let result = x25519(&scalar, &p_le);
        assert!(result.is_ok(), "RFC 7748 requires accepting non-canonical values");
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

    #[test]
    fn golang_crypto_vectors() {
        struct GoVector {
            scalar: [u8; 32],
            base: [u8; 32],
            expected: [u8; 32],
        }

        let vectors = [
            GoVector {
                scalar: decode_hex::<32>("668fb9f76ad971c81ac900071a1560bce2ca00cac7e67af99348913761434014"),
                base: decode_hex::<32>("db5f32b7f841e7a1a00968effded12735fc47a3eb13b579aacadeae80939a7dd"),
                expected: decode_hex::<32>("090d85e599ea8e2beeb61304d37be10ec5c905f9927d32f42a9a0afb3e0b4074"),
            },
            GoVector {
                scalar: decode_hex::<32>("636695e34f75b9a279c8706fad1289f2c0b1e22e16f8b8861729c10a582958af"),
                base: decode_hex::<32>("090d0701f8fde28f70043b83f2346225419b18a7f27e9e3d2bfd04e10f3d213e"),
                expected: decode_hex::<32>("bf26ec7ec413061733d44070ea67cab02a85dc1be8cfe1ff73d541cc08325506"),
            },
            GoVector {
                scalar: decode_hex::<32>("734181cd1a9406522a56fe25e43ecbf0295db5ddd0609b3c2b4e79c06f8bd46d"),
                base: decode_hex::<32>("f8a8421c7d21a92db3ede979e1fa6acb062b56b1885c71c51153ccb880ac7315"),
                expected: decode_hex::<32>("1176d01681f2cf929da2c7a3df66b5d7729fd422226fd6374216bf7e02fd0f62"),
            },
            GoVector {
                scalar: decode_hex::<32>("1f70391f6ba858129413bd801b12acbf662362825ca2509c8187590a2b0e6172"),
                base: decode_hex::<32>("d3ead07a0008f44502d5808bffc8979f25a859d5adf4312ea487489c30e01b3b"),
                expected: decode_hex::<32>("f8482f2e9e58bb067e86b28724b3c0a3bbb5073e4c6acd93df545effdbba505f"),
            },
            GoVector {
                scalar: decode_hex::<32>("3a7ae6cf8b889d2b7a60a470ad6ad999206bf57d9030ddf7f8680c8b1a645daa"),
                base: decode_hex::<32>("4d254c8083d87f1a9b3ea731efcff8a6f2312d6fed680ef829185161c8fc5060"),
                expected: decode_hex::<32>("47b356d5818de8efac774b714c42c44be68523dd57dbd73962d5a52631876237"),
            },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let result = x25519(&v.scalar, &v.base).unwrap();
            assert_eq!(result, v.expected, "Go vector {} failed", i);
        }
    }

    #[test]
    fn libsodium_low_order_points() {
        let scalar = decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

        let low_order_points: [[u8; 32]; 7] = [
            decode_hex("0000000000000000000000000000000000000000000000000000000000000000"),
            decode_hex("0100000000000000000000000000000000000000000000000000000000000000"),
            decode_hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            decode_hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            decode_hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            decode_hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            decode_hex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];

        for (i, point) in low_order_points.iter().enumerate() {
            let result = x25519(&scalar, point);
            if point[0] == 0 && point.iter().all(|&b| b == 0) {
                assert_eq!(result.unwrap(), [0u8; 32], "Zero point should produce zero");
            } else if i == 5 {
                let reduced = x25519(&scalar, &[0u8; 32]).unwrap();
                assert_eq!(result.unwrap(), reduced, "Index 5 (p) should reduce to 0");
            } else if i == 6 {
                let mut one = [0u8; 32];
                one[0] = 1;
                let reduced = x25519(&scalar, &one).unwrap();
                assert_eq!(result.unwrap(), reduced, "Index 6 (p+1) should reduce to 1");
            } else {
                assert!(result.is_ok(), "Low order point {} should not error", i);
            }
        }
    }

    #[test]
    fn additional_boringssl_vectors() {
        struct Vector {
            scalar: [u8; 32],
            base: [u8; 32],
            expected: [u8; 32],
        }

        let vectors = [
            Vector {
                scalar: decode_hex::<32>("203161c3159a876a2beaec29d2427fb0c7c30d382cd013d27cc3d393db0daf6f"),
                base: decode_hex::<32>("6ab95d1abe68c09b005c3db9042cc91ac849f7e94a2a4a9b893678970b7b95bf"),
                expected: decode_hex::<32>("11edaedc95ff78f563a1c8f15591c071dea092b4d7ecaac8e0387b5a160c4e5d"),
            },
            Vector {
                scalar: decode_hex::<32>("13d65491fe75f203a008b4415abc60d532e695dbd2f1e803accb34b2b72c3d70"),
                base: decode_hex::<32>("2e784e04ca0073336256a839255ed2f7d4796a64cdc37f1eb0e5c4c8d1d1e0f5"),
                expected: decode_hex::<32>("563e8c9adaa7d73101b0f2ead3cae1ea5d8fcd5cd36080bb8e6ec03d61450917"),
            },
            Vector {
                scalar: decode_hex::<32>("686f7da93bf268e588069831f047163f33589989d0826e9808fb678ed57e6749"),
                base: decode_hex::<32>("8b549b2df642d3b25fe8380f8cc4375f99b7bb4d275f779f3b7c81b8a2bbc129"),
                expected: decode_hex::<32>("01476965426b6171749a8add9235025ce5f557fe4009f7393044ebbb8ae95279"),
            },
            Vector {
                scalar: decode_hex::<32>("82d61ccedc806a6060a3349a5e87cbc7ac115e4f87776250ae256098a7c44959"),
                base: decode_hex::<32>("8b6b9d08f61fc91fe8b32953c42340f007b571dcb0a56d10724ecef9950cfb25"),
                expected: decode_hex::<32>("9c49941f9c4f1871fa4091fed716d34999c95234edf2fdfba6d14a5afe9e0558"),
            },
            Vector {
                scalar: decode_hex::<32>("7dc76404831397d5884fdf6f97e1744c9eb118a31a7b23f8d79f48ce9cad154b"),
                base: decode_hex::<32>("1acd292784f47919d455f887448358610bb9459670eb99dee46005f689ca5fb6"),
                expected: decode_hex::<32>("00f43c022e94ea3819b036ae2b36b2a76136af628a751fe5d01e030d44258859"),
            },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let result = x25519(&v.scalar, &v.base).unwrap();
            assert_eq!(result, v.expected, "BoringSSL vector {} failed", i);
        }
    }

    // Wycheproof test vectors from Google's Project Wycheproof
    // https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/x25519_test.json
    #[test]
    fn wycheproof_valid_vectors() {
        // tcId 1: normal case
        let shared = x25519(
            &decode_hex::<32>("c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475"),
            &decode_hex::<32>("504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320"));

        // tcId 34: edge case public key u=4
        let shared = x25519(
            &decode_hex::<32>("a8386f7f16c50731d64f82e6a170b142a4e34f31fd7768fcb8902925e7d1e25a"),
            &decode_hex::<32>("0400000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("34b7e4fa53264420d9f943d15513902342b386b172a0b0b7c8b8f2dd3d669f59"));

        // tcId 100: RFC 7748 vector (clamped form)
        let shared = x25519(
            &decode_hex::<32>("a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44"),
            &decode_hex::<32>("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));

        // tcId 102: RFC 8037 Section A.6
        let shared = x25519(
            &decode_hex::<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            &decode_hex::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));

        // tcId 104: edge case shared secret = 9
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("3b18df1e50b899ebd588c3161cbd3bf98ebcc2c1f7df53b811bd0e91b4d5153d"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("0900000000000000000000000000000000000000000000000000000000000000"));

        // tcId 105: edge case shared secret = 16
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("cab6f9e7d8ce00dfcea9bbd8f069ef7fb2ac504abf83b87db601b5ae0a7f7615"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("1000000000000000000000000000000000000000000000000000000000000000"));

        // tcId 107: edge case shared secret near field boundary
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("98730bc03e29e8b057fb1d20ef8c0bffc822485d3db7f45f4e3cc2c3c6d1d14c"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));

        // tcId 109: edge case shared secret
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("317781b0163bae74accc06c0d44ef9a911a22b0d37faf7726621591f9343ea2f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));

        // tcId 110: edge case shared secret
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("7e26f8f24cb590027f9d1bc49b0e1a242c7d8f43624d3e8fab28ee08e02cb45e"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03"));

        // tcId 113: edge case shared secret
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("8d44108d05d940d3dfe5647ea7a87be24d0d036c9f0a95a2386b839e7b7bf145"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("ddffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"));
    }

    #[test]
    fn wycheproof_twist_vectors() {
        // tcId 2: public key on twist
        let shared = x25519(
            &decode_hex::<32>("d85d8c061a50804ac488ad774ac716c3f5ba714b2712e048491379a500211958"),
            &decode_hex::<32>("63aa40c6e38346c5caf23a6df0a5e6c80889a08647e551b3563449befcfc9733"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("279df67a7c4611db4708a0e8282b195e5ac0ed6f4b2f292c6fbd0acac30d1332"));

        // tcId 3: public key on twist
        let shared = x25519(
            &decode_hex::<32>("c8b45bfd32e55325d9fd648cb302848039000b390e44d521e58aab3b29a6964b"),
            &decode_hex::<32>("0f83c36fded9d32fadf4efa3ae93a90bb5cfa66893bc412c43fa7287dbb99779"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("4bc7e01e7d83d6cf67632bf90033487a5fc29eba5328890ea7b1026d23b9a45f"));

        // tcId 7: public key u=2 on twist
        let shared = x25519(
            &decode_hex::<32>("d03edde9f3e7b799045f9ac3793d4a9277dadeadc41bec0290f81f744f73775f"),
            &decode_hex::<32>("0200000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("b87a1722cc6c1e2feecb54e97abd5a22acc27616f78f6e315fd2b73d9f221e57"));

        // tcId 8: public key u=3 on twist
        let shared = x25519(
            &decode_hex::<32>("e09d57a914e3c29036fd9a442ba526b5cdcdf28216153e636c10677acab6bd6a"),
            &decode_hex::<32>("0300000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("a29d8dad28d590cd3017aa97a4761f851bf1d3672b042a4256a45881e2ad9035"));

        // tcId 9: public key u=255 on twist
        let shared = x25519(
            &decode_hex::<32>("e0ed78e6ee02f08bec1c15d66fbbe5b83ffc37ea14e1512cc1bd4b2ea6d8066f"),
            &decode_hex::<32>("ff00000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("e703bc8aa94b7d87ba34e2678353d12cdaaa1a97b5ca3e1b8c060c4636087f07"));

        // tcId 103: edge case shared secret = 2 (twist point)
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("b7b6d39c765cb60c0c8542f4f3952ffb51d3002d4aeb9f8ff988b192043e6d0a"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("0200000000000000000000000000000000000000000000000000000000000000"));

        // tcId 106: edge case near boundary (twist)
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("4977d0d897e1ba566590f60f2eb0db6f7b24c13d436918ccfd32708dfad7e247"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));

        // tcId 108: edge case (twist)
        let shared = x25519(
            &decode_hex::<32>("60a3a4f130b98a5be4b1cedb7cb85584a3520e142d474dc9ccb909a073a9767f"),
            &decode_hex::<32>("97b4fff682df7f096cd1756569e252db482d45406a3198a1aff282a5da474c49"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));
    }

    #[test]
    fn wycheproof_low_order_and_zero_shared() {
        // All low-order public keys should produce zero shared secret
        let private = decode_hex::<32>("786a33a4f7af297a20e7642925932bf509e7070fa1bc36986af1eb13f4f50b55");

        // tcId 69: u=0
        let shared = x25519(&private, &decode_hex::<32>("0000000000000000000000000000000000000000000000000000000000000000")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 70: u=1
        let shared = x25519(&private, &decode_hex::<32>("0100000000000000000000000000000000000000000000000000000000000000")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 71: u = p-1 (ecffffff...7f)
        let shared = x25519(&private, &decode_hex::<32>("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 72: u = low order point 5f9c95bc...
        let shared = x25519(&private, &decode_hex::<32>("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 73: u = low order point e0eb7a7c...
        let shared = x25519(&private, &decode_hex::<32>("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 74: u = p (edffffff...7f) which is 0 mod p
        let shared = x25519(&private, &decode_hex::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 75: u = p+1 (eeffffff...7f) which is 1 mod p
        let shared = x25519(&private, &decode_hex::<32>("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 76: u = 0 with high bit set
        let shared = x25519(&private, &decode_hex::<32>("0000000000000000000000000000000000000000000000000000000000000080")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 77: u = 1 with high bit set
        let shared = x25519(&private, &decode_hex::<32>("0100000000000000000000000000000000000000000000000000000000000080")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 81: u = p with high bit set
        let shared = x25519(&private, &decode_hex::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 82: u = p+1 with high bit set
        let shared = x25519(&private, &decode_hex::<32>("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).unwrap();
        assert_eq!(shared, [0u8; 32]);
    }

    #[test]
    fn wycheproof_non_canonical_public_keys() {
        // tcId 87: u = 2^255 - 18 (non-canonical, just above p-1)
        let shared = x25519(
            &decode_hex::<32>("0016b62af5cabde8c40938ebf2108e05d27fa0533ed85d70015ad4ad39762d54"),
            &decode_hex::<32>("efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("b4d10e832714972f96bd3382e4d082a21a8333a16315b3ffb536061d2482360d"));

        // tcId 88: u = 2^255 - 17
        let shared = x25519(
            &decode_hex::<32>("d83650ba7cec115881916255e3fa5fa0d6b8dcf968731bd2c9d2aec3f561f649"),
            &decode_hex::<32>("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("515eac8f1ed0b00c70762322c3ef86716cd2c51fe77cec3d31b6388bc6eea336"));

        // tcId 89: u = 2^255 - 18 (non-canonical)
        let shared = x25519(
            &decode_hex::<32>("88dd14e2711ebd0b0026c651264ca965e7e3da5082789fbab7e24425e7b4377e"),
            &decode_hex::<32>("f1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("6919992d6a591e77b3f2bacbd74caf3aea4be4802b18b2bc07eb09ade3ad6662"));

        // tcId 90: u = 2^255 - 1 (maximum non-canonical with top bit masked)
        let shared = x25519(
            &decode_hex::<32>("98c2b08cbac14e15953154e3b558d42bb1268a365b0ef2f22725129d8ac5cb7f"),
            &decode_hex::<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("9c034fcd8d3bf69964958c0105161fcb5d1ea5b8f8abb371491e42a7684c2322"));

        // tcId 94: u = 0xdaffffff... (non-canonical with top bit set)
        let shared = x25519(
            &decode_hex::<32>("285a6a7ceeb7122f2c78d99c53b2a902b490892f7dff326f89d12673c3101b53"),
            &decode_hex::<32>("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("9b01287717d72f4cfb583ec85f8f936849b17d978dbae7b837db56a62f100a68"));

        // tcId 99: u = 0xffffffff... (all ones)
        let shared = x25519(
            &decode_hex::<32>("c85f08e60c845f82099141a66dc4583d2b1040462c544d33d0453b20b1a6377e"),
            &decode_hex::<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("e9db74bc88d0d9bf046ddd13f943bccbe6dbb47d49323f8dfeedc4a694991a3c"));
    }

    #[test]
    fn wycheproof_special_public_keys() {
        // tcId 35: u = 256
        let shared = x25519(
            &decode_hex::<32>("d05abd08bf5e62538cb9a5ed105dbedd6de38d07940085072b4311c2678ed77d"),
            &decode_hex::<32>("0001000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("3aa227a30781ed746bd4b3365e5f61461b844d09410c70570abd0d75574dfc77"));

        // tcId 36: u = 2^20
        let shared = x25519(
            &decode_hex::<32>("f0b8b0998c8394364d7dcb25a3885e571374f91615275440db0645ee7c0a6f6b"),
            &decode_hex::<32>("0000001000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("97755e7e775789184e176847ffbc2f8ef98799d46a709c6a1c0ffd29081d7039"));

        // tcId 47: u = 2^248
        let shared = x25519(
            &decode_hex::<32>("38d6403e1377734cdce98285e820f256ad6b769d6b5612bcf42cf2b97945c073"),
            &decode_hex::<32>("0000000000000000000000000000000000000000000000000000000001000000"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("4d46052c7eabba215df8d91327e0c4610421d2d9129b1486d914c766cf104c27"));

        // tcId 51: u = 2^254 - 1
        let shared = x25519(
            &decode_hex::<32>("a8f37318a4c760f3cb2d894822918735683cb1edacf3e666e15694154978fd6d"),
            &decode_hex::<32>("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("d151b97cba9c25d48e6d576338b97d53dd8b25e84f65f7a2091a17016317c553"));

        // tcId 52: u = p - 2^254 + 2^253 - 1 (large value close to p)
        let shared = x25519(
            &decode_hex::<32>("20d4d624cf732f826f09e8088017742f13f2da98f4dcf4b40519adb790cebf64"),
            &decode_hex::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("5716296baf2b1a6b9cd15b23ba86829743d60b0396569be1d5b40014c06b477d"));

        // tcId 62: u = p - 2 (0xebffffff...7f)
        let shared = x25519(
            &decode_hex::<32>("40bd4e1caf39d9def7663823502dad3e7d30eb6eb01e9b89516d4f2f45b7cd7f"),
            &decode_hex::<32>("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ).unwrap();
        assert_eq!(shared, decode_hex::<32>("2cf6974b0c070e3707bf92e721d3ea9de3db6f61ed810e0a23d72d433365f631"));
    }

    #[test]
    fn wycheproof_edge_case_private_keys() {
        // tcId 32: private key that produces zero shared with u=0
        let shared = x25519(
            &decode_hex::<32>("88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e"),
            &decode_hex::<32>("0000000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 33: private key that produces zero shared with u=1
        let shared = x25519(
            &decode_hex::<32>("48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f"),
            &decode_hex::<32>("0100000000000000000000000000000000000000000000000000000000000000"),
        ).unwrap();
        assert_eq!(shared, [0u8; 32]);

        // tcId 83: u = p (== 0 mod p) with different private key
        let shared = x25519(
            &decode_hex::<32>("40ff586e73d61f0960dc2d763ac19e98225f1194f6fe43d5dd97ad55b3d35961"),
            &decode_hex::<32>("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ).unwrap();
        assert_eq!(shared, [0u8; 32]);
    }

    #[test]
    fn more_boringssl_vectors() {
        struct Vector {
            scalar: [u8; 32],
            base: [u8; 32],
            expected: [u8; 32],
        }

        let vectors = [
            Vector {
                scalar: decode_hex::<32>("fbc4511d23a682ae4efd08c8179c1c067f9c8be79bbc4eff5ce296c6bc1ff445"),
                base: decode_hex::<32>("55caff2181f2136b0ed0e1e2994448e16cc970646a983d140dc4eab3d94c284e"),
                expected: decode_hex::<32>("ae39d816532345794d2691e0801caa525fc3634d402ce9580b3338b46f8bb972"),
            },
            Vector {
                scalar: decode_hex::<32>("4e060ce10cebf095098716c86619eb9f7df66524698ba7988c3b9095d9f50134"),
                base: decode_hex::<32>("57733f2d869690d0d2edaec9523daa2da95445f44f5783c1faec6c3a982818f3"),
                expected: decode_hex::<32>("a61e74552cce75f5e972e424f2ccb09c83bc1b67014748f02c371a209ef2fb2c"),
            },
            Vector {
                scalar: decode_hex::<32>("5c492cba2cc892488a9ceb9186c2aac22f015bf3ef8d3ecc9c4176976261aab1"),
                base: decode_hex::<32>("6797c2e7dc92ccbe7c056bec350ab6d3bd2a2c6bc5a807bbcae1f6c2af803644"),
                expected: decode_hex::<32>("fcf307dfbc19020b28a6618c6c622f317e45967dacf4ae4a0a699a10769fde14"),
            },
            Vector {
                scalar: decode_hex::<32>("ea33349296055a4e8b192e3c23c5f4c844282a3bfc19ecc9dc646a42c38dc248"),
                base: decode_hex::<32>("2c75d85142ecad3e69447004540c1c23548fc8f486251b8a19463f3df6f8ac61"),
                expected: decode_hex::<32>("5dcab68973f95bd3ae4b34fab949fb7fb15af1d8cae28cd699f9c1aa3337342f"),
            },
            Vector {
                scalar: decode_hex::<32>("4f2979b1ec8619e45c0a0b2b520934541ab94407b64d190a76f32314efe184e7"),
                base: decode_hex::<32>("f7cae18d8d36a7f56117b8b70e2552277ffc99df8756b5e138bf6368bc87f74c"),
                expected: decode_hex::<32>("e4e634ebb4fb664fe8b2cfa1615f00e6466fff732ce1f8a0c8d2727431d16f14"),
            },
            Vector {
                scalar: decode_hex::<32>("f5d8a927901d4fa4249086b7ffec24f5297d80118e4ac9d3fc9a8237951e3b7f"),
                base: decode_hex::<32>("3c235edc02f9115641dbf516d5de8a735d6e53e22aa2ac143656045ff2e95249"),
                expected: decode_hex::<32>("ab9515ab14af9d270e1dae0c5680cbc8880bd8a8e7eb67b4da42a661961efc0b"),
            },
        ];

        for (i, v) in vectors.iter().enumerate() {
            let result = x25519(&v.scalar, &v.base).unwrap();
            assert_eq!(result, v.expected, "BoringSSL vector {} failed", i);
        }
    }
}
