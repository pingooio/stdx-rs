use big_number::Uint;

use crate::{EllipticCurveError, Hasher, hmac::Hmac, sha2::Sha256};

pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_COMPRESSED_SIZE: usize = 33;
pub const PUBLIC_KEY_UNCOMPRESSED_SIZE: usize = 65;
pub const SIGNATURE_SIZE: usize = 64;

type U256 = Uint<256, 4>;

const MODULUS_P: U256 = U256::from_limbs([
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);
const MODULUS_N: U256 = U256::from_limbs([
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
]);
const P_MINUS_TWO: U256 = U256::from_limbs([
    0xffff_ffff_ffff_fffd,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
]);
const P_PLUS_ONE_OVER_FOUR: U256 = U256::from_limbs([
    0x0000_0000_0000_0000,
    0x0000_0000_4000_0000,
    0x4000_0000_0000_0000,
    0x3fff_ffff_c000_0000,
]);
const N_MINUS_TWO: U256 = U256::from_limbs([
    0xf3b9_cac2_fc63_254f,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
]);

const CURVE_B: FieldElement = FieldElement(U256::from_limbs([
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
]));
const GENERATOR_X: FieldElement = FieldElement(U256::from_limbs([
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
]));
const GENERATOR_Y: FieldElement = FieldElement(U256::from_limbs([
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
]));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldElement(U256);

impl FieldElement {
    const ZERO: Self = Self(U256::ZERO);
    const ONE: Self = Self(U256::ONE);

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let value = U256::from_be_slice(bytes);
        if value.ct_ge(&MODULUS_P) {
            None
        } else {
            Some(Self(value))
        }
    }

    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes_fixed::<32>()
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
    fn double(self) -> Self {
        Self(self.0.double_mod(&MODULUS_P))
    }

    #[inline]
    fn square(self) -> Self {
        self.mul(self)
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod(&rhs.0, &MODULUS_P))
    }

    #[inline]
    fn triple(self) -> Self {
        self.double().add(self)
    }

    #[inline]
    fn negate(self) -> Self {
        let (diff, _) = MODULUS_P.sub_raw(&self.0);
        Self(U256::ct_select(&U256::ZERO, &diff, self.is_zero()))
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
    fn invert(self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.pow(&P_MINUS_TWO))
        }
    }

    #[inline]
    fn sqrt(self) -> Option<Self> {
        let candidate = self.pow(&P_PLUS_ONE_OVER_FOUR);
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
    const ZERO: Self = Self(U256::ZERO);
    const ONE: Self = Self(U256::ONE);

    #[inline]
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let value = U256::from_be_slice(bytes);
        if value.is_zero() || value.ct_ge(&MODULUS_N) {
            None
        } else {
            Some(Self(value))
        }
    }

    #[inline]
    fn from_hash(hash: &[u8; 32]) -> Self {
        let value = U256::from_be_slice(hash);
        let reduced = if value.ct_ge(&MODULUS_N) {
            value.sub_raw(&MODULUS_N).0
        } else {
            value
        };
        Self(reduced)
    }

    #[inline]
    fn to_bytes(self) -> [u8; 32] {
        self.0.to_be_bytes_fixed::<32>()
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.0.bit(index)
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self(self.0.add_mod(&rhs.0, &MODULUS_N))
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self(self.0.sub_mod(&rhs.0, &MODULUS_N))
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self(self.0.mul_mod(&rhs.0, &MODULUS_N))
    }

    #[inline]
    fn invert(self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(Self(self.scalar_pow(&N_MINUS_TWO)))
        }
    }

    #[inline]
    fn scalar_pow(self, exponent: &U256) -> U256 {
        let mut result = Scalar::ONE;
        let mut i = 256usize;
        while i > 0 {
            i -= 1;
            result = result.mul(result);
            let product = result.mul(self);
            result = Scalar::select(&product, &result, exponent.bit(i));
        }
        result.0
    }

    #[inline]
    fn select(a: &Self, b: &Self, choice: bool) -> Self {
        Self(U256::ct_select(&a.0, &b.0, choice))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AffinePoint {
    x: FieldElement,
    y: FieldElement,
    infinity: bool,
}

impl AffinePoint {
    const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        infinity: true,
    };

    const GENERATOR: Self = Self {
        x: GENERATOR_X,
        y: GENERATOR_Y,
        infinity: false,
    };

    #[inline]
    fn new(x: FieldElement, y: FieldElement) -> Option<Self> {
        let point = Self {
            x,
            y,
            infinity: false,
        };
        if point.is_on_curve() { Some(point) } else { None }
    }

    #[inline]
    fn is_on_curve(&self) -> bool {
        if self.infinity {
            return false;
        }
        let x2 = self.x.square();
        let x3 = x2.mul(self.x);
        let rhs = x3.sub(self.x.triple()).add(CURVE_B);
        self.y.square() == rhs
    }

    #[inline]
    fn to_uncompressed_bytes(&self) -> [u8; PUBLIC_KEY_UNCOMPRESSED_SIZE] {
        let mut out = [0u8; PUBLIC_KEY_UNCOMPRESSED_SIZE];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out[33..65].copy_from_slice(&self.y.to_bytes());
        out
    }

    #[inline]
    fn to_compressed_bytes(&self) -> [u8; PUBLIC_KEY_COMPRESSED_SIZE] {
        let mut out = [0u8; PUBLIC_KEY_COMPRESSED_SIZE];
        out[0] = if self.y.is_odd() { 0x03 } else { 0x02 };
        out[1..33].copy_from_slice(&self.x.to_bytes());
        out
    }

    fn from_sec1_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes.len() {
            PUBLIC_KEY_UNCOMPRESSED_SIZE if bytes[0] == 0x04 => {
                let x = FieldElement::from_bytes(bytes[1..33].try_into().unwrap())?;
                let y = FieldElement::from_bytes(bytes[33..65].try_into().unwrap())?;
                Self::new(x, y)
            }
            PUBLIC_KEY_COMPRESSED_SIZE if bytes[0] == 0x02 || bytes[0] == 0x03 => {
                let x = FieldElement::from_bytes(bytes[1..33].try_into().unwrap())?;
                let rhs = x.square().mul(x).sub(x.triple()).add(CURVE_B);
                let y = rhs.sqrt()?;
                let y_is_odd = y.is_odd();
                let select_neg = y_is_odd != (bytes[0] == 0x03);
                let y = FieldElement::select(&y.negate(), &y, select_neg);
                Self::new(x, y)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProjectivePoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl ProjectivePoint {
    const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    #[inline]
    fn from_affine(point: &AffinePoint) -> Self {
        if point.infinity {
            Self::IDENTITY
        } else {
            Self {
                x: point.x,
                y: point.y,
                z: FieldElement::ONE,
            }
        }
    }

    #[inline]
    fn is_identity(&self) -> bool {
        self.z.is_zero()
    }

    #[inline]
    fn select(a: &Self, b: &Self, choice: bool) -> Self {
        Self {
            x: FieldElement::select(&a.x, &b.x, choice),
            y: FieldElement::select(&a.y, &b.y, choice),
            z: FieldElement::select(&a.z, &b.z, choice),
        }
    }

    #[inline]
    fn to_affine(&self) -> Option<AffinePoint> {
        if self.is_identity() {
            return None;
        }
        let z_inv = self.z.invert()?;
        AffinePoint::new(self.x.mul(z_inv), self.y.mul(z_inv))
    }

    fn add(&self, rhs: &Self) -> Self {
        let xx = self.x.mul(rhs.x);
        let yy = self.y.mul(rhs.y);
        let zz = self.z.mul(rhs.z);
        let xy_pairs = self.x.add(self.y).mul(rhs.x.add(rhs.y)).sub(xx.add(yy));
        let yz_pairs = self.y.add(self.z).mul(rhs.y.add(rhs.z)).sub(yy.add(zz));
        let xz_pairs = self.x.add(self.z).mul(rhs.x.add(rhs.z)).sub(xx.add(zz));

        let bzz_part = xz_pairs.sub(CURVE_B.mul(zz));
        let bzz3_part = bzz_part.triple();
        let yy_m_bzz3 = yy.sub(bzz3_part);
        let yy_p_bzz3 = yy.add(bzz3_part);

        let zz3 = zz.triple();
        let bxz_part = CURVE_B.mul(xz_pairs).sub(zz3.add(xx));
        let bxz3_part = bxz_part.triple();
        let xx3_m_zz3 = xx.triple().sub(zz3);

        Self {
            x: yy_p_bzz3.mul(xy_pairs).sub(yz_pairs.mul(bxz3_part)),
            y: yy_p_bzz3.mul(yy_m_bzz3).add(xx3_m_zz3.mul(bxz3_part)),
            z: yy_m_bzz3.mul(yz_pairs).add(xy_pairs.mul(xx3_m_zz3)),
        }
    }

    fn add_mixed(&self, rhs: &AffinePoint) -> Self {
        if rhs.infinity {
            return *self;
        }

        let xx = self.x.mul(rhs.x);
        let yy = self.y.mul(rhs.y);
        let xy_pairs = self.x.add(self.y).mul(rhs.x.add(rhs.y)).sub(xx.add(yy));
        let yz_pairs = rhs.y.mul(self.z).add(self.y);
        let xz_pairs = rhs.x.mul(self.z).add(self.x);

        let bz_part = xz_pairs.sub(CURVE_B.mul(self.z));
        let bz3_part = bz_part.triple();
        let yy_m_bzz3 = yy.sub(bz3_part);
        let yy_p_bzz3 = yy.add(bz3_part);

        let z3 = self.z.triple();
        let bxz_part = CURVE_B.mul(xz_pairs).sub(z3.add(xx));
        let bxz3_part = bxz_part.triple();
        let xx3_m_zz3 = xx.triple().sub(z3);

        Self {
            x: yy_p_bzz3.mul(xy_pairs).sub(yz_pairs.mul(bxz3_part)),
            y: yy_p_bzz3.mul(yy_m_bzz3).add(xx3_m_zz3.mul(bxz3_part)),
            z: yy_m_bzz3.mul(yz_pairs).add(xy_pairs.mul(xx3_m_zz3)),
        }
    }

    fn double(&self) -> Self {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz = self.z.square();
        let xy2 = self.x.mul(self.y).double();
        let xz2 = self.x.mul(self.z).double();

        let bzz_part = CURVE_B.mul(zz).sub(xz2);
        let bzz3_part = bzz_part.triple();
        let yy_m_bzz3 = yy.sub(bzz3_part);
        let yy_p_bzz3 = yy.add(bzz3_part);
        let y_frag = yy_p_bzz3.mul(yy_m_bzz3);
        let x_frag = yy_m_bzz3.mul(xy2);

        let zz3 = zz.triple();
        let bxz2_part = CURVE_B.mul(xz2).sub(zz3.add(xx));
        let bxz6_part = bxz2_part.triple();
        let xx3_m_zz3 = xx.triple().sub(zz3);

        let y = y_frag.add(xx3_m_zz3.mul(bxz6_part));
        let yz2 = self.y.mul(self.z).double();
        let x = x_frag.sub(bxz6_part.mul(yz2));
        let z = yz2.mul(yy).double().double();

        Self {
            x,
            y,
            z,
        }
    }
}

fn scalar_mul_generator(scalar: &Scalar) -> ProjectivePoint {
    scalar_mul_affine(&AffinePoint::GENERATOR, scalar)
}

fn scalar_mul_affine(base: &AffinePoint, scalar: &Scalar) -> ProjectivePoint {
    let mut acc = ProjectivePoint::IDENTITY;
    let mut bit = 256usize;
    while bit > 0 {
        bit -= 1;
        acc = acc.double();
        let candidate = acc.add_mixed(base);
        acc = ProjectivePoint::select(&candidate, &acc, scalar.bit(bit));
    }
    acc
}

#[inline]
fn hash_message(message: &[u8]) -> [u8; 32] {
    let digest = Sha256::hash(message);
    return digest.as_ref().try_into().unwrap();
}

#[inline]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mac = Hmac::<Sha256>::mac(key, data);
    return mac.as_ref().try_into().unwrap();
}

fn bits2octets(hash: &[u8; 32]) -> [u8; 32] {
    Scalar::from_hash(hash).to_bytes()
}

fn rfc6979_generate_k(private_key: &Scalar, message_hash: &[u8; 32]) -> Scalar {
    let x = private_key.to_bytes();
    let h1 = bits2octets(message_hash);

    let mut v = [0x01u8; 32];
    let mut k = [0u8; 32];

    let mut buf = [0u8; 97];
    buf[..32].copy_from_slice(&v);
    buf[32] = 0x00;
    buf[33..65].copy_from_slice(&x);
    buf[65..97].copy_from_slice(&h1);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);

    buf[..32].copy_from_slice(&v);
    buf[32] = 0x01;
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);

    loop {
        v = hmac_sha256(&k, &v);
        if let Some(candidate) = Scalar::from_bytes(&v) {
            return candidate;
        }

        let mut retry_buf = [0u8; 33];
        retry_buf[..32].copy_from_slice(&v);
        retry_buf[32] = 0x00;
        k = hmac_sha256(&k, &retry_buf);
        v = hmac_sha256(&k, &v);
    }
}

fn parse_private_key(private_key: &[u8; PRIVATE_KEY_SIZE]) -> Result<Scalar, EllipticCurveError> {
    Scalar::from_bytes(private_key).ok_or(EllipticCurveError::InvalidKey)
}

fn parse_public_key(public_key: &[u8]) -> Result<AffinePoint, EllipticCurveError> {
    AffinePoint::from_sec1_bytes(public_key).ok_or(EllipticCurveError::InvalidKey)
}

pub fn derive_public_key_uncompressed(
    private_key: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_UNCOMPRESSED_SIZE], EllipticCurveError> {
    let scalar = parse_private_key(private_key)?;
    let point = scalar_mul_generator(&scalar)
        .to_affine()
        .ok_or(EllipticCurveError::Unspecified)?;
    Ok(point.to_uncompressed_bytes())
}

pub fn derive_public_key_compressed(
    private_key: &[u8; PRIVATE_KEY_SIZE],
) -> Result<[u8; PUBLIC_KEY_COMPRESSED_SIZE], EllipticCurveError> {
    let scalar = parse_private_key(private_key)?;
    let point = scalar_mul_generator(&scalar)
        .to_affine()
        .ok_or(EllipticCurveError::Unspecified)?;
    Ok(point.to_compressed_bytes())
}

pub fn ecdsa_sign(
    private_key: &[u8; PRIVATE_KEY_SIZE],
    message: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], EllipticCurveError> {
    let private_scalar = parse_private_key(private_key)?;
    let message_hash = hash_message(message);
    let z = Scalar::from_hash(&message_hash);

    let mut k = rfc6979_generate_k(&private_scalar, &message_hash);
    loop {
        let r_point = scalar_mul_generator(&k)
            .to_affine()
            .ok_or(EllipticCurveError::Unspecified)?;
        let r = Scalar::from_hash(&r_point.x.to_bytes());
        if r.is_zero() {
            k = rfc6979_generate_k(&k, &message_hash);
            continue;
        }

        let kinv = k.invert().ok_or(EllipticCurveError::Unspecified)?;
        let s = kinv.mul(z.add(r.mul(private_scalar)));
        if s.is_zero() {
            k = rfc6979_generate_k(&k, &message_hash);
            continue;
        }

        let mut out = [0u8; SIGNATURE_SIZE];
        out[..32].copy_from_slice(&r.to_bytes());
        out[32..].copy_from_slice(&s.to_bytes());
        return Ok(out);
    }
}

pub fn ecdsa_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), EllipticCurveError> {
    let public = parse_public_key(public_key)?;
    let r = Scalar::from_bytes(signature[..32].try_into().unwrap()).ok_or(EllipticCurveError::Unspecified)?;
    let s = Scalar::from_bytes(signature[32..].try_into().unwrap()).ok_or(EllipticCurveError::Unspecified)?;
    let z = Scalar::from_hash(&hash_message(message));

    let w = s.invert().ok_or(EllipticCurveError::Unspecified)?;
    let u1 = z.mul(w);
    let u2 = r.mul(w);

    let point = scalar_mul_generator(&u1).add(&scalar_mul_affine(&public, &u2));
    let affine = point.to_affine().ok_or(EllipticCurveError::Unspecified)?;
    let x_mod_n = Scalar::from_hash(&affine.x.to_bytes());

    if x_mod_n == r {
        Ok(())
    } else {
        Err(EllipticCurveError::Unspecified)
    }
}

pub fn is_valid_public_key(public_key: &[u8]) -> bool {
    AffinePoint::from_sec1_bytes(public_key).is_some()
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
        let expected = decode_hex::<65>(
            "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
             7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        );
        assert_eq!(derive_public_key_uncompressed(&private_key).unwrap(), expected);
        assert_eq!(
            derive_public_key_compressed(&private_key).unwrap(),
            decode_hex::<33>("0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
        );
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
    fn rfc6979_nonce_point_x_matches_signature_r() {
        let nonce = decode_hex::<32>("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
        let public = derive_public_key_uncompressed(&nonce).unwrap();
        assert_eq!(
            &public[1..33],
            &decode_hex::<32>("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716")
        );
    }

    #[test]
    fn rfc6979_nonce_generation_matches_known_value() {
        let private_key = Scalar::from_bytes(&decode_hex::<32>(
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ))
        .unwrap();
        let hash = hash_message(b"sample");
        assert_eq!(
            rfc6979_generate_k(&private_key, &hash).to_bytes(),
            decode_hex::<32>("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60")
        );
    }

    #[test]
    fn rfc6979_intermediate_hmac_values_match() {
        let x = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let h1 = hash_message(b"sample");
        let mut v = [0x01u8; 32];
        let mut k = [0u8; 32];

        let mut buf = [0u8; 97];
        buf[..32].copy_from_slice(&v);
        buf[32] = 0x00;
        buf[33..65].copy_from_slice(&x);
        buf[65..97].copy_from_slice(&h1);
        k = hmac_sha256(&k, &buf);
        assert_eq!(
            k,
            decode_hex::<32>("122db1de98dae4dfa33f2da8e98494c80bff807b479fd79261b37e25f267ee58")
        );
        v = hmac_sha256(&k, &v);
        assert_eq!(
            v,
            decode_hex::<32>("c9947803a747fc60c23535fdcc13b5ca566b48221ca67d4964d22daa48275844")
        );

        buf[..32].copy_from_slice(&v);
        buf[32] = 0x01;
        k = hmac_sha256(&k, &buf);
        assert_eq!(
            k,
            decode_hex::<32>("b6d4f98ebae70aa15a2238ade4e20ab323fc1e777d22f0c582d8ef2e6ba73569")
        );
        v = hmac_sha256(&k, &v);
        assert_eq!(
            v,
            decode_hex::<32>("bae57fe256de2de806b10635497237e7bae96754582566384c47c6c3416494d1")
        );
        v = hmac_sha256(&k, &v);
        assert_eq!(
            v,
            decode_hex::<32>("a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60")
        );
    }

    #[test]
    fn ecdsa_verify_accepts_compressed_and_uncompressed_public_keys() {
        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let public_key = derive_public_key_uncompressed(&private_key).unwrap();
        let compressed = derive_public_key_compressed(&private_key).unwrap();
        let signature = ecdsa_sign(&private_key, b"sample").unwrap();

        assert!(ecdsa_verify(&public_key, b"sample", &signature).is_ok());
        assert!(ecdsa_verify(&compressed, b"sample", &signature).is_ok());
    }

    #[test]
    fn verify_rejects_tampering_and_invalid_points() {
        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let public_key = derive_public_key_uncompressed(&private_key).unwrap();
        let signature = ecdsa_sign(&private_key, b"sample").unwrap();

        assert!(ecdsa_verify(&public_key, b"tampered", &signature).is_err());

        let mut bad_signature = signature;
        bad_signature[10] ^= 0x80;
        assert!(ecdsa_verify(&public_key, b"sample", &bad_signature).is_err());

        let mut off_curve = public_key;
        off_curve[64] ^= 0x01;
        assert!(!is_valid_public_key(&off_curve));
        assert!(ecdsa_verify(&off_curve, b"sample", &signature).is_err());

        let invalid_x = decode_hex::<33>("02ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        assert!(!is_valid_public_key(&invalid_x));
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        let invalid_private_key = [0u8; PRIVATE_KEY_SIZE];
        assert!(derive_public_key_uncompressed(&invalid_private_key).is_err());
        assert!(derive_public_key_compressed(&invalid_private_key).is_err());
        assert!(ecdsa_sign(&invalid_private_key, b"msg").is_err());

        let private_key = decode_hex::<32>("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let signature = ecdsa_sign(&private_key, b"msg").unwrap();
        let mut zero_r = signature;
        zero_r[..32].fill(0);
        assert!(ecdsa_verify(&derive_public_key_uncompressed(&private_key).unwrap(), b"msg", &zero_r).is_err());
    }

    #[test]
    fn public_key_validation_accepts_known_good_points() {
        assert!(is_valid_public_key(&decode_hex::<65>(
            "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
             4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )));
        assert!(is_valid_public_key(&decode_hex::<33>(
            "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        )));
    }
}
