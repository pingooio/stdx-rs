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
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66,
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
            TestVector {
                seed: "0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9",
                public_key: "e61a185bcef2613a6c7cb79763ce945d3b245d76114dd440bcf5f2dc1aa57057",
                message: "cbc77b",
                signature: "d9868d52c2bebce5f3fa5a79891970f309cb6591e3e1702a70276fa97c24b3a8e58606c38c9758529da50ee31b8219cba45271c689afa60b0ea26c99db19b00c",
            },
            TestVector {
                seed: "6df9340c138cc188b5fe4464ebaa3f7fc206a2d55c3434707e74c9fc04e20ebb",
                public_key: "c0dac102c4533186e25dc43128472353eaabdb878b152aeb8e001f92d90233a7",
                message: "5f4c8989",
                signature: "124f6fc6b0d100842769e71bd530664d888df8507df6c56dedfdb509aeb93416e26b918d38aa06305df3095697c18b2aa832eaa52edc0ae49fbae5a85e150c07",
            },
            TestVector {
                seed: "b780381a65edf8b78f6945e8dbec7941ac049fd4c61040cf0c324357975a293c",
                public_key: "e253af0766804b869bb1595be9765b534886bbaab8305bf50dbc7f899bfb5f01",
                message: "18b6bec097",
                signature: "b2fc46ad47af464478c199e1f8be169f1be6327c7f9a0a6689371ca94caf04064a01b22aff1520abd58951341603faed768cf78ce97ae7b038abfe456aa17c09",
            },
            TestVector {
                seed: "78ae9effe6f245e924a7be63041146ebc670dbd3060cba67fbc6216febc44546",
                public_key: "fbcfbfa40505d7f2be444a33d185cc54e16d615260e1640b2b5087b83ee3643d",
                message: "89010d855972",
                signature: "6ed629fc1d9ce9e1468755ff636d5a3f40a5d9c91afd93b79d241830f7e5fa29854b8f20cc6eecbb248dbd8d16d14e99752194e4904d09c74d639518839d2300",
            },
            TestVector {
                seed: "691865bfc82a1e4b574eecde4c7519093faf0cf867380234e3664645c61c5f79",
                public_key: "98a5e3a36e67aaba89888bf093de1ad963e774013b3902bfab356d8b90178a63",
                message: "b4a8f381e70e7a",
                signature: "6e0af2fe55ae377a6b7a7278edfb419bd321e06d0df5e27037db8812e7e3529810fa5552f6c0020985ca17a0e02e036d7b222a24f99b77b75fdd16cb05568107",
            },
            TestVector {
                seed: "3b26516fb3dc88eb181b9ed73f0bcd52bcd6b4c788e4bcaf46057fd078bee073",
                public_key: "f81fb54a825fced95eb033afcd64314075abfb0abd20a970892503436f34b863",
                message: "4284abc51bb67235",
                signature: "d6addec5afb0528ac17bb178d3e7f2887f9adbb1ad16e110545ef3bc57f9de2314a5c8388f723b8907be0f3ac90c6259bbe885ecc17645df3db7d488f805fa08",
            },
            TestVector {
                seed: "edc6f5fbdd1cee4d101c063530a30490b221be68c036f5b07d0f953b745df192",
                public_key: "c1a49c66e617f9ef5ec66bc4c6564ca33de2a5fb5e1464062e6d6c6219155efd",
                message: "672bf8965d04bc5146",
                signature: "2c76a04af2391c147082e33faacdbe56642a1e134bd388620b852b901a6bc16ff6c9cc9404c41dea12ed281da067a1513866f9d964f8bdd24953856c50042901",
            },
            TestVector {
                seed: "4e7d21fb3b1897571a445833be0f9fd41cd62be3aa04040f8934e1fcbdcacd45",
                public_key: "31b2524b8348f7ab1dfafa675cc538e9a84e3fe5819e27c12ad8bbc1a36e4dff",
                message: "33d7a786aded8c1bf691",
                signature: "28e4598c415ae9de01f03f9f3fab4e919e8bf537dd2b0cdf6e79b9e6559c9409d9151a4c40f083193937627c369488259e99da5a9f0a87497fa6696a5dd6ce08",
            },
            TestVector {
                seed: "a980f892db13c99a3e8971e965b2ff3d41eafd54093bc9f34d1fd22d84115bb6",
                public_key: "44b57ee30cdb55829d0a5d4f046baef078f1e97a7f21b62d75f8e96ea139c35f",
                message: "3486f68848a65a0eb5507d",
                signature: "77d389e599630d934076329583cd4105a649a9292abc44cd28c40000c8e2f5ac7660a81c85b72af8452d7d25c070861dae91601c7803d656531650dd4e5c4100",
            },
            TestVector {
                seed: "5b5a619f8ce1c66d7ce26e5a2ae7b0c04febcd346d286c929e19d0d5973bfef9",
                public_key: "6fe83693d011d111131c4f3fbaaa40a9d3d76b30012ff73bb0e39ec27ab18257",
                message: "5a8d9d0a22357e6655f9c785",
                signature: "0f9ad9793033a2fa06614b277d37381e6d94f65ac2a5a94558d09ed6ce922258c1a567952e863ac94297aec3c0d0c8ddf71084e504860bb6ba27449b55adc40e",
            },
            TestVector {
                seed: "940c89fe40a81dafbdb2416d14ae469119869744410c3303bfaa0241dac57800",
                public_key: "a2eb8c0501e30bae0cf842d2bde8dec7386f6b7fc3981b8c57c9792bb94cf2dd",
                message: "b87d3813e03f58cf19fd0b6395",
                signature: "d8bb64aad8c9955a115a793addd24f7f2b077648714f49c4694ec995b330d09d640df310f447fd7b6cb5c14f9fe9f490bcf8cfadbfd2169c8ac20d3b8af49a0c",
            },
            TestVector {
                seed: "9acad959d216212d789a119252ebfe0c96512a23c73bd9f3b202292d6916a738",
                public_key: "cf3af898467a5b7a52d33d53bc037e2642a8da996903fc252217e9c033e2f291",
                message: "55c7fa434f5ed8cdec2b7aeac173",
                signature: "6ee3fe81e23c60eb2312b2006b3b25e6838e02106623f844c44edb8dafd66ab0671087fd195df5b8f58a1d6e52af42908053d55c7321010092748795ef94cf06",
            },
            TestVector {
                seed: "d5aeee41eeb0e9d1bf8337f939587ebe296161e6bf5209f591ec939e1440c300",
                public_key: "fd2a565723163e29f53c9de3d5e8fbe36a7ab66e1439ec4eae9c0a604af291a5",
                message: "0a688e79be24f866286d4646b5d81c",
                signature: "f68d04847e5b249737899c014d31c805c5007a62c0a10d50bb1538c5f35503951fbc1e08682f2cc0c92efe8f4985dec61dcbd54d4b94a22547d24451271c8b00",
            },
            TestVector {
                seed: "0a47d10452ae2febec518a1c7c362890c3fc1a49d34b03b6467d35c904a8362d",
                public_key: "34e5a8508c4743746962c066e4badea2201b8ab484de5c4f94476ccd2143955b",
                message: "c942fa7ac6b23ab7ff612fdc8e68ef39",
                signature: "2a3d27dc40d0a8127949a3b7f908b3688f63b7f14f651aacd715940bdbe27a0809aac142f47ab0e1e44fa490ba87ce5392f33a891539caf1ef4c367cae54500c",
            },
            TestVector {
                seed: "f8148f7506b775ef46fdc8e8c756516812d47d6cfbfa318c27c9a22641e56f17",
                public_key: "0445e456dacc7d5b0bbed23c8200cdb74bdcb03e4c7b73f0a2b9b46eac5d4372",
                message: "7368724a5b0efb57d28d97622dbde725af",
                signature: "3653ccb21219202b8436fb41a32ba2618c4a133431e6e63463ceb3b6106c4d56e1d2ba165ba76eaad3dc39bffb130f1de3d8e6427db5b71938db4e272bc3e20b",
            },
            TestVector {
                seed: "77f88691c4eff23ebb7364947092951a5ff3f10785b417e918823a552dab7c75",
                public_key: "74d29127f199d86a8676aec33b4ce3f225ccb191f52c191ccd1e8cca65213a6b",
                message: "bd8e05033f3a8bcdcbf4beceb70901c82e31",
                signature: "fbe929d743a03c17910575492f3092ee2a2bf14a60a3fcacec74a58c7334510fc262db582791322d6c8c41f1700adb80027ecabc14270b703444ae3ee7623e0a",
            },
            TestVector {
                seed: "ab6f7aee6a0837b334ba5eb1b2ad7fcecfab7e323cab187fe2e0a95d80eff132",
                public_key: "5b96dca497875bf9664c5e75facf3f9bc54bae913d66ca15ee85f1491ca24d2c",
                message: "8171456f8b907189b1d779e26bc5afbb08c67a",
                signature: "73bca64e9dd0db88138eedfafcea8f5436cfb74bfb0e7733cf349baa0c49775c56d5934e1d38e36f39b7c5beb0a836510c45126f8ec4b6810519905b0ca07c09",
            },
        ];

        for vector in &vectors {
            assert_vector(vector);
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
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
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
}
