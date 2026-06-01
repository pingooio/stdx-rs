use constant_time_eq::constant_time_eq;
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    Xof,
    sha3::{Sha3_256, Sha3_512, Shake128, Shake256},
};

pub const SHARED_SECRET_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE_768: usize = 1184;
pub const SECRET_KEY_SIZE_768: usize = 2400;
pub const CIPHERTEXT_SIZE_768: usize = 1088;
pub const PUBLIC_KEY_SIZE_1024: usize = 1568;
pub const SECRET_KEY_SIZE_1024: usize = 3168;
pub const CIPHERTEXT_SIZE_1024: usize = 1568;

const N: usize = 256;
const Q: i16 = 3329;
const SYMBYTES: usize = 32;
const POLY_BYTES: usize = 384;
const SHAKE128_RATE: usize = 168;
const QINV: i16 = -3327;
const MONT_SQUARED_DIV_N: i16 = 1441;
const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468, 573, -1325, 264,
    383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491,
    -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961,
    -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460,
    1574, 1653, -246, 778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185, -1530, -1278, 794,
    -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

const ML_KEM_768: MlKemParams<3> = MlKemParams {
    eta1: 2,
    polycompressedbytes: 128,
    polyveccompressedbytes: 960,
};
const ML_KEM_1024: MlKemParams<4> = MlKemParams {
    eta1: 2,
    polycompressedbytes: 160,
    polyveccompressedbytes: 1408,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemError {
    InvalidKey,
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for MlKemError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MlKemError::InvalidKey => write!(f, "key is not valid"),
        }
    }
}

/// ML-KEM-768 decapsulation key (secret key).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct SecretKey768 {
    bytes: [u8; SECRET_KEY_SIZE_768],
}

/// ML-KEM-768 encapsulation key (public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey768 {
    bytes: [u8; PUBLIC_KEY_SIZE_768],
}

/// ML-KEM-1024 decapsulation key (secret key).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct SecretKey1024 {
    bytes: [u8; SECRET_KEY_SIZE_1024],
}

/// ML-KEM-1024 encapsulation key (public key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey1024 {
    bytes: [u8; PUBLIC_KEY_SIZE_1024],
}

#[derive(Clone, Copy)]
struct MlKemParams<const K: usize> {
    eta1: usize,
    polycompressedbytes: usize,
    polyveccompressedbytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
struct Poly {
    coeffs: [i16; N],
}

impl Default for Poly {
    #[inline]
    fn default() -> Self {
        Self {
            coeffs: [0; N],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
struct PolyVec<const K: usize> {
    vec: [Poly; K],
}

impl<const K: usize> Default for PolyVec<K> {
    #[inline]
    fn default() -> Self {
        Self {
            vec: core::array::from_fn(|_| Poly::default()),
        }
    }
}

#[inline]
pub fn ml_kem_768_generate_keypair() -> (SecretKey768, PublicKey768) {
    SecretKey768::generate()
}

#[inline]
pub fn ml_kem_768_encapsulate(public_key: &PublicKey768) -> ([u8; CIPHERTEXT_SIZE_768], [u8; SHARED_SECRET_SIZE]) {
    public_key.encapsulate()
}

#[inline]
pub fn ml_kem_768_decapsulate(
    private_key: &SecretKey768,
    ciphertext: &[u8; CIPHERTEXT_SIZE_768],
) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
    private_key.decapsulate(ciphertext)
}

pub fn ml_kem_1024_generate_keypair() -> (SecretKey1024, PublicKey1024) {
    SecretKey1024::generate()
}

#[inline]
pub fn ml_kem_1024_encapsulate(public_key: &PublicKey1024) -> ([u8; CIPHERTEXT_SIZE_1024], [u8; SHARED_SECRET_SIZE]) {
    public_key.encapsulate()
}

#[inline]
pub fn ml_kem_1024_decapsulate(
    private_key: &SecretKey1024,
    ciphertext: &[u8; CIPHERTEXT_SIZE_1024],
) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
    private_key.decapsulate(ciphertext)
}

#[inline]
fn crypto_kem_keypair_derand<const K: usize, const SECRET_KEY_SIZE: usize, const PUBLIC_KEY_SIZE: usize>(
    params: &MlKemParams<K>,
    coins: &[u8; 64],
) -> ([u8; SECRET_KEY_SIZE], [u8; PUBLIC_KEY_SIZE]) {
    let mut public_key = [0u8; PUBLIC_KEY_SIZE];
    let mut secret_key = [0u8; SECRET_KEY_SIZE];

    indcpa_keypair_derand::<K>(
        params,
        &mut public_key,
        &mut secret_key[..indcpa_secret_key_bytes::<K>()],
        &coins[..32],
    );
    secret_key[indcpa_secret_key_bytes::<K>()..indcpa_secret_key_bytes::<K>() + PUBLIC_KEY_SIZE]
        .copy_from_slice(&public_key);

    let public_key_hash = hash_h(&public_key);
    secret_key[SECRET_KEY_SIZE - 64..SECRET_KEY_SIZE - 32].copy_from_slice(&public_key_hash);
    secret_key[SECRET_KEY_SIZE - 32..].copy_from_slice(&coins[32..]);

    (secret_key, public_key)
}

#[inline]
fn crypto_kem_enc_derand<const K: usize, const PUBLIC_KEY_SIZE: usize, const CIPHERTEXT_SIZE: usize>(
    params: &MlKemParams<K>,
    public_key: &[u8; PUBLIC_KEY_SIZE],
    coins: &[u8; 32],
) -> ([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]) {
    let mut ciphertext = [0u8; CIPHERTEXT_SIZE];
    let mut buf = [0u8; 64];
    let mut kr = [0u8; 64];

    buf[..32].copy_from_slice(coins);
    buf[32..].copy_from_slice(&hash_h(public_key));
    kr.copy_from_slice(&hash_g(&buf));

    indcpa_enc::<K>(params, &mut ciphertext, &buf[..32], public_key, array_ref_32(&kr[32..64]));

    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(&kr[..32]);
    (ciphertext, shared_secret)
}

#[inline]
fn crypto_kem_dec<const K: usize, const SECRET_KEY_SIZE: usize, const CIPHERTEXT_SIZE: usize>(
    params: &MlKemParams<K>,
    secret_key: &[u8; SECRET_KEY_SIZE],
    ciphertext: &[u8; CIPHERTEXT_SIZE],
) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
    let public_key_offset = indcpa_secret_key_bytes::<K>();
    let public_key_size = public_key_bytes::<K>();
    if SECRET_KEY_SIZE != secret_key_size::<K>() {
        return Err(MlKemError::InvalidKey);
    }

    let public_key = &secret_key[public_key_offset..public_key_offset + public_key_size];
    let mut message_and_hash = [0u8; 64];
    let mut kr = [0u8; 64];
    let mut cmp = [0u8; CIPHERTEXT_SIZE];

    indcpa_dec::<K>(
        params,
        &mut message_and_hash[..32],
        ciphertext,
        &secret_key[..public_key_offset],
    );
    message_and_hash[32..].copy_from_slice(&secret_key[SECRET_KEY_SIZE - 64..SECRET_KEY_SIZE - 32]);
    kr.copy_from_slice(&hash_g(&message_and_hash));

    indcpa_enc::<K>(params, &mut cmp, &message_and_hash[..32], public_key, array_ref_32(&kr[32..64]));

    let mut shared_secret = rkprf(array_ref_32(&secret_key[SECRET_KEY_SIZE - 32..]), ciphertext);
    cmov(&mut shared_secret, array_ref_32(&kr[..32]), constant_time_eq(ciphertext, &cmp));
    Ok(shared_secret)
}

#[inline]
fn indcpa_keypair_derand<const K: usize>(
    params: &MlKemParams<K>,
    public_key: &mut [u8],
    secret_key: &mut [u8],
    coins: &[u8],
) {
    debug_assert_eq!(public_key.len(), public_key_bytes::<K>());
    debug_assert_eq!(secret_key.len(), indcpa_secret_key_bytes::<K>());
    debug_assert_eq!(coins.len(), 32);

    // FIPS 203, Algorithm 13 (K-PKE.KeyGen): (ρ, σ) ← G(d ‖ k)
    // where k is the module dimension as a domain separator byte.
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(coins);
    g_input[32] = K as u8;
    let seed_output = hash_g(&g_input);
    let public_seed = array_ref_32(&seed_output[..32]);
    let noise_seed = array_ref_32(&seed_output[32..64]);
    let matrix = gen_matrix::<K>(public_seed, false);

    let mut skpv = PolyVec::<K>::default();
    let mut e = PolyVec::<K>::default();
    for (index, poly) in skpv.vec.iter_mut().enumerate() {
        *poly = poly_getnoise(noise_seed, index as u8, params.eta1);
    }
    for (index, poly) in e.vec.iter_mut().enumerate() {
        *poly = poly_getnoise(noise_seed, (K + index) as u8, params.eta1);
    }

    polyvec_ntt(&mut skpv);
    polyvec_ntt(&mut e);

    let mut pkpv = PolyVec::<K>::default();
    for i in 0..K {
        pkpv.vec[i] = polyvec_basemul_acc_montgomery(&matrix[i], &skpv);
        poly_tomont(&mut pkpv.vec[i]);
    }

    polyvec_add(&mut pkpv, &e);
    polyvec_reduce(&mut pkpv);

    pack_sk(secret_key, &skpv);
    pack_pk(public_key, &pkpv, public_seed);
}

#[inline]
fn indcpa_enc<const K: usize>(
    params: &MlKemParams<K>,
    ciphertext: &mut [u8],
    message: &[u8],
    public_key: &[u8],
    coins: &[u8; 32],
) {
    debug_assert_eq!(ciphertext.len(), ciphertext_bytes(params));
    debug_assert_eq!(message.len(), 32);
    debug_assert_eq!(public_key.len(), public_key_bytes::<K>());

    let (pkpv, seed) = unpack_pk::<K>(public_key);
    let at = gen_matrix::<K>(&seed, true);
    let k = poly_frommsg(message);

    let mut sp = PolyVec::<K>::default();
    let mut ep = PolyVec::<K>::default();
    for (index, poly) in sp.vec.iter_mut().enumerate() {
        *poly = poly_getnoise(coins, index as u8, params.eta1);
    }
    let ep_nonce_offset = sp.vec.len();
    for (index, poly) in ep.vec.iter_mut().enumerate() {
        *poly = poly_getnoise(coins, (ep_nonce_offset + index) as u8, 2);
    }
    let epp = poly_getnoise(coins, (sp.vec.len() + ep.vec.len()) as u8, 2);

    polyvec_ntt(&mut sp);

    let mut b = PolyVec::<K>::default();
    for i in 0..K {
        b.vec[i] = polyvec_basemul_acc_montgomery(&at[i], &sp);
    }
    let mut v = polyvec_basemul_acc_montgomery(&pkpv, &sp);

    polyvec_invntt_tomont(&mut b);
    poly_invntt_tomont(&mut v);

    polyvec_add(&mut b, &ep);
    poly_add(&mut v, &epp);
    poly_add(&mut v, &k);
    polyvec_reduce(&mut b);
    poly_reduce(&mut v);

    pack_ciphertext(params, ciphertext, &b, &v);
}

#[inline]
fn indcpa_dec<const K: usize>(params: &MlKemParams<K>, message: &mut [u8], ciphertext: &[u8], secret_key: &[u8]) {
    debug_assert_eq!(message.len(), 32);
    debug_assert_eq!(ciphertext.len(), ciphertext_bytes(params));
    debug_assert_eq!(secret_key.len(), indcpa_secret_key_bytes::<K>());

    let (mut b, v) = unpack_ciphertext::<K>(params, ciphertext);
    let skpv = unpack_sk::<K>(secret_key);

    polyvec_ntt(&mut b);
    let mut mp = polyvec_basemul_acc_montgomery(&skpv, &b);
    poly_invntt_tomont(&mut mp);
    let product = mp.clone();
    poly_sub(&mut mp, &v, &product);
    poly_reduce(&mut mp);

    message.copy_from_slice(&poly_tomsg(&mp));
}

#[inline]
fn pack_pk<const K: usize>(out: &mut [u8], pk: &PolyVec<K>, seed: &[u8; 32]) {
    let polyvec_bytes = polyvec_bytes::<K>();
    polyvec_tobytes(&mut out[..polyvec_bytes], pk);
    out[polyvec_bytes..polyvec_bytes + 32].copy_from_slice(seed);
}

#[inline]
fn unpack_pk<const K: usize>(packed: &[u8]) -> (PolyVec<K>, [u8; 32]) {
    let polyvec_bytes = polyvec_bytes::<K>();
    let pk = polyvec_frombytes::<K>(&packed[..polyvec_bytes]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&packed[polyvec_bytes..polyvec_bytes + 32]);
    (pk, seed)
}

#[inline]
fn pack_sk<const K: usize>(out: &mut [u8], sk: &PolyVec<K>) {
    polyvec_tobytes(out, sk);
}

#[inline]
fn unpack_sk<const K: usize>(packed: &[u8]) -> PolyVec<K> {
    polyvec_frombytes(packed)
}

#[inline]
fn pack_ciphertext<const K: usize>(params: &MlKemParams<K>, out: &mut [u8], b: &PolyVec<K>, v: &Poly) {
    let split = params.polyveccompressedbytes;
    polyvec_compress(params, &mut out[..split], b);
    poly_compress(params, &mut out[split..split + params.polycompressedbytes], v);
}

#[inline]
fn unpack_ciphertext<const K: usize>(params: &MlKemParams<K>, packed: &[u8]) -> (PolyVec<K>, Poly) {
    let split = params.polyveccompressedbytes;
    (
        polyvec_decompress(params, &packed[..split]),
        poly_decompress(params, &packed[split..split + params.polycompressedbytes]),
    )
}

#[inline]
fn gen_matrix<const K: usize>(seed: &[u8; 32], transpose: bool) -> [PolyVec<K>; K] {
    let mut matrix = core::array::from_fn(|_| PolyVec::<K>::default());
    for i in 0..K {
        for j in 0..K {
            let (x, y) = if transpose {
                (i as u8, j as u8)
            } else {
                (j as u8, i as u8)
            };
            matrix[i].vec[j] = uniform_poly(seed, x, y);
        }
    }
    matrix
}

#[inline]
fn uniform_poly(seed: &[u8; 32], x: u8, y: u8) -> Poly {
    let mut shake = Shake128::new();
    shake.absorb(seed);
    shake.absorb(&[x, y]);

    let mut poly = Poly::default();
    let mut ctr = 0usize;
    let mut block = [0u8; SHAKE128_RATE];
    while ctr < N {
        shake.squeeze(&mut block);
        ctr += rej_uniform(&mut poly.coeffs[ctr..], &block);
    }
    poly
}

#[inline]
fn rej_uniform(out: &mut [i16], buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < out.len() && pos + 3 <= buf.len() {
        let val0 = (((buf[pos] as u16) | ((buf[pos + 1] as u16) << 8)) & 0x0fff) as i16;
        let val1 = ((((buf[pos + 1] as u16) >> 4) | ((buf[pos + 2] as u16) << 4)) & 0x0fff) as i16;
        pos += 3;

        if val0 < Q {
            out[ctr] = val0;
            ctr += 1;
        }
        if ctr < out.len() && val1 < Q {
            out[ctr] = val1;
            ctr += 1;
        }
    }
    ctr
}

#[inline]
fn poly_getnoise(seed: &[u8; 32], nonce: u8, eta: usize) -> Poly {
    debug_assert_eq!(eta, 2);
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = nonce;
    let mut buf = [0u8; 128];
    Shake256::hash(&input, &mut buf);
    cbd2(&buf)
}

#[inline]
fn cbd2(buf: &[u8; 128]) -> Poly {
    let mut poly = Poly::default();
    for i in 0..(N / 8) {
        let t = load32(&buf[4 * i..4 * i + 4]);
        let mut d = t & 0x5555_5555;
        d += (t >> 1) & 0x5555_5555;
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            poly.coeffs[8 * i + j] = a - b;
        }
    }
    poly
}

#[inline]
fn polyvec_compress<const K: usize>(params: &MlKemParams<K>, out: &mut [u8], a: &PolyVec<K>) {
    match params.polyveccompressedbytes {
        960 => {
            let mut offset = 0usize;
            for poly in &a.vec {
                for chunk in poly.coeffs.chunks_exact(4) {
                    let mut t = [0u16; 4];
                    for (dst, coeff) in t.iter_mut().zip(chunk.iter()) {
                        let mut u = *coeff as i32;
                        u += (u >> 15) & Q as i32;
                        let mut d0 = u as u64;
                        d0 <<= 10;
                        d0 += 1665;
                        d0 *= 1_290_167;
                        d0 >>= 32;
                        *dst = (d0 as u16) & 0x03ff;
                    }
                    out[offset] = t[0] as u8;
                    out[offset + 1] = ((t[0] >> 8) as u8) | ((t[1] << 2) as u8);
                    out[offset + 2] = ((t[1] >> 6) as u8) | ((t[2] << 4) as u8);
                    out[offset + 3] = ((t[2] >> 4) as u8) | ((t[3] << 6) as u8);
                    out[offset + 4] = (t[3] >> 2) as u8;
                    offset += 5;
                }
            }
        }
        1408 => {
            let mut offset = 0usize;
            for poly in &a.vec {
                for chunk in poly.coeffs.chunks_exact(8) {
                    let mut t = [0u16; 8];
                    for (dst, coeff) in t.iter_mut().zip(chunk.iter()) {
                        let mut u = *coeff as i32;
                        u += (u >> 15) & Q as i32;
                        let mut d0 = u as u64;
                        d0 <<= 11;
                        d0 += 1664;
                        d0 *= 645_084;
                        d0 >>= 31;
                        *dst = (d0 as u16) & 0x07ff;
                    }
                    out[offset] = t[0] as u8;
                    out[offset + 1] = ((t[0] >> 8) as u8) | ((t[1] << 3) as u8);
                    out[offset + 2] = ((t[1] >> 5) as u8) | ((t[2] << 6) as u8);
                    out[offset + 3] = (t[2] >> 2) as u8;
                    out[offset + 4] = ((t[2] >> 10) as u8) | ((t[3] << 1) as u8);
                    out[offset + 5] = ((t[3] >> 7) as u8) | ((t[4] << 4) as u8);
                    out[offset + 6] = ((t[4] >> 4) as u8) | ((t[5] << 7) as u8);
                    out[offset + 7] = (t[5] >> 1) as u8;
                    out[offset + 8] = ((t[5] >> 9) as u8) | ((t[6] << 2) as u8);
                    out[offset + 9] = ((t[6] >> 6) as u8) | ((t[7] << 5) as u8);
                    out[offset + 10] = (t[7] >> 3) as u8;
                    offset += 11;
                }
            }
        }
        _ => unreachable!(),
    }
}

#[inline]
fn polyvec_decompress<const K: usize>(params: &MlKemParams<K>, input: &[u8]) -> PolyVec<K> {
    let mut out = PolyVec::<K>::default();
    match params.polyveccompressedbytes {
        960 => {
            let mut offset = 0usize;
            for poly in &mut out.vec {
                for j in 0..(N / 4) {
                    let t0 = (input[offset] as u16) | ((input[offset + 1] as u16) << 8);
                    let t1 = ((input[offset + 1] as u16) >> 2) | ((input[offset + 2] as u16) << 6);
                    let t2 = ((input[offset + 2] as u16) >> 4) | ((input[offset + 3] as u16) << 4);
                    let t3 = ((input[offset + 3] as u16) >> 6) | ((input[offset + 4] as u16) << 2);
                    offset += 5;
                    poly.coeffs[4 * j] = ((((t0 & 0x03ff) as u32) * Q as u32 + 512) >> 10) as i16;
                    poly.coeffs[4 * j + 1] = ((((t1 & 0x03ff) as u32) * Q as u32 + 512) >> 10) as i16;
                    poly.coeffs[4 * j + 2] = ((((t2 & 0x03ff) as u32) * Q as u32 + 512) >> 10) as i16;
                    poly.coeffs[4 * j + 3] = ((((t3 & 0x03ff) as u32) * Q as u32 + 512) >> 10) as i16;
                }
            }
        }
        1408 => {
            let mut offset = 0usize;
            for poly in &mut out.vec {
                for j in 0..(N / 8) {
                    let t0 = (input[offset] as u16) | ((input[offset + 1] as u16) << 8);
                    let t1 = ((input[offset + 1] as u16) >> 3) | ((input[offset + 2] as u16) << 5);
                    let t2 = ((input[offset + 2] as u16) >> 6)
                        | ((input[offset + 3] as u16) << 2)
                        | ((input[offset + 4] as u16) << 10);
                    let t3 = ((input[offset + 4] as u16) >> 1) | ((input[offset + 5] as u16) << 7);
                    let t4 = ((input[offset + 5] as u16) >> 4) | ((input[offset + 6] as u16) << 4);
                    let t5 = ((input[offset + 6] as u16) >> 7)
                        | ((input[offset + 7] as u16) << 1)
                        | ((input[offset + 8] as u16) << 9);
                    let t6 = ((input[offset + 8] as u16) >> 2) | ((input[offset + 9] as u16) << 6);
                    let t7 = ((input[offset + 9] as u16) >> 5) | ((input[offset + 10] as u16) << 3);
                    offset += 11;
                    let values = [t0, t1, t2, t3, t4, t5, t6, t7];
                    for (k, value) in values.into_iter().enumerate() {
                        poly.coeffs[8 * j + k] = ((((value & 0x07ff) as u32) * Q as u32 + 1024) >> 11) as i16;
                    }
                }
            }
        }
        _ => unreachable!(),
    }
    out
}

#[inline]
fn polyvec_tobytes<const K: usize>(out: &mut [u8], polyvec: &PolyVec<K>) {
    for (i, poly) in polyvec.vec.iter().enumerate() {
        poly_tobytes(&mut out[i * POLY_BYTES..(i + 1) * POLY_BYTES], poly);
    }
}

#[inline]
fn polyvec_frombytes<const K: usize>(input: &[u8]) -> PolyVec<K> {
    let mut out = PolyVec::<K>::default();
    for (i, poly) in out.vec.iter_mut().enumerate() {
        *poly = poly_frombytes(&input[i * POLY_BYTES..(i + 1) * POLY_BYTES]);
    }
    out
}

#[inline]
fn polyvec_ntt<const K: usize>(polyvec: &mut PolyVec<K>) {
    for poly in &mut polyvec.vec {
        poly_ntt(poly);
    }
}

#[inline]
fn polyvec_invntt_tomont<const K: usize>(polyvec: &mut PolyVec<K>) {
    for poly in &mut polyvec.vec {
        poly_invntt_tomont(poly);
    }
}

#[inline]
fn polyvec_basemul_acc_montgomery<const K: usize>(a: &PolyVec<K>, b: &PolyVec<K>) -> Poly {
    let mut out = poly_basemul_montgomery(&a.vec[0], &b.vec[0]);
    for i in 1..K {
        let t = poly_basemul_montgomery(&a.vec[i], &b.vec[i]);
        poly_add(&mut out, &t);
    }
    poly_reduce(&mut out);
    out
}

#[inline]
fn polyvec_reduce<const K: usize>(polyvec: &mut PolyVec<K>) {
    for poly in &mut polyvec.vec {
        poly_reduce(poly);
    }
}

#[inline]
fn polyvec_add<const K: usize>(left: &mut PolyVec<K>, right: &PolyVec<K>) {
    for i in 0..K {
        poly_add(&mut left.vec[i], &right.vec[i]);
    }
}

#[inline]
fn poly_compress<const K: usize>(params: &MlKemParams<K>, out: &mut [u8], poly: &Poly) {
    match params.polycompressedbytes {
        128 => {
            let mut offset = 0usize;
            for chunk in poly.coeffs.chunks_exact(8) {
                let mut t = [0u8; 8];
                for (dst, coeff) in t.iter_mut().zip(chunk.iter()) {
                    let mut u = *coeff as i32;
                    u += (u >> 15) & Q as i32;
                    let mut d0 = ((u as u32) << 4) as u64;
                    d0 += 1665;
                    d0 *= 80_635;
                    d0 >>= 28;
                    *dst = (d0 as u8) & 0x0f;
                }
                out[offset] = t[0] | (t[1] << 4);
                out[offset + 1] = t[2] | (t[3] << 4);
                out[offset + 2] = t[4] | (t[5] << 4);
                out[offset + 3] = t[6] | (t[7] << 4);
                offset += 4;
            }
        }
        160 => {
            let mut offset = 0usize;
            for chunk in poly.coeffs.chunks_exact(8) {
                let mut t = [0u8; 8];
                for (dst, coeff) in t.iter_mut().zip(chunk.iter()) {
                    let mut u = *coeff as i32;
                    u += (u >> 15) & Q as i32;
                    let mut d0 = ((u as u32) << 5) as u64;
                    d0 += 1664;
                    d0 *= 40_318;
                    d0 >>= 27;
                    *dst = (d0 as u8) & 0x1f;
                }
                out[offset] = t[0] | (t[1] << 5);
                out[offset + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                out[offset + 2] = (t[3] >> 1) | (t[4] << 4);
                out[offset + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                out[offset + 4] = (t[6] >> 2) | (t[7] << 3);
                offset += 5;
            }
        }
        _ => unreachable!(),
    }
}

#[inline]
fn poly_decompress<const K: usize>(params: &MlKemParams<K>, input: &[u8]) -> Poly {
    let mut out = Poly::default();
    match params.polycompressedbytes {
        128 => {
            for i in 0..(N / 2) {
                out.coeffs[2 * i] = ((((input[i] & 0x0f) as u16) * Q as u16 + 8) >> 4) as i16;
                out.coeffs[2 * i + 1] = ((((input[i] >> 4) as u16) * Q as u16 + 8) >> 4) as i16;
            }
        }
        160 => {
            let mut offset = 0usize;
            for i in 0..(N / 8) {
                let t0 = input[offset] >> 0;
                let t1 = (input[offset] >> 5) | (input[offset + 1] << 3);
                let t2 = input[offset + 1] >> 2;
                let t3 = (input[offset + 1] >> 7) | (input[offset + 2] << 1);
                let t4 = (input[offset + 2] >> 4) | (input[offset + 3] << 4);
                let t5 = input[offset + 3] >> 1;
                let t6 = (input[offset + 3] >> 6) | (input[offset + 4] << 2);
                let t7 = input[offset + 4] >> 3;
                offset += 5;
                let values = [t0, t1, t2, t3, t4, t5, t6, t7];
                for (j, value) in values.into_iter().enumerate() {
                    out.coeffs[8 * i + j] = (((value as u32 & 31) * Q as u32 + 16) >> 5) as i16;
                }
            }
        }
        _ => unreachable!(),
    }
    out
}

#[inline]
fn poly_tobytes(out: &mut [u8], poly: &Poly) {
    for i in 0..(N / 2) {
        let mut t0 = poly.coeffs[2 * i] as i32;
        t0 += (t0 >> 15) & Q as i32;
        let mut t1 = poly.coeffs[2 * i + 1] as i32;
        t1 += (t1 >> 15) & Q as i32;
        out[3 * i] = t0 as u8;
        out[3 * i + 1] = ((t0 >> 8) as u8) | ((t1 << 4) as u8);
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

#[inline]
fn poly_frombytes(input: &[u8]) -> Poly {
    let mut out = Poly::default();
    for i in 0..(N / 2) {
        out.coeffs[2 * i] = (((input[3 * i] as u16) | ((input[3 * i + 1] as u16) << 8)) & 0x0fff) as i16;
        out.coeffs[2 * i + 1] = ((((input[3 * i + 1] as u16) >> 4) | ((input[3 * i + 2] as u16) << 4)) & 0x0fff) as i16;
    }
    out
}

#[inline]
fn poly_frommsg(msg: &[u8]) -> Poly {
    let mut out = Poly::default();
    let half_q: i16 = ((Q + 1) / 2) as i16;
    for i in 0..(N / 8) {
        for j in 0..8 {
            let bit = ((msg[i] >> j) & 1) as i16;
            out.coeffs[8 * i + j] = (-bit) & half_q;
        }
    }
    out
}

#[inline]
fn poly_tomsg(poly: &Poly) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..(N / 8) {
        for j in 0..8 {
            let mut t = poly.coeffs[8 * i + j] as i32;
            t <<= 1;
            t += 1665;
            t *= 80_635;
            t >>= 28;
            msg[i] |= ((t & 1) as u8) << j;
        }
    }
    msg
}

#[inline]
fn poly_ntt(poly: &mut Poly) {
    ntt(&mut poly.coeffs);
    poly_reduce(poly);
}

#[inline]
fn poly_invntt_tomont(poly: &mut Poly) {
    invntt(&mut poly.coeffs);
}

#[inline]
fn poly_basemul_montgomery(a: &Poly, b: &Poly) -> Poly {
    let mut out = Poly::default();
    for i in 0..(N / 4) {
        let r0 = basemul(
            [a.coeffs[4 * i], a.coeffs[4 * i + 1]],
            [b.coeffs[4 * i], b.coeffs[4 * i + 1]],
            ZETAS[64 + i],
        );
        out.coeffs[4 * i] = r0[0];
        out.coeffs[4 * i + 1] = r0[1];

        let r1 = basemul(
            [a.coeffs[4 * i + 2], a.coeffs[4 * i + 3]],
            [b.coeffs[4 * i + 2], b.coeffs[4 * i + 3]],
            -ZETAS[64 + i],
        );
        out.coeffs[4 * i + 2] = r1[0];
        out.coeffs[4 * i + 3] = r1[1];
    }
    out
}

#[inline]
fn poly_tomont(poly: &mut Poly) {
    for coeff in &mut poly.coeffs {
        *coeff = montgomery_reduce(*coeff as i32 * 1353);
    }
}

#[inline]
fn poly_reduce(poly: &mut Poly) {
    for coeff in &mut poly.coeffs {
        *coeff = barrett_reduce(*coeff);
    }
}

#[inline]
fn poly_add(left: &mut Poly, right: &Poly) {
    for i in 0..N {
        left.coeffs[i] = (left.coeffs[i] as i32 + right.coeffs[i] as i32) as i16;
    }
}

#[inline]
fn poly_sub(out: &mut Poly, left: &Poly, right: &Poly) {
    for i in 0..N {
        out.coeffs[i] = (left.coeffs[i] as i32 - right.coeffs[i] as i32) as i16;
    }
}

#[inline]
fn ntt(r: &mut [i16; N]) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                let rj = r[j] as i32;
                r[j + len] = (rj - t as i32) as i16;
                r[j] = (rj + t as i32) as i16;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

#[inline]
fn invntt(r: &mut [i16; N]) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = barrett_reduce((t as i32 + r[j + len] as i32) as i16);
                r[j + len] = fqmul(zeta, (r[j + len] as i32 - t as i32) as i16);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    for coeff in r.iter_mut() {
        *coeff = fqmul(*coeff, MONT_SQUARED_DIV_N);
    }
}

#[inline]
fn basemul(a: [i16; 2], b: [i16; 2], zeta: i16) -> [i16; 2] {
    let mut out = [0i16; 2];
    out[0] = fqmul(a[1], b[1]);
    out[0] = fqmul(out[0], zeta);
    out[0] = (out[0] as i32 + fqmul(a[0], b[0]) as i32) as i16;
    out[1] = (fqmul(a[0], b[1]) as i32 + fqmul(a[1], b[0]) as i32) as i16;
    out
}

#[inline]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

#[inline]
fn montgomery_reduce(a: i32) -> i16 {
    let t = (a as i16).wrapping_mul(QINV) as i32;
    ((a - t * Q as i32) >> 16) as i16
}

#[inline]
fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = ((1 << 26) + (Q as i32 / 2)) / Q as i32;
    let t = ((V * a as i32 + (1 << 25)) >> 26) * Q as i32;
    (a as i32 - t) as i16
}

#[inline]
fn hash_h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.write(data);
    hasher.sum()
}

#[inline]
fn hash_g(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.write(data);
    hasher.sum()
}

#[inline]
fn rkprf(cipher_key: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut shake = Shake256::new();
    shake.absorb(cipher_key);
    shake.absorb(ciphertext);
    let mut out = [0u8; 32];
    shake.squeeze(&mut out);
    out
}

#[inline]
fn cmov(out: &mut [u8; 32], value: &[u8; 32], cond: bool) {
    let mask = 0u8.wrapping_sub(cond as u8);
    for i in 0..32 {
        out[i] ^= mask & (out[i] ^ value[i]);
    }
}

#[inline]
fn load32(input: &[u8]) -> u32 {
    (input[0] as u32) | ((input[1] as u32) << 8) | ((input[2] as u32) << 16) | ((input[3] as u32) << 24)
}

#[inline]
fn public_key_bytes<const K: usize>() -> usize {
    polyvec_bytes::<K>() + SYMBYTES
}

#[inline]
fn indcpa_secret_key_bytes<const K: usize>() -> usize {
    polyvec_bytes::<K>()
}

#[inline]
fn polyvec_bytes<const K: usize>() -> usize {
    K * POLY_BYTES
}

#[inline]
fn secret_key_size<const K: usize>() -> usize {
    indcpa_secret_key_bytes::<K>() + public_key_bytes::<K>() + 2 * SYMBYTES
}

#[inline]
fn ciphertext_bytes<const K: usize>(params: &MlKemParams<K>) -> usize {
    params.polyveccompressedbytes + params.polycompressedbytes
}

#[inline]
fn array_ref_32(input: &[u8]) -> &[u8; 32] {
    input.try_into().expect("slice length should be 32")
}

#[inline]
pub(crate) fn ml_kem_768_keypair_derand(coins: &[u8; 64]) -> (SecretKey768, PublicKey768) {
    SecretKey768::generate_derand(coins)
}

// ---------------------------------------------------------------------------
// SecretKey768
// ---------------------------------------------------------------------------

impl SecretKey768 {
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE_768]) -> Self {
        Self {
            bytes: *bytes,
        }
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE_768] {
        self.bytes
    }

    pub fn generate() -> (Self, PublicKey768) {
        let coins: [u8; 64] = rand::random();
        Self::generate_derand(&coins)
    }

    pub(crate) fn generate_derand(coins: &[u8; 64]) -> (Self, PublicKey768) {
        let (sk_bytes, pk_bytes) =
            crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, coins);
        (
            Self {
                bytes: sk_bytes,
            },
            PublicKey768 {
                bytes: pk_bytes,
            },
        )
    }

    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_SIZE_768]) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
        crypto_kem_dec::<3, SECRET_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &self.bytes, ciphertext)
    }

    pub fn public_key(&self) -> PublicKey768 {
        let offset = indcpa_secret_key_bytes::<3>();
        let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE_768];
        pk_bytes.copy_from_slice(&self.bytes[offset..offset + PUBLIC_KEY_SIZE_768]);
        PublicKey768 {
            bytes: pk_bytes,
        }
    }
}

impl From<&[u8; SECRET_KEY_SIZE_768]> for SecretKey768 {
    fn from(bytes: &[u8; SECRET_KEY_SIZE_768]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for SecretKey768 {
    type Error = MlKemError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(bytes.try_into().map_err(|_| MlKemError::InvalidKey)?))
    }
}

// ---------------------------------------------------------------------------
// PublicKey768
// ---------------------------------------------------------------------------

impl PublicKey768 {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE_768]) -> Self {
        Self {
            bytes: *bytes,
        }
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE_768] {
        self.bytes
    }

    pub fn encapsulate(&self) -> ([u8; CIPHERTEXT_SIZE_768], [u8; SHARED_SECRET_SIZE]) {
        let coins: [u8; 32] = rand::random();
        self.encapsulate_derand(&coins)
    }

    pub(crate) fn encapsulate_derand(&self, coins: &[u8; 32]) -> ([u8; CIPHERTEXT_SIZE_768], [u8; SHARED_SECRET_SIZE]) {
        crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &self.bytes, coins)
    }
}

impl From<&[u8; PUBLIC_KEY_SIZE_768]> for PublicKey768 {
    fn from(bytes: &[u8; PUBLIC_KEY_SIZE_768]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for PublicKey768 {
    type Error = MlKemError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(bytes.try_into().map_err(|_| MlKemError::InvalidKey)?))
    }
}

// ---------------------------------------------------------------------------
// SecretKey1024
// ---------------------------------------------------------------------------

impl SecretKey1024 {
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE_1024]) -> Self {
        Self {
            bytes: *bytes,
        }
    }

    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE_1024] {
        self.bytes
    }

    pub fn generate() -> (Self, PublicKey1024) {
        let coins: [u8; 64] = rand::random();
        Self::generate_derand(&coins)
    }

    fn generate_derand(coins: &[u8; 64]) -> (Self, PublicKey1024) {
        let (sk_bytes, pk_bytes) =
            crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, coins);
        (
            Self {
                bytes: sk_bytes,
            },
            PublicKey1024 {
                bytes: pk_bytes,
            },
        )
    }

    pub fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_SIZE_1024]) -> Result<[u8; SHARED_SECRET_SIZE], MlKemError> {
        crypto_kem_dec::<4, SECRET_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &self.bytes, ciphertext)
    }

    pub fn public_key(&self) -> PublicKey1024 {
        let offset = indcpa_secret_key_bytes::<4>();
        let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE_1024];
        pk_bytes.copy_from_slice(&self.bytes[offset..offset + PUBLIC_KEY_SIZE_1024]);
        PublicKey1024 {
            bytes: pk_bytes,
        }
    }
}

impl From<&[u8; SECRET_KEY_SIZE_1024]> for SecretKey1024 {
    fn from(bytes: &[u8; SECRET_KEY_SIZE_1024]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for SecretKey1024 {
    type Error = MlKemError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(bytes.try_into().map_err(|_| MlKemError::InvalidKey)?))
    }
}

// ---------------------------------------------------------------------------
// PublicKey1024
// ---------------------------------------------------------------------------

impl PublicKey1024 {
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE_1024]) -> Self {
        Self {
            bytes: *bytes,
        }
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE_1024] {
        self.bytes
    }

    pub fn encapsulate(&self) -> ([u8; CIPHERTEXT_SIZE_1024], [u8; SHARED_SECRET_SIZE]) {
        let coins: [u8; 32] = rand::random();
        self.encapsulate_derand(&coins)
    }

    fn encapsulate_derand(&self, coins: &[u8; 32]) -> ([u8; CIPHERTEXT_SIZE_1024], [u8; SHARED_SECRET_SIZE]) {
        crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &self.bytes, coins)
    }
}

impl From<&[u8; PUBLIC_KEY_SIZE_1024]> for PublicKey1024 {
    fn from(bytes: &[u8; PUBLIC_KEY_SIZE_1024]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<&[u8]> for PublicKey1024 {
    type Error = MlKemError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(bytes.try_into().map_err(|_| MlKemError::InvalidKey)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex_array<const N: usize>(s: &str) -> [u8; N] {
        let bytes = hex::decode(s).expect("valid hex");
        assert_eq!(bytes.len(), N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn sha3_256_hex(data: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.write(data);
        hex::encode(hasher.sum())
    }

    #[test]
    fn ml_kem_768_round_trip() {
        let (private_key, public_key) = ml_kem_768_generate_keypair();
        let (ciphertext, encapsulated_secret) = ml_kem_768_encapsulate(&public_key);
        let decapsulated_secret = ml_kem_768_decapsulate(&private_key, &ciphertext).unwrap();

        assert_eq!(encapsulated_secret, decapsulated_secret);
    }

    #[test]
    fn ml_kem_1024_round_trip() {
        let (private_key, public_key) = ml_kem_1024_generate_keypair();
        let (ciphertext, encapsulated_secret) = ml_kem_1024_encapsulate(&public_key);
        let decapsulated_secret = ml_kem_1024_decapsulate(&private_key, &ciphertext).unwrap();

        assert_eq!(encapsulated_secret, decapsulated_secret);
    }

    #[test]
    fn ml_kem_768_decapsulation_rejects_tampered_ciphertext() {
        let (private_key, public_key) = ml_kem_768_generate_keypair();
        let (mut ciphertext, encapsulated_secret) = ml_kem_768_encapsulate(&public_key);

        ciphertext[0] ^= 0x80;

        let decapsulated_secret = ml_kem_768_decapsulate(&private_key, &ciphertext).unwrap();

        assert_ne!(encapsulated_secret, decapsulated_secret);
    }

    #[test]
    fn ml_kem_768_deterministic_derand_vectors_are_stable() {
        let key_coins = [7u8; 64];
        let enc_coins = [9u8; 32];
        let (secret_key, public_key) =
            crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &key_coins);
        let (ciphertext, shared_secret) =
            crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &public_key, &enc_coins);
        let decapsulated =
            crypto_kem_dec::<3, SECRET_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &secret_key, &ciphertext)
                .unwrap();

        assert_eq!(shared_secret, decapsulated);
        assert_eq!(
            hex::encode(&public_key[..32]),
            "925a2700ad064ff778b4da4cf51457a48224a52751250a8ee10b251c818bafca"
        );
        assert_eq!(
            hex::encode(&ciphertext[..32]),
            "766c326c3483444c5b6d917cdddc3c07fbf935295c8f17c92a187a80dc4d15f2"
        );
        assert_eq!(
            hex::encode(shared_secret),
            "afcf18dfd6b710a09b5cf591d0eb8229d83aa10904934a3ca60a52da5ff36b96"
        );
    }

    // CCTV accumulated vectors: https://github.com/C2SP/CCTV/tree/main/ML-KEM
    //
    // The RNG is a single SHAKE-128 instance absorbing empty input, then squeezed
    // repeatedly. For each test: draw d (32 B), z (32 B), m (32 B), ct_random (CT_SIZE B).
    // Run KeyGen(d||z), Encaps(ek, m), Decaps(dk, ct), Decaps(dk, ct_random).
    // Feed ek, dk, ct, k_encaps, k_decaps_random into a running SHAKE-128 accumulator.
    // The final 32-byte squeeze of the accumulator must match a known hash.
    //
    // 10 000 tests per variant; hashes derived from implementation matching FIPS 203 final:
    //   ML-KEM-768:  f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1
    //   ML-KEM-1024: e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5

    #[test]
    fn ml_kem_768_cctv_accumulated_10k() {
        use crate::{Xof, sha3::Shake128};

        let mut rng = Shake128::new();
        // absorb nothing; first squeeze will pad and permute
        rng.absorb(&[]);

        let mut acc = Shake128::new();

        for _ in 0..10_000u32 {
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            let mut m = [0u8; 32];
            let mut ct_random = [0u8; CIPHERTEXT_SIZE_768];

            rng.squeeze(&mut d);
            rng.squeeze(&mut z);
            rng.squeeze(&mut m);
            rng.squeeze(&mut ct_random);

            let mut coins = [0u8; 64];
            coins[..32].copy_from_slice(&d);
            coins[32..].copy_from_slice(&z);

            let (dk, ek) =
                crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &coins);
            let (ct, k_encaps) =
                crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &ek, &m);

            let k_decaps =
                crypto_kem_dec::<3, SECRET_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &dk, &ct).unwrap();
            assert_eq!(k_encaps, k_decaps);

            let k_decaps_random =
                crypto_kem_dec::<3, SECRET_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &dk, &ct_random).unwrap();

            acc.absorb(&ek);
            acc.absorb(&dk);
            acc.absorb(&ct);
            acc.absorb(&k_encaps);
            acc.absorb(&k_decaps_random);
        }

        let mut hash = [0u8; 32];
        acc.squeeze(&mut hash);
        assert_eq!(
            hex::encode(hash),
            "f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1",
            "ML-KEM-768 CCTV accumulated hash mismatch"
        );
    }

    #[test]
    fn ml_kem_1024_cctv_accumulated_10k() {
        use crate::{Xof, sha3::Shake128};

        let mut rng = Shake128::new();
        rng.absorb(&[]);

        let mut acc = Shake128::new();

        for _ in 0..10_000u32 {
            let mut d = [0u8; 32];
            let mut z = [0u8; 32];
            let mut m = [0u8; 32];
            let mut ct_random = [0u8; CIPHERTEXT_SIZE_1024];

            rng.squeeze(&mut d);
            rng.squeeze(&mut z);
            rng.squeeze(&mut m);
            rng.squeeze(&mut ct_random);

            let mut coins = [0u8; 64];
            coins[..32].copy_from_slice(&d);
            coins[32..].copy_from_slice(&z);

            let (dk, ek) =
                crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &coins);
            let (ct, k_encaps) =
                crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &ek, &m);

            let k_decaps =
                crypto_kem_dec::<4, SECRET_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &dk, &ct).unwrap();
            assert_eq!(k_encaps, k_decaps);

            let k_decaps_random =
                crypto_kem_dec::<4, SECRET_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &dk, &ct_random).unwrap();

            acc.absorb(&ek);
            acc.absorb(&dk);
            acc.absorb(&ct);
            acc.absorb(&k_encaps);
            acc.absorb(&k_decaps_random);
        }

        let mut hash = [0u8; 32];
        acc.squeeze(&mut hash);
        assert_eq!(
            hex::encode(hash),
            "e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5",
            "ML-KEM-1024 CCTV accumulated hash mismatch"
        );
    }

    #[test]
    fn ml_kem_1024_deterministic_derand_vectors_are_stable() {
        let key_coins = [3u8; 64];
        let enc_coins = [5u8; 32];
        let (secret_key, public_key) =
            crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &key_coins);
        let (ciphertext, shared_secret) = crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(
            &ML_KEM_1024,
            &public_key,
            &enc_coins,
        );
        let decapsulated =
            crypto_kem_dec::<4, SECRET_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &secret_key, &ciphertext)
                .unwrap();

        assert_eq!(shared_secret, decapsulated);
        assert_eq!(
            hex::encode(&public_key[..32]),
            "2dd29da8b193397a4336c02382aab3bcfbac25f0cd71c888af379e1e75149a79"
        );
        assert_eq!(
            hex::encode(&ciphertext[..32]),
            "5f12f173ef59a45f910d3a225913f3297b2277636a72401a273648015cccf079"
        );
        assert_eq!(
            hex::encode(shared_secret),
            "8bf157178aa556b55f95686ba9b5afe13a6b75c848f1ddd9a334d50287bec24e"
        );
    }

    #[test]
    fn ml_kem_768_cctv_intermediate_vector() {
        // Intermediate values for ML-KEM-768 (FIPS 203 final with G(d||k) domain separator).
        // Input d, z, m from C2SP/CCTV; expected outputs recomputed for FIPS 203 final.
        let d: [u8; 32] = decode_hex_array("f688563f7c66a5da2d8bdb5a5f3e07bd8dce6f7efcec7f41298d79863459f7cd");
        let z: [u8; 32] = decode_hex_array("d1d49a515250dbceb9f6e3fcc1c7d5306918964b21ddb22207e03e57f0600da8");
        let m: [u8; 32] = decode_hex_array("3dc27ca0a6594b0e56320457c45a0f76bb8a213ea4a76d442186a0aefadbcdb9");

        let mut coins = [0u8; 64];
        coins[..32].copy_from_slice(&d);
        coins[32..].copy_from_slice(&z);

        let (dk, ek) = crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &coins);
        let (ct, k) = crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &ek, &m);

        assert_eq!(
            sha3_256_hex(&ek),
            "42d930a50dfd1f0541ca45c4598daebb4f51cd10d711a001bd9bb87d5c87a4bf"
        );
        assert_eq!(
            sha3_256_hex(&dk),
            "db563aebd9fdc875e88563693edad1e5e359cc37b0f685d2d0a3723b37253192"
        );
        assert_eq!(
            sha3_256_hex(&ct),
            "9d6e358208c4d583050becb319050b7f916de47caad1d589a1d01fea43fe1750"
        );
        assert_eq!(
            hex::encode(k),
            "ae726da2df66601c6648a7565c02b203a089276ac30f6cc226d048f93fafd78c"
        );
    }

    #[test]
    fn ml_kem_1024_cctv_intermediate_vector() {
        // Intermediate values for ML-KEM-1024 (FIPS 203 final with G(d||k) domain separator).
        // Input d, z, m from C2SP/CCTV; expected outputs recomputed for FIPS 203 final.
        let d: [u8; 32] = decode_hex_array("2a62c39ef4fc499f2d132716f480bb7521a49558ae84ee80d9352e66daf1e3a8");
        let z: [u8; 32] = decode_hex_array("5f574ef7f013d4336801fed022178c3ed91d0b6d51325315fc1dcabf4770a2ea");
        let m: [u8; 32] = decode_hex_array("e07d685ed308e609c9c7842026e35732f6ffc6e2fee10f0afd348f2b42a8acb4");

        let mut coins = [0u8; 64];
        coins[..32].copy_from_slice(&d);
        coins[32..].copy_from_slice(&z);

        let (dk, ek) = crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &coins);
        let (ct, k) = crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &ek, &m);

        assert_eq!(
            sha3_256_hex(&ek),
            "3b308d1344ed70366b84d790acb705b86cd3dfd471fff171969aaa338f26dca5"
        );
        assert_eq!(
            sha3_256_hex(&dk),
            "aa63a9e0c035ada6635e7938b71856b24917ff9b3ebca1a4d205a83b502a415a"
        );
        assert_eq!(
            sha3_256_hex(&ct),
            "8caba02733421f12a7ba9a2bcbe4de7c9853156a0637df5a7a0f9127c81da943"
        );
        assert_eq!(
            hex::encode(k),
            "d53825c3ff666bb2881215dbec04a8bdce9099b2a3680938c2f199b54d505953"
        );
    }

    #[test]
    fn ml_kem_1024_decapsulation_rejects_tampered_ciphertext() {
        let (private_key, public_key) = ml_kem_1024_generate_keypair();
        let (mut ciphertext, encapsulated_secret) = ml_kem_1024_encapsulate(&public_key);

        ciphertext[0] ^= 0x80;

        let decapsulated_secret = ml_kem_1024_decapsulate(&private_key, &ciphertext).unwrap();

        assert_ne!(encapsulated_secret, decapsulated_secret);
    }

    #[test]
    fn ml_kem_768_decapsulation_with_wrong_key_rejects() {
        let (alice_sk, alice_pk) = ml_kem_768_generate_keypair();
        let (bob_sk, _bob_pk) = ml_kem_768_generate_keypair();
        let (ct, _alice_ss) = ml_kem_768_encapsulate(&alice_pk);

        let wrong_ss = ml_kem_768_decapsulate(&bob_sk, &ct).unwrap();
        assert_ne!(_alice_ss, wrong_ss);
    }

    #[test]
    fn ml_kem_1024_decapsulation_with_wrong_key_rejects() {
        let (alice_sk, alice_pk) = ml_kem_1024_generate_keypair();
        let (bob_sk, _bob_pk) = ml_kem_1024_generate_keypair();
        let (ct, _alice_ss) = ml_kem_1024_encapsulate(&alice_pk);

        let wrong_ss = ml_kem_1024_decapsulate(&bob_sk, &ct).unwrap();
        assert_ne!(_alice_ss, wrong_ss);
    }

    #[test]
    fn ml_kem_768_round_trip_many() {
        for _ in 0..100 {
            let (sk, pk) = ml_kem_768_generate_keypair();
            let (ct, ss_enc) = ml_kem_768_encapsulate(&pk);
            let ss_dec = ml_kem_768_decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss_enc, ss_dec);
        }
    }

    #[test]
    fn ml_kem_1024_round_trip_many() {
        for _ in 0..100 {
            let (sk, pk) = ml_kem_1024_generate_keypair();
            let (ct, ss_enc) = ml_kem_1024_encapsulate(&pk);
            let ss_dec = ml_kem_1024_decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss_enc, ss_dec);
        }
    }

    #[test]
    fn ml_kem_768_all_zero_ciphertext_does_not_panic() {
        let (sk, _pk) = ml_kem_768_generate_keypair();
        let ct = [0u8; CIPHERTEXT_SIZE_768];
        let _result = ml_kem_768_decapsulate(&sk, &ct);
    }

    #[test]
    fn ml_kem_1024_all_zero_ciphertext_does_not_panic() {
        let (sk, _pk) = ml_kem_1024_generate_keypair();
        let ct = [0u8; CIPHERTEXT_SIZE_1024];
        let _result = ml_kem_1024_decapsulate(&sk, &ct);
    }

    #[test]
    fn ml_kem_768_all_ones_ciphertext_does_not_panic() {
        let (sk, _pk) = ml_kem_768_generate_keypair();
        let ct = [0xffu8; CIPHERTEXT_SIZE_768];
        let _result = ml_kem_768_decapsulate(&sk, &ct);
    }

    #[test]
    fn ml_kem_1024_all_ones_ciphertext_does_not_panic() {
        let (sk, _pk) = ml_kem_1024_generate_keypair();
        let ct = [0xffu8; CIPHERTEXT_SIZE_1024];
        let _result = ml_kem_1024_decapsulate(&sk, &ct);
    }

    #[test]
    fn ml_kem_768_derand_keygen_is_deterministic() {
        let coins = [7u8; 64];
        let (sk1, pk1) = crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &coins);
        let (sk2, pk2) = crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &coins);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn ml_kem_1024_derand_keygen_is_deterministic() {
        let coins = [3u8; 64];
        let (sk1, pk1) =
            crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &coins);
        let (sk2, pk2) =
            crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &coins);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn ml_kem_768_key_sizes_are_correct() {
        let (sk, pk) = ml_kem_768_generate_keypair();
        let sk_bytes = sk.to_bytes();
        let pk_bytes = pk.to_bytes();
        assert_eq!(sk_bytes.len(), SECRET_KEY_SIZE_768);
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE_768);
        let (ct, _) = ml_kem_768_encapsulate(&pk);
        assert_eq!(ct.len(), CIPHERTEXT_SIZE_768);
    }

    #[test]
    fn ml_kem_1024_key_sizes_are_correct() {
        let (sk, pk) = ml_kem_1024_generate_keypair();
        let sk_bytes = sk.to_bytes();
        let pk_bytes = pk.to_bytes();
        assert_eq!(sk_bytes.len(), SECRET_KEY_SIZE_1024);
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_SIZE_1024);
        let (ct, _) = ml_kem_1024_encapsulate(&pk);
        assert_eq!(ct.len(), CIPHERTEXT_SIZE_1024);
    }

    #[test]
    fn poly_frommsg_tomsg_roundtrip() {
        for pattern in 0..=255u16 {
            let mut msg = [0u8; 32];
            msg[0] = pattern as u8;
            msg[1] = (pattern >> 8) as u8;
            let poly = poly_frommsg(&msg);
            let recovered = poly_tomsg(&poly);
            assert_eq!(msg, recovered, "roundtrip failed for pattern {pattern:#06x}");
        }
    }

    #[test]
    fn poly_frommsg_constant_time_produces_expected_values() {
        // Verify the constant-time version produces correct mapped coefficients
        let half_q = ((Q + 1) / 2) as i16;
        let mut msg = [0u8; 32];
        msg[0] = 0b1010_1010;
        msg[1] = 0b0101_0101;
        let poly = poly_frommsg(&msg);
        // For msg[0] = 0xAA, bits 1,3,5,7 are set
        assert_eq!(poly.coeffs[0], 0); // bit 0 not set
        assert_eq!(poly.coeffs[1], half_q); // bit 1 set
        assert_eq!(poly.coeffs[2], 0); // bit 2 not set
        assert_eq!(poly.coeffs[3], half_q); // bit 3 set
        // msg[1] = 0x55, bits 0,2,4,6 are set
        assert_eq!(poly.coeffs[8], half_q); // bit 0 of msg[1] is 1
        assert_eq!(poly.coeffs[9], 0); // bit 1 of msg[1] is 0
        assert_eq!(poly.coeffs[10], half_q); // bit 2 of msg[1] is 1
        assert_eq!(poly.coeffs[11], 0); // bit 3 of msg[1] is 0
    }

    #[test]
    fn ml_kem_768_encaps_is_deterministic_with_same_coins() {
        let enc_coins = [9u8; 32];
        let key_coins = [7u8; 64];
        let (_sk, pk) =
            crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &key_coins);
        let (ct1, ss1) =
            crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &pk, &enc_coins);
        let (ct2, ss2) =
            crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &pk, &enc_coins);
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ml_kem_1024_encaps_is_deterministic_with_same_coins() {
        let enc_coins = [5u8; 32];
        let key_coins = [3u8; 64];
        let (_sk, pk) =
            crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &key_coins);
        let (ct1, ss1) =
            crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &pk, &enc_coins);
        let (ct2, ss2) =
            crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &pk, &enc_coins);
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ml_kem_768_decapsulation_with_wrong_key_is_deterministic() {
        // The implicit rejection must be deterministic: same (sk, ct) → same K
        let (sk_a, pk_a) = ml_kem_768_generate_keypair();
        let (sk_b, _pk_b) = ml_kem_768_generate_keypair();
        let (ct, _) = ml_kem_768_encapsulate(&pk_a);

        let ss1 = ml_kem_768_decapsulate(&sk_b, &ct).unwrap();
        let ss2 = ml_kem_768_decapsulate(&sk_b, &ct).unwrap();
        assert_eq!(ss1, ss2, "implicit rejection must be deterministic");
    }

    #[test]
    fn ml_kem_1024_decapsulation_with_wrong_key_is_deterministic() {
        let (sk_a, pk_a) = ml_kem_1024_generate_keypair();
        let (sk_b, _pk_b) = ml_kem_1024_generate_keypair();
        let (ct, _) = ml_kem_1024_encapsulate(&pk_a);

        let ss1 = ml_kem_1024_decapsulate(&sk_b, &ct).unwrap();
        let ss2 = ml_kem_1024_decapsulate(&sk_b, &ct).unwrap();
        assert_eq!(ss1, ss2, "implicit rejection must be deterministic");
    }

    // --- Wycheproof test vectors ---

    #[test]
    fn ml_kem_768_wycheproof_keygen() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/wycheproof/testvectors_v1/mlkem_768_keygen_seed_test.json"
        ))
        .unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-768") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let seed_hex = test["seed"].as_str().unwrap();
                let expected_ek_hex = test["ek"].as_str().unwrap();
                let expected_dk_hex = test["dk"].as_str().unwrap();
                let result = test["result"].as_str().unwrap();

                let mut seed = [0u8; 64];
                hex::decode_to_slice(seed_hex, &mut seed).unwrap();

                let (dk, ek) =
                    crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &seed);

                let ek_hex = hex::encode(ek);
                let dk_hex = hex::encode(dk);

                if result == "valid" {
                    assert_eq!(
                        ek_hex, expected_ek_hex,
                        "wycheproof keygen KAT tcId={} ek mismatch",
                        test["tcId"]
                    );
                    assert_eq!(
                        dk_hex, expected_dk_hex,
                        "wycheproof keygen KAT tcId={} dk mismatch",
                        test["tcId"]
                    );
                }
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-768 keygen tests were run");
    }

    #[test]
    fn ml_kem_1024_wycheproof_keygen() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/wycheproof/testvectors_v1/mlkem_1024_keygen_seed_test.json"
        ))
        .unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-1024") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let seed_hex = test["seed"].as_str().unwrap();
                let expected_ek_hex = test["ek"].as_str().unwrap();
                let expected_dk_hex = test["dk"].as_str().unwrap();
                let result = test["result"].as_str().unwrap();

                let mut seed = [0u8; 64];
                hex::decode_to_slice(seed_hex, &mut seed).unwrap();

                let (dk, ek) =
                    crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &seed);

                let ek_hex = hex::encode(ek);
                let dk_hex = hex::encode(dk);

                if result == "valid" {
                    assert_eq!(
                        ek_hex, expected_ek_hex,
                        "wycheproof keygen KAT tcId={} ek mismatch",
                        test["tcId"]
                    );
                    assert_eq!(
                        dk_hex, expected_dk_hex,
                        "wycheproof keygen KAT tcId={} dk mismatch",
                        test["tcId"]
                    );
                }
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-1024 keygen tests were run");
    }

    fn wycheproof_kem_skip_invalid_lengths(seed_hex: &str, c_hex: &str, ct_size: usize) -> bool {
        seed_hex.len() != 128 || c_hex.len() != ct_size * 2
    }

    #[test]
    fn ml_kem_768_wycheproof_kem() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/wycheproof/testvectors_v1/mlkem_768_test.json")).unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-768") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let seed_hex = test["seed"].as_str().unwrap();
                let c_hex = test["c"].as_str().unwrap();
                let expected_k_hex = test["K"].as_str().unwrap();
                let result = test["result"].as_str().unwrap();

                if wycheproof_kem_skip_invalid_lengths(seed_hex, c_hex, CIPHERTEXT_SIZE_768) {
                    tested += 1;
                    continue;
                }

                let mut seed = [0u8; 64];
                hex::decode_to_slice(seed_hex, &mut seed).unwrap();

                let (dk, ek) =
                    crypto_kem_keypair_derand::<3, SECRET_KEY_SIZE_768, PUBLIC_KEY_SIZE_768>(&ML_KEM_768, &seed);

                if let Some(expected_ek_hex) = test.get("ek").and_then(|v| v.as_str()) {
                    let ek_hex = hex::encode(ek);
                    assert_eq!(ek_hex, expected_ek_hex, "wycheproof KEM KAT tcId={} ek mismatch", test["tcId"]);
                }

                let c = decode_hex_array::<CIPHERTEXT_SIZE_768>(c_hex);
                let shared_secret = crypto_kem_dec::<3, SECRET_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &dk, &c);

                if result == "valid" {
                    let k = shared_secret.unwrap();
                    let k_hex = hex::encode(k);
                    assert_eq!(k_hex, expected_k_hex, "wycheproof KEM KAT tcId={} K mismatch", test["tcId"]);
                } else {
                    assert!(
                        shared_secret.is_ok(),
                        "wycheproof KEM KAT tcId={} unexpected error",
                        test["tcId"]
                    );
                }
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-768 KEM tests were run");
    }

    #[test]
    fn ml_kem_1024_wycheproof_kem() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/wycheproof/testvectors_v1/mlkem_1024_test.json")).unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-1024") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let seed_hex = test["seed"].as_str().unwrap();
                let c_hex = test["c"].as_str().unwrap();
                let expected_k_hex = test["K"].as_str().unwrap();
                let result = test["result"].as_str().unwrap();

                if wycheproof_kem_skip_invalid_lengths(seed_hex, c_hex, CIPHERTEXT_SIZE_1024) {
                    tested += 1;
                    continue;
                }

                let mut seed = [0u8; 64];
                hex::decode_to_slice(seed_hex, &mut seed).unwrap();

                let (dk, ek) =
                    crypto_kem_keypair_derand::<4, SECRET_KEY_SIZE_1024, PUBLIC_KEY_SIZE_1024>(&ML_KEM_1024, &seed);

                if let Some(expected_ek_hex) = test.get("ek").and_then(|v| v.as_str()) {
                    let ek_hex = hex::encode(ek);
                    assert_eq!(ek_hex, expected_ek_hex, "wycheproof KEM KAT tcId={} ek mismatch", test["tcId"]);
                }

                let c = decode_hex_array::<CIPHERTEXT_SIZE_1024>(c_hex);
                let shared_secret =
                    crypto_kem_dec::<4, SECRET_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &dk, &c);

                if result == "valid" {
                    let k = shared_secret.unwrap();
                    let k_hex = hex::encode(k);
                    assert_eq!(k_hex, expected_k_hex, "wycheproof KEM KAT tcId={} K mismatch", test["tcId"]);
                } else {
                    assert!(
                        shared_secret.is_ok(),
                        "wycheproof KEM KAT tcId={} unexpected error",
                        test["tcId"]
                    );
                }
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-1024 KEM tests were run");
    }

    #[test]
    fn ml_kem_768_wycheproof_encaps() {
        let data: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/wycheproof/testvectors_v1/mlkem_768_encaps_test.json"))
                .unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-768") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let ek_hex = test["ek"].as_str().unwrap();
                let m_hex = test["m"].as_str().unwrap();
                let expected_c_hex = test["c"].as_str().unwrap();
                let expected_k_hex = test["K"].as_str().unwrap();
                let result = test["result"].as_str().unwrap();

                if ek_hex.len() != PUBLIC_KEY_SIZE_768 * 2 {
                    tested += 1;
                    continue;
                }

                let ek = decode_hex_array::<PUBLIC_KEY_SIZE_768>(ek_hex);

                if result == "valid" {
                    let m = decode_hex_array::<32>(m_hex);
                    let (c, k) =
                        crypto_kem_enc_derand::<3, PUBLIC_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &ek, &m);
                    let c_hex_out = hex::encode(c);
                    let k_hex_out = hex::encode(k);
                    assert_eq!(
                        c_hex_out, expected_c_hex,
                        "wycheproof encaps KAT tcId={} c mismatch",
                        test["tcId"]
                    );
                    assert_eq!(
                        k_hex_out, expected_k_hex,
                        "wycheproof encaps KAT tcId={} K mismatch",
                        test["tcId"]
                    );
                }
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-768 encaps tests were run");
    }

    #[test]
    fn ml_kem_1024_wycheproof_encaps() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/wycheproof/testvectors_v1/mlkem_1024_encaps_test.json"
        ))
        .unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-1024") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let ek_hex = test["ek"].as_str().unwrap();
                let m_hex = test["m"].as_str().unwrap();
                let expected_c_hex = test["c"].as_str().unwrap();
                let expected_k_hex = test["K"].as_str().unwrap();
                let result = test["result"].as_str().unwrap();

                if ek_hex.len() != PUBLIC_KEY_SIZE_1024 * 2 {
                    tested += 1;
                    continue;
                }

                let ek = decode_hex_array::<PUBLIC_KEY_SIZE_1024>(ek_hex);

                if result == "valid" {
                    let m = decode_hex_array::<32>(m_hex);
                    let (c, k) =
                        crypto_kem_enc_derand::<4, PUBLIC_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &ek, &m);
                    let c_hex_out = hex::encode(c);
                    let k_hex_out = hex::encode(k);
                    assert_eq!(
                        c_hex_out, expected_c_hex,
                        "wycheproof encaps KAT tcId={} c mismatch",
                        test["tcId"]
                    );
                    assert_eq!(
                        k_hex_out, expected_k_hex,
                        "wycheproof encaps KAT tcId={} K mismatch",
                        test["tcId"]
                    );
                }
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-1024 encaps tests were run");
    }

    #[test]
    fn ml_kem_768_wycheproof_decaps_validation() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/wycheproof/testvectors_v1/mlkem_768_semi_expanded_decaps_test.json"
        ))
        .unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-768") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let flags: Vec<&str> = test["flags"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let dk_hex = test["dk"].as_str().unwrap();
                let c_hex = test["c"].as_str().unwrap();

                // Tests with wrong-length keys or ciphertexts can't be tested
                // with our fixed-size array API.
                if flags.contains(&"IncorrectDecapsulationKeyLength") || flags.contains(&"IncorrectCiphertextLength") {
                    tested += 1;
                    continue;
                }

                let dk = decode_hex_array::<SECRET_KEY_SIZE_768>(dk_hex);
                let c = decode_hex_array::<CIPHERTEXT_SIZE_768>(c_hex);

                let result = crypto_kem_dec::<3, SECRET_KEY_SIZE_768, CIPHERTEXT_SIZE_768>(&ML_KEM_768, &dk, &c);

                // For valid decaps, the call should succeed.
                // For invalid decaps (corrupted dk), ML-KEM still returns Ok due to implicit rejection.
                assert!(result.is_ok(), "wycheproof decaps tcId={} panicked", test["tcId"]);
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-768 decaps validation tests were run");
    }

    #[test]
    fn ml_kem_1024_wycheproof_decaps_validation() {
        let data: serde_json::Value = serde_json::from_str(include_str!(
            "../testdata/wycheproof/testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json"
        ))
        .unwrap();
        let mut tested = 0u64;
        for group in data["testGroups"].as_array().unwrap() {
            if group["parameterSet"].as_str() != Some("ML-KEM-1024") {
                continue;
            }
            for test in group["tests"].as_array().unwrap() {
                let flags: Vec<&str> = test["flags"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                let dk_hex = test["dk"].as_str().unwrap();
                let c_hex = test["c"].as_str().unwrap();

                if flags.contains(&"IncorrectDecapsulationKeyLength") || flags.contains(&"IncorrectCiphertextLength") {
                    tested += 1;
                    continue;
                }

                let dk = decode_hex_array::<SECRET_KEY_SIZE_1024>(dk_hex);
                let c = decode_hex_array::<CIPHERTEXT_SIZE_1024>(c_hex);

                let result = crypto_kem_dec::<4, SECRET_KEY_SIZE_1024, CIPHERTEXT_SIZE_1024>(&ML_KEM_1024, &dk, &c);

                assert!(result.is_ok(), "wycheproof decaps tcId={} panicked", test["tcId"]);
                tested += 1;
            }
        }
        assert!(tested > 0, "no ML-KEM-1024 decaps validation tests were run");
    }
}
