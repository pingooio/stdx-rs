/// Pure-Rust AES-256 block cipher and AES-256-GCM authenticated encryption.
///
/// Design notes:
/// - Favours speed over constant-time execution (table-driven S-box lookups).
/// - The x86-64 code path (aes256_amd64) dispatches to AES-NI + PCLMULQDQ
///   at runtime and is used whenever the required CPU features are present.
use crate::EllipticCurveError;

// ── AES constants ─────────────────────────────────────────────────────────────

#[rustfmt::skip]
pub(crate) const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[rustfmt::skip]
const SBOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Round constants for AES key expansion (RCON[1..10]).
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// ── AES-256 key schedule ───────────────────────────────────────────────────────

/// AES-256 expanded key: 15 round keys × 16 bytes = 240 bytes.
pub(crate) type RoundKeys = [[u8; 16]; 15];

#[inline(always)]
fn rot_word(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

#[inline(always)]
fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [
        SBOX[w[0] as usize],
        SBOX[w[1] as usize],
        SBOX[w[2] as usize],
        SBOX[w[3] as usize],
    ]
}

/// Expand a 256-bit key into 15 AES round keys (FIPS 197 §5.2, Nk=8, Nr=14).
pub(crate) fn key_expand(key: &[u8; 32]) -> RoundKeys {
    // W[0..60] – 60 words of 4 bytes each
    let mut w = [[0u8; 4]; 60];

    for i in 0..8 {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }

    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / 8];
        } else if i % 8 == 4 {
            temp = sub_word(temp);
        }
        w[i] = [
            w[i - 8][0] ^ temp[0],
            w[i - 8][1] ^ temp[1],
            w[i - 8][2] ^ temp[2],
            w[i - 8][3] ^ temp[3],
        ];
    }

    let mut rk = [[0u8; 16]; 15];
    for i in 0..15 {
        for j in 0..4 {
            rk[i][4 * j..4 * j + 4].copy_from_slice(&w[4 * i + j]);
        }
    }
    rk
}

// ── AES block cipher (encrypt / decrypt) ─────────────────────────────────────

#[inline(always)]
fn xtime(a: u8) -> u8 {
    let hi = a & 0x80;
    let b = a << 1;
    if hi != 0 { b ^ 0x1b } else { b }
}

#[inline(always)]
fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

#[inline(always)]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

/// AES ShiftRows: row r is shifted left by r positions (column-major layout).
#[inline(always)]
fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // row 0: no shift
    // row 1: shift left 1
    s[1] = t[5];
    s[5] = t[9];
    s[9] = t[13];
    s[13] = t[1];
    // row 2: shift left 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // row 3: shift left 3
    s[3] = t[15];
    s[7] = t[3];
    s[11] = t[7];
    s[15] = t[11];
}

/// AES MixColumns on a single column (bytes at indices col*4 .. col*4+3).
#[inline(always)]
fn mix_col(s: &mut [u8; 16], col: usize) {
    let i = col * 4;
    let s0 = s[i];
    let s1 = s[i + 1];
    let s2 = s[i + 2];
    let s3 = s[i + 3];
    s[i] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
    s[i + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
    s[i + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
    s[i + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
}

#[inline(always)]
fn mix_columns(state: &mut [u8; 16]) {
    mix_col(state, 0);
    mix_col(state, 1);
    mix_col(state, 2);
    mix_col(state, 3);
}

// ── Decryption helpers ────────────────────────────────────────────────────────

#[inline(always)]
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = SBOX_INV[*b as usize];
    }
}

#[inline(always)]
fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // row 1: shift right 1
    s[1] = t[13];
    s[5] = t[1];
    s[9] = t[5];
    s[13] = t[9];
    // row 2: shift right 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // row 3: shift right 3
    s[3] = t[7];
    s[7] = t[11];
    s[11] = t[15];
    s[15] = t[3];
}

/// Multiply in GF(2^8) mod 0x11b.
#[inline(always)]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

#[inline(always)]
fn inv_mix_col(s: &mut [u8; 16], col: usize) {
    let i = col * 4;
    let s0 = s[i];
    let s1 = s[i + 1];
    let s2 = s[i + 2];
    let s3 = s[i + 3];
    s[i] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
    s[i + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
    s[i + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
    s[i + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
}

#[inline(always)]
fn inv_mix_columns(state: &mut [u8; 16]) {
    inv_mix_col(state, 0);
    inv_mix_col(state, 1);
    inv_mix_col(state, 2);
    inv_mix_col(state, 3);
}

// ── Pure-Rust AES-256 block encrypt / decrypt ─────────────────────────────────

/// Encrypt one 16-byte block (pure Rust, FIPS 197 §5.1).
pub(crate) fn encrypt_block(rk: &RoundKeys, block: &[u8; 16]) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, &rk[0]);
    for r in 1..14 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &rk[r]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &rk[14]);
    state
}

/// Decrypt one 16-byte block (pure Rust, FIPS 197 §5.3).
pub(crate) fn decrypt_block(rk: &RoundKeys, block: &[u8; 16]) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, &rk[14]);
    for r in (1..14).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &rk[r]);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &rk[0]);
    state
}

// ── GF(2^128) arithmetic for GHASH ───────────────────────────────────────────
//
// Representation: a 128-bit GCM element is stored as `u128` where
//   – bit 127 (MSB of u128) = coefficient of x^0  (= MSB of the first byte)
//   – bit 0   (LSB of u128) = coefficient of x^127 (= LSB of the last byte)
//
// This matches `u128::from_be_bytes(block)` exactly.
//
// Multiplication by x in this field:
//   All coefficients shift up by one degree.  If the old x^127 coefficient
//   (u128 bit 0) was 1, we reduce by x^128 ≡ x^7 + x^2 + x + 1, i.e.
//   XOR with 0xe1 << 120.

#[inline(always)]
fn gf128_mul_x(v: u128) -> u128 {
    let carry = v & 1; // coefficient of x^127 before shift
    let shifted = v >> 1;
    if carry != 0 {
        shifted ^ (0xe1u128 << 120)
    } else {
        shifted
    }
}

/// Multiply two GCM elements in GF(2^128).
/// Both operands and the result use big-endian byte layout (NIST SP 800-38D).
pub(crate) fn gf128_mul(x: &[u8; 16], h: &[u8; 16]) -> [u8; 16] {
    let x_val = u128::from_be_bytes(*x);
    let h_val = u128::from_be_bytes(*h);
    let mut z = 0u128;
    let mut v = h_val;

    // Iterate over bits of X from MSB (bit 127 = x_0 = coeff of x^0) down
    // to LSB (bit 0 = x_127 = coeff of x^127).
    // v holds H * α^(127-k) at iteration k.
    for k in (0..128u32).rev() {
        if (x_val >> k) & 1 == 1 {
            z ^= v;
        }
        v = gf128_mul_x(v);
    }
    z.to_be_bytes()
}

// ── GHASH ─────────────────────────────────────────────────────────────────────

/// Update a running GHASH state by XOR-ing one 16-byte block and multiplying
/// by H (NIST SP 800-38D §6.4).
#[inline(always)]
fn ghash_block(state: &mut [u8; 16], h: &[u8; 16], block: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= block[i];
    }
    let new = gf128_mul(state, h);
    *state = new;
}

/// Feed an arbitrarily-sized byte slice into GHASH, zero-padding the last
/// block if necessary.
fn ghash_update(state: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut chunks = data.chunks_exact(16);
    for chunk in chunks.by_ref() {
        let block: [u8; 16] = chunk.try_into().unwrap();
        ghash_block(state, h, &block);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut padded = [0u8; 16];
        padded[..rem.len()].copy_from_slice(rem);
        ghash_block(state, h, &padded);
    }
}

// ── AES-256-GCM ───────────────────────────────────────────────────────────────

/// Increment the 32-bit big-endian counter stored in bytes [12..16].
#[inline(always)]
fn ctr_inc(counter: &mut [u8; 16]) {
    let c = u32::from_be_bytes(counter[12..16].try_into().unwrap());
    counter[12..16].copy_from_slice(&c.wrapping_add(1).to_be_bytes());
}

/// XOR `in_out` with the AES-CTR keystream produced by the given counter,
/// starting at the supplied counter value (incremented for each block).
fn ctr_encrypt(rk: &RoundKeys, in_out: &mut [u8], counter: &mut [u8; 16]) {
    let n = in_out.len();
    let mut i = 0;
    while i + 16 <= n {
        let ks = encrypt_block(rk, counter);
        for k in 0..16 {
            in_out[i + k] ^= ks[k];
        }
        ctr_inc(counter);
        i += 16;
    }
    if i < n {
        let ks = encrypt_block(rk, counter);
        for k in 0..n - i {
            in_out[i + k] ^= ks[k];
        }
        ctr_inc(counter);
    }
}

/// Compute the GCM authentication tag (pure Rust).
///
/// `h`   – GHASH subkey = AES_K(0^128)
/// `ej0` – E(J0) used to mask the final GHASH output
fn compute_tag(h: &[u8; 16], aad: &[u8], ciphertext: &[u8], ej0: &[u8; 16]) -> [u8; 16] {
    let mut state = [0u8; 16];

    ghash_update(&mut state, h, aad);
    ghash_update(&mut state, h, ciphertext);

    // Length block: len(A) || len(C) in bits as two 64-bit big-endian integers
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_block(&mut state, h, &len_block);

    // Tag = GHASH ^ E(J0)
    for i in 0..16 {
        state[i] ^= ej0[i];
    }
    state
}

// ── Public struct ─────────────────────────────────────────────────────────────

/// AES-256-GCM authenticated cipher (pure-Rust implementation).
///
/// On x86-64 machines with AES-NI + PCLMULQDQ the methods automatically
/// dispatch to the hardware-accelerated path (see `aes256_amd64`).
pub struct Aes256Gcm {
    pub(crate) key: [u8; 32],
    pub(crate) round_keys: RoundKeys,
}

impl Aes256Gcm {
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 12;

    /// Create a new `Aes256Gcm` instance from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256Gcm {
            key: *key,
            round_keys: key_expand(key),
        }
    }

    /// Encrypt `in_out` in-place and return the 16-byte authentication tag.
    ///
    /// * `nonce` – 12-byte nonce (must be unique per (key, plaintext) pair)
    /// * `aad`   – additional authenticated data (not encrypted)
    #[inline]
    #[allow(unreachable_code)]
    pub fn encrypt_in_place_detached(&self, in_out: &mut [u8], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
        // we assume that AES instructions are always present on aarch64
        #[cfg(target_arch = "aarch64")]
        {
            use crate::aes::aes256_arm64::encrypt_armv8;
            unsafe { return encrypt_armv8(&self.key, in_out, nonce, aad) }
        }

        // runtime detection of CPU features for x86 and x86_64 when the "std" feature is enabled
        #[cfg(feature = "std")]
        {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::aes::aes256_amd64::encrypt_aesni;
                if std::arch::is_x86_feature_detected!("aes")
                    && std::arch::is_x86_feature_detected!("pclmulqdq")
                    && std::arch::is_x86_feature_detected!("ssse3")
                    && std::arch::is_x86_feature_detected!("sse4.1")
                {
                    unsafe { return encrypt_aesni(&self.key, in_out, nonce, aad) }
                }
            }
        }

        #[cfg(not(feature = "std"))]
        {
            #[cfg(enable = "aes,pclmulqdq,ssse3,sse4.1,sse2")]
            {
                use crate::aes::aes256_amd64::encrypt_aesni;
                unsafe {
                    return encrypt_aesni(&self.key, in_out, nonce, aad);
                }
            }
        }

        self.encrypt_in_place_detached_soft(in_out, nonce, aad)
    }

    /// Decrypt `in_out` in-place and verify the authentication tag.
    ///
    /// Returns `Err(Error::Unspecified)` if the tag does not match.
    #[inline]
    #[allow(unreachable_code)]
    pub fn decrypt_in_place_detached(
        &self,
        in_out: &mut [u8],
        tag: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<(), EllipticCurveError> {
        // we assume that AES instructions are always present on aarch64
        #[cfg(target_arch = "aarch64")]
        {
            use crate::aes::aes256_arm64::decrypt_armv8;
            unsafe { return decrypt_armv8(&self.key, in_out, tag, nonce, aad) }
        }

        #[cfg(feature = "std")]
        {
            #[cfg(target_arch = "x86_64")]
            {
                use crate::aes::aes256_amd64::decrypt_aesni;
                if std::arch::is_x86_feature_detected!("aes")
                    && std::arch::is_x86_feature_detected!("pclmulqdq")
                    && std::arch::is_x86_feature_detected!("ssse3")
                    && std::arch::is_x86_feature_detected!("sse4.1")
                {
                    unsafe { return decrypt_aesni(&self.key, in_out, tag, nonce, aad) }
                }
            }
        }

        #[cfg(not(feature = "std"))]
        {
            #[cfg(enable = "aes,pclmulqdq,ssse3,sse4.1,sse2")]
            {
                use crate::aes::aes256_amd64::decrypt_aesni;
                unsafe {
                    return decrypt_aesni(&self.key, in_out, tag, nonce, aad);
                }
            }
        }

        self.decrypt_in_place_detached_soft(in_out, tag, nonce, aad)
    }

    /// Pure-Rust encrypt implementation.
    pub(crate) fn encrypt_in_place_detached_soft(&self, in_out: &mut [u8], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
        let rk = &self.round_keys;
        let h = encrypt_block(rk, &[0u8; 16]);

        // J0 = nonce || 0x00000001
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let ej0 = encrypt_block(rk, &j0);

        // CTR starts at J0 + 1 (= nonce || 0x00000002)
        let mut ctr = j0;
        ctr_inc(&mut ctr);

        ctr_encrypt(rk, in_out, &mut ctr);
        compute_tag(&h, aad, in_out, &ej0)
    }

    /// Pure-Rust decrypt implementation.
    pub(crate) fn decrypt_in_place_detached_soft(
        &self,
        in_out: &mut [u8],
        tag: &[u8; 16],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<(), EllipticCurveError> {
        let rk = &self.round_keys;
        let h = encrypt_block(rk, &[0u8; 16]);

        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;

        let ej0 = encrypt_block(rk, &j0);

        // Verify tag before decrypting (authenticate-then-decrypt ordering)
        let expected_tag = compute_tag(&h, aad, in_out, &ej0);

        // Constant-time comparison to avoid timing oracle
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= expected_tag[i] ^ tag[i];
        }
        if diff != 0 {
            return Err(EllipticCurveError::Unspecified);
        }

        let mut ctr = j0;
        ctr_inc(&mut ctr);
        ctr_encrypt(rk, in_out, &mut ctr);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: Add tests:
    // https://www.tuhs.org/cgi-bin/utree.pl?file=OpenBSD-4.6/regress/sys/crypto/aes/vectors/ecbnk48.txt
    // https://android.googlesource.com/platform/libcore/+/1db6bf619611525020518a180f0ee82c8cd50af2/luni/src/test/resources/crypto/aes-cbc.csv

    fn hb<const N: usize>(s: &str) -> [u8; N] {
        let v = hex::decode(s).unwrap();
        assert_eq!(v.len(), N, "wrong hex length for '{s}'");
        v.try_into().unwrap()
    }

    // ── AES-256 block cipher (FIPS 197 Appendix B + C) ────────────────────────

    /// NIST FIPS 197 Appendix B – AES-128 vectors (re-confirmed in AES-256 test)
    /// These come from FIPS 197 Appendix C.3 (AES-256).
    #[test]
    fn fips197_aes256_encrypt() {
        // FIPS 197 Appendix C.3
        let key: [u8; 32] = hb("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt: [u8; 16] = hb("00112233445566778899aabbccddeeff");
        let ct_expected: [u8; 16] = hb("8ea2b7ca516745bfeafc49904b496089");

        let rk = key_expand(&key);
        let ct = encrypt_block(&rk, &pt);
        assert_eq!(ct, ct_expected);
    }

    #[test]
    fn fips197_aes256_decrypt() {
        let key: [u8; 32] = hb("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let ct: [u8; 16] = hb("8ea2b7ca516745bfeafc49904b496089");
        let pt_expected: [u8; 16] = hb("00112233445566778899aabbccddeeff");

        let rk = key_expand(&key);
        let pt = decrypt_block(&rk, &ct);
        assert_eq!(pt, pt_expected);
    }

    /// NIST SP 800-38A ECB-AES256 vectors (F.1.5 / F.1.6).
    #[test]
    fn nist_sp800_38a_aes256_ecb() {
        let key: [u8; 32] = hb("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");

        let blocks: &[([u8; 16], [u8; 16])] = &[
            (hb("6bc1bee22e409f96e93d7e117393172a"), hb("f3eed1bdb5d2a03c064b5a7e3db181f8")),
            (hb("ae2d8a571e03ac9c9eb76fac45af8e51"), hb("591ccb10d410ed26dc5ba74a31362870")),
            (hb("30c81c46a35ce411e5fbc1191a0a52ef"), hb("b6ed21b99ca6f4f9f153e7b1beafed1d")),
            (hb("f69f2445df4f9b17ad2b417be66c3710"), hb("23304b7a39f9f3ff067d8d8f9e24ecc7")),
        ];

        let rk = key_expand(&key);
        for (pt, ct) in blocks {
            assert_eq!(encrypt_block(&rk, pt), *ct);
            assert_eq!(decrypt_block(&rk, ct), *pt);
        }
    }

    /// NIST Known Answer Test (KAT) – a few AES-256 single-block KATs.
    #[test]
    fn aes256_kat_vectors() {
        // key, plaintext, ciphertext
        let vectors: &[([u8; 32], [u8; 16], [u8; 16])] = &[
            // All-zero key and plaintext
            ([0u8; 32], [0u8; 16], hb("dc95c078a2408989ad48a21492842087")),
            // Key = 0x01..0x20, PT = 0
            (
                hb("0101010101010101010101010101010101010101010101010101010101010101"),
                [0u8; 16],
                hb("7298caa565031eadc6ce23d23ea66378"),
            ),
            // Key = 0xff..0xff
            ([0xff; 32], [0u8; 16], hb("4bf85f1b5d54adbc307b0a048389adcb")),
        ];

        for (key, pt, ct_expected) in vectors {
            let rk = key_expand(key);
            let ct = encrypt_block(&rk, pt);
            assert_eq!(ct, *ct_expected, "key={}", hex::encode(key));
            let pt2 = decrypt_block(&rk, &ct);
            assert_eq!(pt2, *pt, "round-trip failed");
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip_random() {
        let key: [u8; 32] = hb("deadbeefcafebabedeadbeefcafebabe0011223344556677deadbeefcafebabe");
        let rk = key_expand(&key);
        for seed in 0u8..=255 {
            let pt = [seed; 16];
            let ct = encrypt_block(&rk, &pt);
            let pt2 = decrypt_block(&rk, &ct);
            assert_eq!(pt2, pt);
        }
    }

    // ── GF(2^128) multiplication ───────────────────────────────────────────────

    #[test]
    fn gf128_mul_zero() {
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
        ];
        let zero = [0u8; 16];
        assert_eq!(gf128_mul(&zero, &h), zero);
        assert_eq!(gf128_mul(&h, &zero), zero);
    }

    #[test]
    fn gf128_mul_commutativity() {
        let a: [u8; 16] = hb("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let b: [u8; 16] = hb("feedfacedeadbeeffeedfacedeadbeef");
        assert_eq!(gf128_mul(&a, &b), gf128_mul(&b, &a));
    }

    // H and X from GCM Test Case 2 (NIST SP 800-38D Appendix B).
    #[test]
    fn gf128_mul_nist_tv2() {
        // H = AES_K(0) for K = all-zeros 128-bit key → irrelevant for 256-bit here,
        // but we test the raw GF multiplication with known values from NIST test vectors.
        // From TC2: H = 66e94bd4ef8a2c3b884cfa59ca342b2e
        //           X (first GHASH input) = feedfacedeadbeeffeedfacedeadbeef
        // Expected product from the NIST spec reference implementation.
        let h: [u8; 16] = hb("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let x: [u8; 16] = hb("feedfacedeadbeeffeedfacedeadbeef");
        // Computed offline with a reference implementation.
        let expected: [u8; 16] = hb("88eddca9968dec8b9c952d6ae0290a82");
        assert_eq!(gf128_mul(&x, &h), expected);
    }

    // ── AES-256-GCM (NIST SP 800-38D Appendix B and additional vectors) ────────

    struct GcmVector {
        key: &'static str,
        nonce: &'static str,
        pt: &'static str,
        aad: &'static str,
        ct: &'static str,
        tag: &'static str,
    }

    include!("aes256_gcm_vectors.rs");

    /// NIST SP 800-38D Appendix B – test cases for AES-256-GCM.
    ///
    /// These are the canonical NIST test vectors.  Each vector specifies:
    ///   key, IV (nonce), plaintext, additional authenticated data (AAD),
    ///   expected ciphertext, and expected authentication tag.
    const NIST_GCM_VECTORS: &[GcmVector] = &[
        // Test Case 13 – empty plaintext, empty AAD, 256-bit key
        GcmVector {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            pt: "",
            aad: "",
            ct: "",
            tag: "530f8afbc74536b9a963b4f1c4cb738b",
        },
        // Test Case 14 – plaintext = 16 zero bytes, empty AAD, 256-bit key
        GcmVector {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            pt: "00000000000000000000000000000000",
            aad: "",
            ct: "cea7403d4d606b6e074ec5d3baf39d18",
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        // Test Case 15 – from NIST SP 800-38D
        GcmVector {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            nonce: "cafebabefacedbaddecaf888",
            pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            aad: "",
            ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            tag: "b094dac5d93471bdec1a502270e3cc6c",
        },
        // Test Case 16 – with AAD
        GcmVector {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            nonce: "cafebabefacedbaddecaf888",
            pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            tag: "76fc6ece0f4e1768cddf8853bb2d551b",
        },
        // Additional: Google Tink / BoringSSL reference vector (AES-256-GCM)
        GcmVector {
            key: "0e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0cc",
            nonce: "12153524c0895e81b2c28465",
            pt: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002",
            aad: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            ct: "d017a35445d3b3d2a9faf8699b12114551c325744fd174cb53950ab4e33d4cfe90b3c39f9ff0f681b5339437476603bc",
            tag: "4122cd6a136671d8fe83937439623596",
        },
        // Additional: Google Wycheproof AES-GCM vectors (valid, keySize=256).
        GcmVector {
            key: "92ace3e348cd821092cd921aa3546374299ab46209691bc28b8752d17f123c20",
            nonce: "00112233445566778899aabb",
            pt: "00010203040506070809",
            aad: "00000000ffffffff",
            ct: "e27abdd2d2a53d2f136b",
            tag: "9a4a2579529301bcfb71c78d4060f52c",
        },
        GcmVector {
            key: "cc56b680552eb75008f5484b4cb803fa5063ebd6eab91f6ab6aef4916a766273",
            nonce: "99e23ec48985bccdeeab60f1",
            pt: "2a",
            aad: "",
            ct: "06",
            tag: "633c1e9703ef744ffffb40edf9d14355",
        },
        // Additional: pyca/cryptography CAVS AES-GCM vectors (gcmEncryptExtIV256.rsp).
        GcmVector {
            key: "78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223",
            nonce: "d79cf22d504cc793c3fb6c8a",
            pt: "",
            aad: "b96baa8c1c75a671bfb2d08d06be5f36",
            ct: "",
            tag: "3e5d486aa2e30b22e040b85723a06e76",
        },
    ];

    fn run_gcm_vector_soft(v: &GcmVector) {
        let key: [u8; 32] = hb(v.key);
        let nonce: [u8; 12] = hb(v.nonce);
        let pt = hex::decode(v.pt).unwrap();
        let aad = hex::decode(v.aad).unwrap();
        let expected_ct = hex::decode(v.ct).unwrap();
        let expected_tag: [u8; 16] = hb(v.tag);

        let cipher = Aes256Gcm::new(&key);

        // Encrypt
        let mut buf = pt.clone();
        let tag = cipher.encrypt_in_place_detached_soft(&mut buf, &nonce, &aad);
        assert_eq!(buf, expected_ct, "ciphertext mismatch for key={}", v.key);
        assert_eq!(tag, expected_tag, "tag mismatch for key={}", v.key);

        // Decrypt
        let mut buf2 = expected_ct.clone();
        cipher
            .decrypt_in_place_detached_soft(&mut buf2, &expected_tag, &nonce, &aad)
            .expect("decrypt failed");
        assert_eq!(buf2, pt, "plaintext mismatch after decrypt for key={}", v.key);
    }

    #[test]
    fn nist_gcm_test_vectors_soft() {
        for v in NIST_GCM_VECTORS.iter().chain(EXTRA_GCM_VECTORS.iter()) {
            run_gcm_vector_soft(v);
        }
    }

    #[test]
    fn gcm_tag_mismatch_returns_error_soft() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let cipher = Aes256Gcm::new(&key);
        let mut buf = b"hello world".to_vec();
        let tag = cipher.encrypt_in_place_detached_soft(&mut buf, &nonce, &[]);
        // Flip one tag byte
        let mut bad_tag = tag;
        bad_tag[0] ^= 0xff;
        let mut buf2 = buf.clone();
        assert!(
            cipher
                .decrypt_in_place_detached_soft(&mut buf2, &bad_tag, &nonce, &[])
                .is_err()
        );
    }

    #[test]
    fn gcm_encrypt_decrypt_large_soft() {
        let key = [0xabu8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"additional data";
        let plaintext: Vec<u8> = (0u8..=255u8).cycle().take(1024).collect();

        let cipher = Aes256Gcm::new(&key);
        let mut buf = plaintext.clone();
        let tag = cipher.encrypt_in_place_detached_soft(&mut buf, &nonce, aad);
        cipher
            .decrypt_in_place_detached_soft(&mut buf, &tag, &nonce, aad)
            .expect("decrypt failed");
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn gcm_empty_plaintext_nonempty_aad_soft() {
        let key: [u8; 32] = hb("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce: [u8; 12] = hb("cafebabefacedbaddecaf888");
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeef").unwrap();
        let cipher = Aes256Gcm::new(&key);
        let mut buf: Vec<u8> = vec![];
        let tag = cipher.encrypt_in_place_detached_soft(&mut buf, &nonce, &aad);
        cipher
            .decrypt_in_place_detached_soft(&mut buf, &tag, &nonce, &aad)
            .expect("decrypt failed");
    }

    // ── Dispatching wrappers (use hardware path when available) ───────────────

    #[test]
    fn nist_gcm_test_vectors_dispatch() {
        for v in NIST_GCM_VECTORS.iter().chain(EXTRA_GCM_VECTORS.iter()) {
            let key: [u8; 32] = hb(v.key);
            let nonce: [u8; 12] = hb(v.nonce);
            let pt = hex::decode(v.pt).unwrap();
            let aad = hex::decode(v.aad).unwrap();
            let expected_ct = hex::decode(v.ct).unwrap();
            let expected_tag: [u8; 16] = hb(v.tag);

            let cipher = Aes256Gcm::new(&key);

            let mut buf = pt.clone();
            let tag = cipher.encrypt_in_place_detached(&mut buf, &nonce, &aad);
            assert_eq!(buf, expected_ct, "dispatch ciphertext mismatch key={}", v.key);
            assert_eq!(tag, expected_tag, "dispatch tag mismatch key={}", v.key);

            let mut buf2 = expected_ct.clone();
            cipher
                .decrypt_in_place_detached(&mut buf2, &expected_tag, &nonce, &aad)
                .expect("dispatch decrypt failed");
            assert_eq!(buf2, pt);
        }
    }
}
