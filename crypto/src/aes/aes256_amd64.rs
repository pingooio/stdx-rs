/// x86-64 AES-256-GCM using AES-NI and PCLMULQDQ intrinsics.
///
/// ## Representations
///
/// GCM uses a big-endian polynomial ring: bit 0 of byte 0 = coefficient of x^127.
/// PCLMULQDQ uses little-endian polynomial order: bit 0 of SSE lane = coefficient of x^0.
///
/// To bridge this, every GCM block is **byte-reversed** with `_mm_shuffle_epi8`
/// before any carry-less multiplication.  After byte-reversal, SSE bit k equals the
/// GCM coefficient of x^k, so PCLMULQDQ directly computes GCM multiplication and
/// the reduction polynomial is the natural P(x) = x^128 + x^7 + x^2 + x + 1.
///
/// ## Reduction
///
/// Given a 256-bit Karatsuba product (product_lo, product_hi) the reduction uses
/// three PCLMULQDQ instructions (two for the two 64-bit halves of product_hi, one
/// for the seven-bit overflow of the second multiplication):
///
///   T1 = hi_lo  × 0x87           → 71-bit result (bits 0..70)
///   T2 = hi_hi  × 0x87           → 71-bit result (bits 0..70)
///   T3 = T2_hi7 × 0x87           → ≤14-bit result (second-step overflow)
///   out = lo ⊕ T1 ⊕ (T2 << 64) ⊕ T3
///
/// ## Feature detection
///
/// `try_encrypt_in_place_detached` / `try_decrypt_in_place_detached` check for
/// `aes + pclmulqdq + ssse3 + sse4.1` at runtime (via `is_x86_feature_detected!`)
/// and return `None` when any feature is absent, causing the caller to fall back
/// to the pure-Rust implementation.
#[allow(clippy::many_single_char_names)]
use core::arch::x86_64::*;

use crate::Error;
use super::aes256::gf128_mul;

// ── Public API ────────────────────────────────────────────────────────────────

/// Attempt to encrypt using AES-NI + PCLMULQDQ.  Returns `None` when the CPU
/// does not support the required feature set.
#[inline]
pub(crate) fn try_encrypt_in_place_detached(
    key: &[u8; 32],
    in_out: &mut [u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Option<[u8; 16]> {
    if !have_features() {
        return None;
    }
    // SAFETY: all required CPU features were just confirmed.
    Some(unsafe { encrypt_aesni(key, in_out, nonce, aad) })
}

/// Attempt to decrypt using AES-NI + PCLMULQDQ.  Returns `None` when the CPU
/// does not support the required feature set.
#[inline]
pub(crate) fn try_decrypt_in_place_detached(
    key: &[u8; 32],
    in_out: &mut [u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Option<Result<(), Error>> {
    if !have_features() {
        return None;
    }
    // SAFETY: all required CPU features were just confirmed.
    Some(unsafe { decrypt_aesni(key, in_out, tag, nonce, aad) })
}

// ── Runtime feature detection ─────────────────────────────────────────────────

#[inline]
fn have_features() -> bool {
    std::arch::is_x86_feature_detected!("aes")
        && std::arch::is_x86_feature_detected!("pclmulqdq")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

// ── 128-bit byte-swap ─────────────────────────────────────────────────────────
//
// Reverses the byte order of a 128-bit SSE value using SSSE3 `pshufb`.
// This maps each GCM block so that SSE bit k = GCM coefficient of x^k,
// making PCLMULQDQ directly compute GCM field multiplication.

#[target_feature(enable = "ssse3")]
#[inline]
unsafe fn bswap128(x: __m128i) -> __m128i {
    // _mm_set_epi8 takes args from HIGH byte to LOW byte.
    // This mask reverses byte order: dst byte 15 = src byte 0, …, dst byte 0 = src byte 15.
    let mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    _mm_shuffle_epi8(x, mask)
}

// ── AES-256 key expansion (AES-NI) ────────────────────────────────────────────

/// 15 round-keys for AES-256 (Nr = 14 rounds + 1 whitening key).
type RoundKeysNi = [__m128i; 15];

/// One "even" step of the AES-256 key schedule.
#[target_feature(enable = "aes,sse2")]
#[inline]
unsafe fn ks_even(mut prev: __m128i, mut rcon_word: __m128i) -> __m128i {
    // AESKEYGENASSIST result: we want the high 32-bit word, rotated and sub'd.
    rcon_word = _mm_shuffle_epi32(rcon_word, 0xff); // broadcast word 3
    prev = _mm_xor_si128(prev, _mm_slli_si128(prev, 4));
    prev = _mm_xor_si128(prev, _mm_slli_si128(prev, 4));
    prev = _mm_xor_si128(prev, _mm_slli_si128(prev, 4));
    _mm_xor_si128(prev, rcon_word)
}

/// One "odd" step of the AES-256 key schedule.
#[target_feature(enable = "aes,sse2")]
#[inline]
unsafe fn ks_odd(mut prev: __m128i, mut sub_word: __m128i) -> __m128i {
    sub_word = _mm_shuffle_epi32(sub_word, 0xaa); // broadcast word 2
    prev = _mm_xor_si128(prev, _mm_slli_si128(prev, 4));
    prev = _mm_xor_si128(prev, _mm_slli_si128(prev, 4));
    prev = _mm_xor_si128(prev, _mm_slli_si128(prev, 4));
    _mm_xor_si128(prev, sub_word)
}

/// Expand a 256-bit key into the 15 AES-256 round keys using AES-NI.
#[target_feature(enable = "aes,sse2")]
unsafe fn key_expand_aesni(key: &[u8; 32]) -> RoundKeysNi {
    let mut rk = [_mm_setzero_si128(); 15];
    rk[0] = _mm_loadu_si128(key.as_ptr().cast());
    rk[1] = _mm_loadu_si128(key.as_ptr().add(16).cast());

    macro_rules! rnd {
        ($i:expr, $rcon:expr) => {{
            let t = _mm_aeskeygenassist_si128(rk[$i + 1], $rcon);
            rk[$i + 2] = ks_even(rk[$i], t);
            if $i + 3 < 15 {
                let t2 = _mm_aeskeygenassist_si128(rk[$i + 2], 0x00);
                rk[$i + 3] = ks_odd(rk[$i + 1], t2);
            }
        }};
    }

    rnd!(0, 0x01);
    rnd!(2, 0x02);
    rnd!(4, 0x04);
    rnd!(6, 0x08);
    rnd!(8, 0x10);
    rnd!(10, 0x20);
    // Final even round key (index 14):
    let t = _mm_aeskeygenassist_si128(rk[13], 0x40);
    rk[14] = ks_even(rk[12], t);

    rk
}

// ── AES-256 block encrypt (AES-NI) ────────────────────────────────────────────

#[target_feature(enable = "aes,sse2")]
#[inline]
unsafe fn aes256_enc(rk: &RoundKeysNi, block: __m128i) -> __m128i {
    let mut b = _mm_xor_si128(block, rk[0]);
    b = _mm_aesenc_si128(b, rk[1]);
    b = _mm_aesenc_si128(b, rk[2]);
    b = _mm_aesenc_si128(b, rk[3]);
    b = _mm_aesenc_si128(b, rk[4]);
    b = _mm_aesenc_si128(b, rk[5]);
    b = _mm_aesenc_si128(b, rk[6]);
    b = _mm_aesenc_si128(b, rk[7]);
    b = _mm_aesenc_si128(b, rk[8]);
    b = _mm_aesenc_si128(b, rk[9]);
    b = _mm_aesenc_si128(b, rk[10]);
    b = _mm_aesenc_si128(b, rk[11]);
    b = _mm_aesenc_si128(b, rk[12]);
    b = _mm_aesenc_si128(b, rk[13]);
    _mm_aesenclast_si128(b, rk[14])
}

// ── GF(2^128) multiplication via PCLMULQDQ ────────────────────────────────────

/// Reduce a 256-bit carry-less product `(lo, hi)` modulo P = x^128+x^7+x^2+x+1.
///
/// Both operands are in the byte-swapped domain (SSE bit k = GCM coefficient of x^k).
/// The polynomial constant 0x87 = x^7+x^2+x+1.
///
/// Algorithm (three PCLMULQDQ):
///   T1 = hi_lo64  × 0x87   → ≤71 bits
///   T2 = hi_hi64  × 0x87   → ≤71 bits
///   T3 = T2[64..70] × 0x87 → ≤14 bits  (second-step overflow)
///   out = lo ⊕ T1 ⊕ (T2 << 64) ⊕ T3
#[target_feature(enable = "pclmulqdq,sse2")]
#[inline]
unsafe fn gcm_reduce(lo: __m128i, hi: __m128i) -> __m128i {
    let poly = _mm_set_epi64x(0, 0x87_i64); // low64 = 0x87

    // T1: hi_lo64 × 0x87  (imm8=0x00 → low64(hi) × low64(poly))
    let t1 = _mm_clmulepi64_si128(hi, poly, 0x00);

    // T2: hi_hi64 × 0x87  (imm8=0x01 → high64(hi) × low64(poly))
    let t2 = _mm_clmulepi64_si128(hi, poly, 0x01);

    // Fold T2 into bits 64..127 of the accumulator.
    // _mm_slli_si128 shifts by bytes: 8-byte left shift puts T2[0..63] at positions 64..127.
    let t2_lo = _mm_slli_si128(t2, 8); // T2 bits 0..63 → positions 64..127
    let t2_hi = _mm_srli_si128(t2, 8); // T2 bits 64..70 → positions 0..6 (overflow)

    // Second reduction: T2's overflow bits (≤7 bits) × 0x87 → ≤14 bits
    let t3 = _mm_clmulepi64_si128(t2_hi, poly, 0x00);

    _mm_xor_si128(lo, _mm_xor_si128(t1, _mm_xor_si128(t2_lo, t3)))
}

/// Multiply two GCM elements (both already byte-swapped) using Karatsuba + PCLMULQDQ.
#[target_feature(enable = "pclmulqdq,sse2")]
#[inline]
unsafe fn clmul_gcm(a: __m128i, b: __m128i) -> __m128i {
    // Karatsuba: a*b = a_hi*b_hi*x^128 + ((a_lo^a_hi)*(b_lo^b_hi) ^ a_lo*b_lo ^ a_hi*b_hi)*x^64 + a_lo*b_lo
    let lo = _mm_clmulepi64_si128(a, b, 0x00); // a_lo × b_lo
    let hi = _mm_clmulepi64_si128(a, b, 0x11); // a_hi × b_hi

    // Swap 64-bit halves to compute (a_lo ^ a_hi) and (b_lo ^ b_hi)
    let a_swap = _mm_shuffle_epi32(a, 0x4e); // swap 64-bit lanes
    let b_swap = _mm_shuffle_epi32(b, 0x4e);
    let mid = _mm_clmulepi64_si128(
        _mm_xor_si128(a, a_swap), // a_lo ^ a_hi in both lanes
        _mm_xor_si128(b, b_swap), // b_lo ^ b_hi in both lanes
        0x00,
    );

    // Recombine Karatsuba terms
    let mid_true = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    let product_lo = _mm_xor_si128(lo, _mm_slli_si128(mid_true, 8));
    let product_hi = _mm_xor_si128(hi, _mm_srli_si128(mid_true, 8));

    gcm_reduce(product_lo, product_hi)
}

// ── GHASH ─────────────────────────────────────────────────────────────────────
//
// The GHASH state and hash key H are kept in byte-swapped form throughout.
// Input blocks are byte-swapped before being XOR'd into the state.
// After all blocks are processed, the state is byte-swapped back to obtain
// the GCM GHASH result.

/// Feed a byte slice into the running GHASH state.
///
/// `state` and `h` are in the byte-swapped domain.
/// Each input block is byte-swapped before processing.
#[target_feature(enable = "pclmulqdq,ssse3,sse2")]
unsafe fn ghash_update(mut state: __m128i, h: __m128i, data: &[u8]) -> __m128i {
    let n = data.len();
    let mut i = 0;

    while i + 16 <= n {
        let block = bswap128(_mm_loadu_si128(data.as_ptr().add(i).cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h);
        i += 16;
    }

    if i < n {
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&data[i..]);
        let block = bswap128(_mm_loadu_si128(buf.as_ptr().cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h);
    }

    state
}

// ── Counter helpers ───────────────────────────────────────────────────────────

/// Increment the big-endian 32-bit counter stored in bytes 12..15 of the block.
#[target_feature(enable = "sse2")]
#[inline]
unsafe fn ctr_inc(ctr: __m128i) -> __m128i {
    let mut buf = [0u8; 16];
    _mm_storeu_si128(buf.as_mut_ptr().cast(), ctr);
    let c = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let c1 = c.wrapping_add(1);
    buf[12] = (c1 >> 24) as u8;
    buf[13] = (c1 >> 16) as u8;
    buf[14] = (c1 >> 8) as u8;
    buf[15] = c1 as u8;
    _mm_loadu_si128(buf.as_ptr().cast())
}

// ── AES-256-GCM encrypt ───────────────────────────────────────────────────────

#[target_feature(enable = "aes,pclmulqdq,ssse3,sse4.1,sse2")]
unsafe fn encrypt_aesni(key: &[u8; 32], in_out: &mut [u8], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    let rk = key_expand_aesni(key);

    // H = AES_K(0^128) in natural byte order.
    let h_xmm = aes256_enc(&rk, _mm_setzero_si128());
    let mut h = [0u8; 16];
    _mm_storeu_si128(h.as_mut_ptr().cast(), h_xmm);

    // J0 = nonce ∥ 0x00000001
    let mut j0_bytes = [0u8; 16];
    j0_bytes[..12].copy_from_slice(nonce);
    j0_bytes[15] = 0x01;
    let j0 = _mm_loadu_si128(j0_bytes.as_ptr().cast());
    let ej0 = aes256_enc(&rk, j0); // E(J0) in natural byte order
    let mut ej0_bytes = [0u8; 16];
    _mm_storeu_si128(ej0_bytes.as_mut_ptr().cast(), ej0);

    // CTR: starts at J0 + 1 = nonce ∥ 0x00000002
    let mut ctr = ctr_inc(j0);
    let n = in_out.len();
    let mut i = 0;

    while i + 16 <= n {
        let ks = aes256_enc(&rk, ctr);
        let ct = _mm_xor_si128(_mm_loadu_si128(in_out.as_ptr().add(i).cast()), ks);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), ct);
        ctr = ctr_inc(ctr);
        i += 16;
    }
    if i < n {
        let ks = aes256_enc(&rk, ctr);
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&in_out[i..]);
        let ct = _mm_xor_si128(_mm_loadu_si128(buf.as_ptr().cast()), ks);
        let mut out_buf = [0u8; 16];
        _mm_storeu_si128(out_buf.as_mut_ptr().cast(), ct);
        in_out[i..].copy_from_slice(&out_buf[..n - i]);
    }

    compute_tag_scalar(&h, aad, in_out, &ej0_bytes)
}

// ── AES-256-GCM decrypt ───────────────────────────────────────────────────────

#[target_feature(enable = "aes,pclmulqdq,ssse3,sse4.1,sse2")]
unsafe fn decrypt_aesni(
    key: &[u8; 32],
    in_out: &mut [u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<(), Error> {
    let rk = key_expand_aesni(key);

    let h_xmm = aes256_enc(&rk, _mm_setzero_si128());
    let mut h = [0u8; 16];
    _mm_storeu_si128(h.as_mut_ptr().cast(), h_xmm);

    let mut j0_bytes = [0u8; 16];
    j0_bytes[..12].copy_from_slice(nonce);
    j0_bytes[15] = 0x01;
    let j0 = _mm_loadu_si128(j0_bytes.as_ptr().cast());
    let ej0 = aes256_enc(&rk, j0);
    let mut ej0_bytes = [0u8; 16];
    _mm_storeu_si128(ej0_bytes.as_mut_ptr().cast(), ej0);

    // Authenticate-then-decrypt: verify tag first.
    let computed_tag = compute_tag_scalar(&h, aad, in_out, &ej0_bytes);

    // Constant-time comparison
    let mut diff = 0u8;
    for k in 0..16 {
        diff |= computed_tag[k] ^ tag[k];
    }
    if diff != 0 {
        return Err(Error::Unspecified);
    }

    // CTR decrypt
    let mut ctr = ctr_inc(j0);
    let n = in_out.len();
    let mut i = 0;

    while i + 16 <= n {
        let ks = aes256_enc(&rk, ctr);
        let pt = _mm_xor_si128(_mm_loadu_si128(in_out.as_ptr().add(i).cast()), ks);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), pt);
        ctr = ctr_inc(ctr);
        i += 16;
    }
    if i < n {
        let ks = aes256_enc(&rk, ctr);
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&in_out[i..]);
        let pt = _mm_xor_si128(_mm_loadu_si128(buf.as_ptr().cast()), ks);
        let mut out_buf = [0u8; 16];
        _mm_storeu_si128(out_buf.as_mut_ptr().cast(), pt);
        in_out[i..].copy_from_slice(&out_buf[..n - i]);
    }

    Ok(())
}

#[inline]
fn ghash_block_scalar(state: &mut [u8; 16], h: &[u8; 16], block: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= block[i];
    }
    *state = gf128_mul(state, h);
}

#[inline]
fn ghash_update_scalar(state: &mut [u8; 16], h: &[u8; 16], data: &[u8]) {
    let mut chunks = data.chunks_exact(16);
    for chunk in chunks.by_ref() {
        let block: [u8; 16] = chunk.try_into().unwrap();
        ghash_block_scalar(state, h, &block);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut padded = [0u8; 16];
        padded[..rem.len()].copy_from_slice(rem);
        ghash_block_scalar(state, h, &padded);
    }
}

#[inline]
fn compute_tag_scalar(h: &[u8; 16], aad: &[u8], ciphertext: &[u8], ej0: &[u8; 16]) -> [u8; 16] {
    let mut state = [0u8; 16];

    ghash_update_scalar(&mut state, h, aad);
    ghash_update_scalar(&mut state, h, ciphertext);

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_block_scalar(&mut state, h, &len_block);

    for i in 0..16 {
        state[i] ^= ej0[i];
    }
    state
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s = s.replace(|c: char| c.is_whitespace(), "");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hb<const N: usize>(s: &str) -> [u8; N] {
        h(s).try_into().unwrap()
    }

    macro_rules! skip_unless_aesni {
        () => {
            if !have_features() {
                eprintln!("Skipping AES-NI test: CPU features not available");
                return;
            }
        };
    }

    // ── AES-NI key-schedule matches pure-Rust schedule ────────────────────────

    #[test]
    fn aesni_key_expand_matches_soft() {
        skip_unless_aesni!();

        let key: [u8; 32] = hb("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let soft_rk = crate::aes::aes256::key_expand(&key);
        let ni_rk = unsafe { key_expand_aesni(&key) };

        for i in 0..15 {
            let mut ni_bytes = [0u8; 16];
            unsafe { _mm_storeu_si128(ni_bytes.as_mut_ptr().cast(), ni_rk[i]) };
            assert_eq!(soft_rk[i], ni_bytes, "round key {i} mismatch");
        }
    }

    // ── AES-NI block encrypt matches NIST SP 800-38A ECB-AES256 ──────────────

    #[test]
    fn aesni_ecb_vectors() {
        skip_unless_aesni!();

        let key: [u8; 32] = hb("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let ni_rk = unsafe { key_expand_aesni(&key) };

        let vectors: &[([u8; 16], [u8; 16])] = &[
            (hb("6bc1bee22e409f96e93d7e117393172a"), hb("f3eed1bdb5d2a03c064b5a7e3db181f8")),
            (hb("ae2d8a571e03ac9c9eb76fac45af8e51"), hb("591ccb10d410ed26dc5ba74a31362870")),
            (hb("30c81c46a35ce411e5fbc1191a0a52ef"), hb("b6ed21b99ca6f4f9f153e7b1beafed1d")),
            (hb("f69f2445df4f9b17ad2b417be66c3710"), hb("23304b7a39f9f3ff067d8d8f9e24ecc7")),
        ];

        for (pt, ct_exp) in vectors {
            let pt_xmm = unsafe { _mm_loadu_si128(pt.as_ptr().cast()) };
            let ct_xmm = unsafe { aes256_enc(&ni_rk, pt_xmm) };
            let mut ni_ct = [0u8; 16];
            unsafe { _mm_storeu_si128(ni_ct.as_mut_ptr().cast(), ct_xmm) };
            assert_eq!(ni_ct, *ct_exp);
        }
    }

    // ── GHASH / GCM test vectors (NIST SP 800-38D + others) ──────────────────

    struct GcmVec {
        key: &'static str,
        nonce: &'static str,
        pt: &'static str,
        aad: &'static str,
        ct: &'static str,
        tag: &'static str,
    }

    const VECTORS: &[GcmVec] = &[
        // NIST SP 800-38D TC13 – empty PT, empty AAD
        GcmVec {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            pt: "",
            aad: "",
            ct: "",
            tag: "530f8afbc74536b9a963b4f1c4cb738b",
        },
        // NIST SP 800-38D TC14 – 16-byte PT, no AAD
        GcmVec {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            pt: "00000000000000000000000000000000",
            aad: "",
            ct: "cea7403d4d606b6e074ec5d3baf39d18",
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        // NIST SP 800-38D TC15 – 60-byte PT, no AAD
        GcmVec {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            nonce: "cafebabefacedbaddecaf888",
            pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            aad: "",
            ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            tag: "b094dac5d93471bdec1a502270e3cc6c",
        },
        // NIST SP 800-38D TC16 – 60-byte PT, 20-byte AAD
        GcmVec {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            nonce: "cafebabefacedbaddecaf888",
            pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            tag: "76fc6ece0f4e1768cddf8853bb2d551b",
        },
        // Google Tink / BoringSSL AES-256-GCM reference vector
        GcmVec {
            key: "0e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0cc",
            nonce: "12153524c0895e81b2c28465",
            pt: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002",
            aad: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            ct: "d017a35445d3b3d2a9faf8699b12114551c325744fd174cb53950ab4e33d4cfe90b3c39f9ff0f681b5339437476603bc",
            tag: "4122cd6a136671d8fe83937439623596",
        },
    ];

    #[test]
    fn nist_gcm_aesni() {
        skip_unless_aesni!();

        for v in VECTORS {
            let key: [u8; 32] = hb(v.key);
            let nonce: [u8; 12] = hb(v.nonce);
            let pt = h(v.pt);
            let aad = h(v.aad);
            let exp_ct = h(v.ct);
            let exp_tag: [u8; 16] = hb(v.tag);

            let mut buf = pt.clone();
            let tag = unsafe { encrypt_aesni(&key, &mut buf, &nonce, &aad) };
            assert_eq!(buf, exp_ct, "AES-NI ct  key={}", v.key);
            assert_eq!(tag, exp_tag, "AES-NI tag key={}", v.key);

            let mut buf2 = exp_ct.clone();
            unsafe { decrypt_aesni(&key, &mut buf2, &exp_tag, &nonce, &aad) }.expect("AES-NI decrypt failed");
            assert_eq!(buf2, pt, "AES-NI pt  key={}", v.key);
        }
    }

    #[test]
    fn aesni_tag_mismatch() {
        skip_unless_aesni!();

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut buf = b"hello world".to_vec();
        let tag = unsafe { encrypt_aesni(&key, &mut buf, &nonce, &[]) };
        let mut bad = tag;
        bad[7] ^= 0x01;
        assert!(unsafe { decrypt_aesni(&key, &mut buf.clone(), &bad, &nonce, &[]) }.is_err());
    }

    #[test]
    fn aesni_matches_soft() {
        skip_unless_aesni!();

        let key: [u8; 32] = hb("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce: [u8; 12] = hb("cafebabefacedbaddecaf888");
        let aad = h("feedfacedeadbeeffeedfacedeadbeef");
        let pt: Vec<u8> = (0u8..=255u8).collect();

        let cipher = crate::aes::aes256::Aes256Gcm::new(&key);
        let mut soft_buf = pt.clone();
        let soft_tag = cipher.encrypt_in_place_detached_soft(&mut soft_buf, &nonce, &aad);

        let mut ni_buf = pt.clone();
        let ni_tag = unsafe { encrypt_aesni(&key, &mut ni_buf, &nonce, &aad) };

        assert_eq!(soft_buf, ni_buf, "ciphertext mismatch soft vs AES-NI");
        assert_eq!(soft_tag, ni_tag, "tag mismatch soft vs AES-NI");
    }

    #[test]
    fn aesni_large_roundtrip() {
        skip_unless_aesni!();

        let key = [0x42u8; 32];
        let nonce = [0x99u8; 12];
        let aad = b"some additional data";
        let pt: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();

        let mut buf = pt.clone();
        let tag = unsafe { encrypt_aesni(&key, &mut buf, &nonce, aad) };
        unsafe { decrypt_aesni(&key, &mut buf, &tag, &nonce, aad) }.expect("large roundtrip decrypt failed");
        assert_eq!(buf, pt);
    }
}
