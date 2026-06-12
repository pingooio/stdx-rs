/// x86-64 AES-256-GCM using AES-NI and PCLMULQDQ intrinsics.
///
/// ## Representations
///
/// GCM uses a big-endian polynomial ring: bit 0 of byte 0 = coefficient of x^127.
/// PCLMULQDQ uses little-endian polynomial order: bit 0 of SSE lane = coefficient of x^0.
///
/// To bridge this, every GCM block is transformed by **reversing bits in each byte**
/// with `_mm_shuffle_epi8` nibble lookups before carry-less multiplication.
/// In that transformed domain, PCLMULQDQ directly computes GHASH multiplication with
/// reduction polynomial P(x) = x^128 + x^7 + x^2 + x + 1.
///
/// ## Precomputed keys
///
/// The caller (via `encrypt_aesni` / `decrypt_aesni`) supplies the precomputed
/// AES round keys (`rk: &[__m128i; 15]`) and precomputed GHASH powers
/// (`h_powers: &[__m128i; 4]` where index 0 = H¹, 1 = H², 2 = H³, 3 = H⁴,
/// all in bit-reversed-per-byte form). This eliminates key expansion and
/// GHASH-subkey derivation from every encrypt/decrypt call.
///
/// ## 4-block parallel CTR
///
/// The counter is maintained in a byte-swapped (little-endian counter domain)
/// to allow cheap `_mm_add_epi32` increments without per-block byte-reversal
/// round-trips. Four successive counters are unswapped via `pshufb`, encrypted
/// in an interleaved 4-way AES pipeline, then XOR'd with the plaintext.
///
/// ## 4-block aggregated GHASH
///
/// For four successive ciphertext blocks B₁…B₄, the aggregate update is:
///   state' = state·H⁴ ⊕ B₁·H⁴ ⊕ B₂·H³ ⊕ B₃·H² ⊕ B₄·H
/// where · is GF(2¹²⁸) multiplication and Hⁱ are the precomputed powers.
/// This reduces the reduction critical path compared to four serial
/// multiply-reduce chains.
#[allow(clippy::many_single_char_names)]
use core::arch::x86_64::*;

use crate::AeadError;

// ── 128-bit per-byte bit-reversal ────────────────────────────────────────────

/// Reverses bits in each byte of a 128-bit SSE value using SSSE3 `pshufb`.
#[target_feature(enable = "ssse3")]
#[inline]
unsafe fn bitreverse_per_byte(x: __m128i) -> __m128i {
    let reverse4 = _mm_setr_epi8(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15);
    let low_nibble_mask = _mm_set1_epi8(0x0f_u8 as i8);

    let lo = _mm_and_si128(x, low_nibble_mask);
    let hi = _mm_and_si128(_mm_srli_epi16(x, 4), low_nibble_mask);

    let rev_lo = _mm_shuffle_epi8(reverse4, lo);
    let rev_hi = _mm_shuffle_epi8(reverse4, hi);
    _mm_or_si128(_mm_slli_epi16(rev_lo, 4), rev_hi)
}

// ── AES-256 block encrypt (AES-NI) ────────────────────────────────────────────

/// 15 round-keys for AES-256 (Nr = 14 rounds + 1 whitening key).
type RoundKeysNi = [__m128i; 15];

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
/// Uses the 2-pclmulqdq reduction from the Intel GCM whitepaper
/// (Gueron & Kounavis 2014 revision), which replaces one `pclmulqdq`
/// with a cheaper `pshufd` compared to the naive 3-pclmulqdq approach.
#[target_feature(enable = "pclmulqdq,sse2")]
#[inline]
unsafe fn gcm_reduce(lo: __m128i, hi: __m128i) -> __m128i {
    let poly = _mm_set_epi64x(0, 0x87_i64);
    let t0 = _mm_clmulepi64_si128(hi, poly, 0x00);
    let t1 = _mm_clmulepi64_si128(_mm_shuffle_epi32(hi, 0x4e), poly, 0x00);
    _mm_xor_si128(lo, _mm_xor_si128(t0, _mm_shuffle_epi32(t1, 0x4e)))
}

/// Multiply two GCM elements (both already byte-swapped) using Karatsuba + PCLMULQDQ.
#[target_feature(enable = "pclmulqdq,sse2")]
#[inline]
unsafe fn clmul_gcm(a: __m128i, b: __m128i) -> __m128i {
    let lo = _mm_clmulepi64_si128(a, b, 0x00);
    let hi = _mm_clmulepi64_si128(a, b, 0x11);
    let a_swap = _mm_shuffle_epi32(a, 0x4e);
    let b_swap = _mm_shuffle_epi32(b, 0x4e);
    let mid = _mm_clmulepi64_si128(_mm_xor_si128(a, a_swap), _mm_xor_si128(b, b_swap), 0x00);
    let mid_true = _mm_xor_si128(mid, _mm_xor_si128(lo, hi));
    let product_lo = _mm_xor_si128(lo, _mm_slli_si128(mid_true, 8));
    let product_hi = _mm_xor_si128(hi, _mm_srli_si128(mid_true, 8));
    gcm_reduce(product_lo, product_hi)
}

// ── GHASH ─────────────────────────────────────────────────────────────────────

/// Feed a byte slice into the running GHASH state (single-block loop).
#[target_feature(enable = "pclmulqdq,ssse3,sse2")]
unsafe fn ghash_update(mut state: __m128i, h: __m128i, data: &[u8]) -> __m128i {
    let n = data.len();
    let mut i = 0;
    while i + 16 <= n {
        let block = bitreverse_per_byte(_mm_loadu_si128(data.as_ptr().add(i).cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h);
        i += 16;
    }
    if i < n {
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&data[i..]);
        let block = bitreverse_per_byte(_mm_loadu_si128(buf.as_ptr().cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h);
    }
    state
}

/// Process 4 successive GHASH blocks in one aggregated step.
///
/// Given the running state S and blocks B₁…B₄ (ciphertext, NOT bit-reversed),
/// computes:
///   S' = S·H⁴ ⊕ B₁·H⁴ ⊕ B₂·H³ ⊕ B₃·H² ⊕ B₄·H
///
/// `h_powers` is [H¹..H⁸] all in bit-reversed-per-byte form.
#[target_feature(enable = "pclmulqdq,ssse3,sse2")]
#[inline]
unsafe fn ghash_4blocks(
    state: __m128i,
    b1: __m128i,
    b2: __m128i,
    b3: __m128i,
    b4: __m128i,
    h_powers: &[__m128i; 8],
) -> __m128i {
    let b1 = bitreverse_per_byte(b1);
    let b2 = bitreverse_per_byte(b2);
    let b3 = bitreverse_per_byte(b3);
    let b4 = bitreverse_per_byte(b4);

    let h4 = h_powers[3]; // H⁴
    let h3 = h_powers[2]; // H³
    let h2 = h_powers[1]; // H²
    let h1 = h_powers[0]; // H¹

    let t0 = clmul_gcm(state, h4);
    let t1 = clmul_gcm(b1, h4);
    let t2 = clmul_gcm(b2, h3);
    let t3 = clmul_gcm(b3, h2);
    let t4 = clmul_gcm(b4, h1);

    _mm_xor_si128(t0, _mm_xor_si128(t1, _mm_xor_si128(t2, _mm_xor_si128(t3, t4))))
}

/// Process 8 successive GHASH blocks in one aggregated step.
///
/// Computes:
///   S' = S·H⁸ ⊕ B₁·H⁸ ⊕ B₂·H⁷ ⊕ B₃·H⁶ ⊕ B₄·H⁵
///      ⊕ B₅·H⁴ ⊕ B₆·H³ ⊕ B₇·H² ⊕ B₈·H
#[target_feature(enable = "pclmulqdq,ssse3,sse2")]
#[inline]
unsafe fn ghash_8blocks(
    state: __m128i,
    b1: __m128i,
    b2: __m128i,
    b3: __m128i,
    b4: __m128i,
    b5: __m128i,
    b6: __m128i,
    b7: __m128i,
    b8: __m128i,
    h_powers: &[__m128i; 8],
) -> __m128i {
    let b1 = bitreverse_per_byte(b1);
    let b2 = bitreverse_per_byte(b2);
    let b3 = bitreverse_per_byte(b3);
    let b4 = bitreverse_per_byte(b4);
    let b5 = bitreverse_per_byte(b5);
    let b6 = bitreverse_per_byte(b6);
    let b7 = bitreverse_per_byte(b7);
    let b8 = bitreverse_per_byte(b8);

    let h8 = h_powers[7];
    let h7 = h_powers[6];
    let h6 = h_powers[5];
    let h5 = h_powers[4];
    let h4 = h_powers[3];
    let h3 = h_powers[2];
    let h2 = h_powers[1];
    let h1 = h_powers[0];

    let t0 = clmul_gcm(state, h8);
    let t1 = clmul_gcm(b1, h8);
    let t2 = clmul_gcm(b2, h7);
    let t3 = clmul_gcm(b3, h6);
    let t4 = clmul_gcm(b4, h5);
    let t5 = clmul_gcm(b5, h4);
    let t6 = clmul_gcm(b6, h3);
    let t7 = clmul_gcm(b7, h2);
    let t8 = clmul_gcm(b8, h1);

    _mm_xor_si128(
        t0,
        _mm_xor_si128(
            t1,
            _mm_xor_si128(
                t2,
                _mm_xor_si128(
                    t3,
                    _mm_xor_si128(t4, _mm_xor_si128(t5, _mm_xor_si128(t6, _mm_xor_si128(t7, t8)))),
                ),
            ),
        ),
    )
}

// ── Counter helpers ───────────────────────────────────────────────────────────

/// Byte-reversal shuffle mask: maps BE byte order to LE within each 32-bit lane
/// (bytes 0↔3, 1↔2, 4↔7, 5↔6, 8↔11, 9↔10, 12↔15, 13↔14).
const SWAP_BYTES: [i8; 16] = [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];

/// Increment the big-endian 32-bit counter stored in bytes 12..15.
///
/// Uses `pshufb` to byte-swap the counter to little-endian, adds 1 to the
/// low 32-bit lane, then swaps back. No memory round-trip.
#[target_feature(enable = "ssse3,sse2")]
#[inline]
unsafe fn ctr_inc(ctr: __m128i) -> __m128i {
    let swap = _mm_loadu_si128(SWAP_BYTES.as_ptr().cast());
    let le = _mm_shuffle_epi8(ctr, swap);
    let inc = _mm_add_epi32(le, _mm_set_epi32(0, 0, 0, 1));
    _mm_shuffle_epi8(inc, swap)
}

// ── AES-256-GCM encrypt (hardware) ────────────────────────────────────────────

const MAX_GCM_LEN: usize = (u32::MAX as usize - 1) * 16;

/// Encrypt using AES-NI + PCLMULQDQ with precomputed keys and GHASH powers.
///
/// `rk` – precomputed round keys (15 × __m128i).
/// `h_powers` – [H¹..H⁸] all in bit-reversed-per-byte form.
///
/// CTR and GHASH are **fused** into a single pass over the data to minimise
/// memory bandwidth. Eight blocks are processed per iteration for better
/// pipelining of the `aesenc` instruction chain.
#[target_feature(enable = "aes,pclmulqdq,ssse3,sse4.1,sse2")]
pub(crate) unsafe fn encrypt_aesni(
    rk: &[__m128i; 15],
    h_powers: &[__m128i; 8],
    in_out: &mut [u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> [u8; 16] {
    assert!(
        in_out.len() <= MAX_GCM_LEN,
        "GCM plaintext exceeds maximum allowed length (2^32 - 2 blocks)"
    );

    // J0 = nonce ∥ 0x00000001
    let mut j0_bytes = [0u8; 16];
    j0_bytes[..12].copy_from_slice(nonce);
    j0_bytes[15] = 0x01;
    let j0 = _mm_loadu_si128(j0_bytes.as_ptr().cast());

    // E(J0) in natural byte order (used to mask the tag)
    let ej0 = aes256_enc(rk, j0);
    let mut ej0_bytes = [0u8; 16];
    _mm_storeu_si128(ej0_bytes.as_mut_ptr().cast(), ej0);

    // CTR starts at J0 + 1 = nonce ∥ 0x00000002
    let mut ctr = ctr_inc(j0);

    // ── Single-pass fused CTR + GHASH ──────────────────────────────────────
    let swap = _mm_loadu_si128(SWAP_BYTES.as_ptr().cast());
    let mut base = _mm_shuffle_epi8(ctr, swap);
    let zero = _mm_setzero_si128();
    let one = _mm_set_epi32(0, 0, 0, 1);
    let two = _mm_set_epi32(0, 0, 0, 2);
    let three = _mm_set_epi32(0, 0, 0, 3);
    let four = _mm_set_epi32(0, 0, 0, 4);
    let five = _mm_set_epi32(0, 0, 0, 5);
    let six = _mm_set_epi32(0, 0, 0, 6);
    let seven = _mm_set_epi32(0, 0, 0, 7);

    let mut state = _mm_setzero_si128();
    // AAD (single-block GHASH, usually short)
    state = ghash_update(state, h_powers[0], aad);

    let n = in_out.len();
    let mut i = 0;

    // 8-block fused pipeline
    while i + 128 <= n {
        let c1 = _mm_shuffle_epi8(_mm_add_epi32(base, zero), swap);
        let c2 = _mm_shuffle_epi8(_mm_add_epi32(base, one), swap);
        let c3 = _mm_shuffle_epi8(_mm_add_epi32(base, two), swap);
        let c4 = _mm_shuffle_epi8(_mm_add_epi32(base, three), swap);
        let c5 = _mm_shuffle_epi8(_mm_add_epi32(base, four), swap);
        let c6 = _mm_shuffle_epi8(_mm_add_epi32(base, five), swap);
        let c7 = _mm_shuffle_epi8(_mm_add_epi32(base, six), swap);
        let c8 = _mm_shuffle_epi8(_mm_add_epi32(base, seven), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);
        let k5 = aes256_enc(rk, c5);
        let k6 = aes256_enc(rk, c6);
        let k7 = aes256_enc(rk, c7);
        let k8 = aes256_enc(rk, c8);

        let p1 = _mm_loadu_si128(in_out.as_ptr().add(i).cast());
        let p2 = _mm_loadu_si128(in_out.as_ptr().add(i + 16).cast());
        let p3 = _mm_loadu_si128(in_out.as_ptr().add(i + 32).cast());
        let p4 = _mm_loadu_si128(in_out.as_ptr().add(i + 48).cast());
        let p5 = _mm_loadu_si128(in_out.as_ptr().add(i + 64).cast());
        let p6 = _mm_loadu_si128(in_out.as_ptr().add(i + 80).cast());
        let p7 = _mm_loadu_si128(in_out.as_ptr().add(i + 96).cast());
        let p8 = _mm_loadu_si128(in_out.as_ptr().add(i + 112).cast());

        let ct1 = _mm_xor_si128(p1, k1);
        let ct2 = _mm_xor_si128(p2, k2);
        let ct3 = _mm_xor_si128(p3, k3);
        let ct4 = _mm_xor_si128(p4, k4);
        let ct5 = _mm_xor_si128(p5, k5);
        let ct6 = _mm_xor_si128(p6, k6);
        let ct7 = _mm_xor_si128(p7, k7);
        let ct8 = _mm_xor_si128(p8, k8);

        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), ct1);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 16).cast(), ct2);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 32).cast(), ct3);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 48).cast(), ct4);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 64).cast(), ct5);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 80).cast(), ct6);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 96).cast(), ct7);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 112).cast(), ct8);

        state = ghash_8blocks(state, ct1, ct2, ct3, ct4, ct5, ct6, ct7, ct8, h_powers);

        base = _mm_add_epi32(base, _mm_set_epi32(0, 0, 0, 8));
        i += 128;
    }

    // 4-block fused pipeline (tail, when 8 blocks won't fit but 4 will)
    while i + 64 <= n {
        let c1 = _mm_shuffle_epi8(_mm_add_epi32(base, zero), swap);
        let c2 = _mm_shuffle_epi8(_mm_add_epi32(base, one), swap);
        let c3 = _mm_shuffle_epi8(_mm_add_epi32(base, two), swap);
        let c4 = _mm_shuffle_epi8(_mm_add_epi32(base, three), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);

        let p1 = _mm_loadu_si128(in_out.as_ptr().add(i).cast());
        let p2 = _mm_loadu_si128(in_out.as_ptr().add(i + 16).cast());
        let p3 = _mm_loadu_si128(in_out.as_ptr().add(i + 32).cast());
        let p4 = _mm_loadu_si128(in_out.as_ptr().add(i + 48).cast());

        let ct1 = _mm_xor_si128(p1, k1);
        let ct2 = _mm_xor_si128(p2, k2);
        let ct3 = _mm_xor_si128(p3, k3);
        let ct4 = _mm_xor_si128(p4, k4);

        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), ct1);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 16).cast(), ct2);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 32).cast(), ct3);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 48).cast(), ct4);

        state = ghash_4blocks(state, ct1, ct2, ct3, ct4, h_powers);

        base = _mm_add_epi32(base, four);
        i += 64;
    }

    // Tail blocks (1-3)
    while i + 16 <= n {
        let k = aes256_enc(rk, _mm_shuffle_epi8(base, swap));
        let ct = _mm_xor_si128(_mm_loadu_si128(in_out.as_ptr().add(i).cast()), k);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), ct);

        let block = bitreverse_per_byte(ct);
        state = clmul_gcm(_mm_xor_si128(state, block), h_powers[0]);

        base = _mm_add_epi32(base, one);
        i += 16;
    }
    if i < n {
        let k = aes256_enc(rk, _mm_shuffle_epi8(base, swap));
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&in_out[i..]);
        let ct = _mm_xor_si128(_mm_loadu_si128(buf.as_ptr().cast()), k);
        let mut out_buf = [0u8; 16];
        _mm_storeu_si128(out_buf.as_mut_ptr().cast(), ct);
        in_out[i..].copy_from_slice(&out_buf[..n - i]);

        let mut padded = [0u8; 16];
        padded[..n - i].copy_from_slice(&in_out[i..]);
        let block = bitreverse_per_byte(_mm_loadu_si128(padded.as_ptr().cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h_powers[0]);
    }

    // ── Length block ───────────────────────────────────────────────────────
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((in_out.len() as u64) * 8).to_be_bytes());
    let len_br = bitreverse_per_byte(_mm_loadu_si128(len_block.as_ptr().cast()));
    state = clmul_gcm(_mm_xor_si128(state, len_br), h_powers[0]);

    // ── Tag ────────────────────────────────────────────────────────────────
    let tag = _mm_xor_si128(bitreverse_per_byte(state), _mm_loadu_si128(ej0_bytes.as_ptr().cast()));
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast(), tag);
    out
}

// ── AES-256-GCM decrypt (hardware) ───────────────────────────────────────────

/// Decrypt using AES-NI + PCLMULQDQ with precomputed keys and GHASH powers.
///
/// Authenticate-then-decrypt: GHASH the ciphertext first, verify the tag,
/// then CTR-decrypt. 8-block aggregates are used for large payloads,
/// falling back to 4-block when less than 8 blocks remain.
#[target_feature(enable = "aes,pclmulqdq,ssse3,sse4.1,sse2")]
pub(crate) unsafe fn decrypt_aesni(
    rk: &[__m128i; 15],
    h_powers: &[__m128i; 8],
    in_out: &mut [u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<(), AeadError> {
    if in_out.len() > MAX_GCM_LEN {
        return Err(AeadError::InvalidCiphertext);
    }

    // J0 = nonce ∥ 0x00000001
    let mut j0_bytes = [0u8; 16];
    j0_bytes[..12].copy_from_slice(nonce);
    j0_bytes[15] = 0x01;
    let j0 = _mm_loadu_si128(j0_bytes.as_ptr().cast());

    let ej0 = aes256_enc(rk, j0);
    let mut ej0_bytes = [0u8; 16];
    _mm_storeu_si128(ej0_bytes.as_mut_ptr().cast(), ej0);

    // ── GHASH the ciphertext ──────────────────────────────────────────────
    let mut state = _mm_setzero_si128();
    state = ghash_update(state, h_powers[0], aad);

    let n = in_out.len();
    let mut i = 0;

    while i + 128 <= n {
        let b1 = _mm_loadu_si128(in_out.as_ptr().add(i).cast());
        let b2 = _mm_loadu_si128(in_out.as_ptr().add(i + 16).cast());
        let b3 = _mm_loadu_si128(in_out.as_ptr().add(i + 32).cast());
        let b4 = _mm_loadu_si128(in_out.as_ptr().add(i + 48).cast());
        let b5 = _mm_loadu_si128(in_out.as_ptr().add(i + 64).cast());
        let b6 = _mm_loadu_si128(in_out.as_ptr().add(i + 80).cast());
        let b7 = _mm_loadu_si128(in_out.as_ptr().add(i + 96).cast());
        let b8 = _mm_loadu_si128(in_out.as_ptr().add(i + 112).cast());
        state = ghash_8blocks(state, b1, b2, b3, b4, b5, b6, b7, b8, h_powers);
        i += 128;
    }

    while i + 64 <= n {
        let b1 = _mm_loadu_si128(in_out.as_ptr().add(i).cast());
        let b2 = _mm_loadu_si128(in_out.as_ptr().add(i + 16).cast());
        let b3 = _mm_loadu_si128(in_out.as_ptr().add(i + 32).cast());
        let b4 = _mm_loadu_si128(in_out.as_ptr().add(i + 48).cast());
        state = ghash_4blocks(state, b1, b2, b3, b4, h_powers);
        i += 64;
    }

    while i + 16 <= n {
        let block = bitreverse_per_byte(_mm_loadu_si128(in_out.as_ptr().add(i).cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h_powers[0]);
        i += 16;
    }
    if i < n {
        let mut padded = [0u8; 16];
        padded[..n - i].copy_from_slice(&in_out[i..]);
        let block = bitreverse_per_byte(_mm_loadu_si128(padded.as_ptr().cast()));
        state = clmul_gcm(_mm_xor_si128(state, block), h_powers[0]);
    }

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((in_out.len() as u64) * 8).to_be_bytes());
    let len_br = bitreverse_per_byte(_mm_loadu_si128(len_block.as_ptr().cast()));
    state = clmul_gcm(_mm_xor_si128(state, len_br), h_powers[0]);

    let computed_tag = _mm_xor_si128(bitreverse_per_byte(state), _mm_loadu_si128(ej0_bytes.as_ptr().cast()));
    let mut computed = [0u8; 16];
    _mm_storeu_si128(computed.as_mut_ptr().cast(), computed_tag);

    // Constant-time comparison
    let mut diff = 0u8;
    for k in 0..16 {
        diff |= computed[k] ^ tag[k];
    }
    if diff != 0 {
        return Err(AeadError::InvalidCiphertext);
    }

    // ── CTR decrypt ────────────────────────────────────────────────────────
    let swap = _mm_loadu_si128(SWAP_BYTES.as_ptr().cast());
    let mut ctr = ctr_inc(j0);
    let mut base = _mm_shuffle_epi8(ctr, swap);
    let zero_offset = _mm_setzero_si128();
    let one = _mm_set_epi32(0, 0, 0, 1);
    let two = _mm_set_epi32(0, 0, 0, 2);
    let three = _mm_set_epi32(0, 0, 0, 3);
    let four = _mm_set_epi32(0, 0, 0, 4);
    let five = _mm_set_epi32(0, 0, 0, 5);
    let six = _mm_set_epi32(0, 0, 0, 6);
    let seven = _mm_set_epi32(0, 0, 0, 7);

    let mut i = 0;
    while i + 128 <= n {
        let c1 = _mm_shuffle_epi8(_mm_add_epi32(base, zero_offset), swap);
        let c2 = _mm_shuffle_epi8(_mm_add_epi32(base, one), swap);
        let c3 = _mm_shuffle_epi8(_mm_add_epi32(base, two), swap);
        let c4 = _mm_shuffle_epi8(_mm_add_epi32(base, three), swap);
        let c5 = _mm_shuffle_epi8(_mm_add_epi32(base, four), swap);
        let c6 = _mm_shuffle_epi8(_mm_add_epi32(base, five), swap);
        let c7 = _mm_shuffle_epi8(_mm_add_epi32(base, six), swap);
        let c8 = _mm_shuffle_epi8(_mm_add_epi32(base, seven), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);
        let k5 = aes256_enc(rk, c5);
        let k6 = aes256_enc(rk, c6);
        let k7 = aes256_enc(rk, c7);
        let k8 = aes256_enc(rk, c8);

        let ct1 = _mm_loadu_si128(in_out.as_ptr().add(i).cast());
        let ct2 = _mm_loadu_si128(in_out.as_ptr().add(i + 16).cast());
        let ct3 = _mm_loadu_si128(in_out.as_ptr().add(i + 32).cast());
        let ct4 = _mm_loadu_si128(in_out.as_ptr().add(i + 48).cast());
        let ct5 = _mm_loadu_si128(in_out.as_ptr().add(i + 64).cast());
        let ct6 = _mm_loadu_si128(in_out.as_ptr().add(i + 80).cast());
        let ct7 = _mm_loadu_si128(in_out.as_ptr().add(i + 96).cast());
        let ct8 = _mm_loadu_si128(in_out.as_ptr().add(i + 112).cast());

        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), _mm_xor_si128(ct1, k1));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 16).cast(), _mm_xor_si128(ct2, k2));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 32).cast(), _mm_xor_si128(ct3, k3));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 48).cast(), _mm_xor_si128(ct4, k4));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 64).cast(), _mm_xor_si128(ct5, k5));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 80).cast(), _mm_xor_si128(ct6, k6));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 96).cast(), _mm_xor_si128(ct7, k7));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 112).cast(), _mm_xor_si128(ct8, k8));

        base = _mm_add_epi32(base, _mm_set_epi32(0, 0, 0, 8));
        i += 128;
    }

    while i + 64 <= n {
        let c1 = _mm_shuffle_epi8(_mm_add_epi32(base, zero_offset), swap);
        let c2 = _mm_shuffle_epi8(_mm_add_epi32(base, one), swap);
        let c3 = _mm_shuffle_epi8(_mm_add_epi32(base, two), swap);
        let c4 = _mm_shuffle_epi8(_mm_add_epi32(base, three), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);

        let ct1 = _mm_loadu_si128(in_out.as_ptr().add(i).cast());
        let ct2 = _mm_loadu_si128(in_out.as_ptr().add(i + 16).cast());
        let ct3 = _mm_loadu_si128(in_out.as_ptr().add(i + 32).cast());
        let ct4 = _mm_loadu_si128(in_out.as_ptr().add(i + 48).cast());

        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), _mm_xor_si128(ct1, k1));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 16).cast(), _mm_xor_si128(ct2, k2));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 32).cast(), _mm_xor_si128(ct3, k3));
        _mm_storeu_si128(in_out.as_mut_ptr().add(i + 48).cast(), _mm_xor_si128(ct4, k4));

        base = _mm_add_epi32(base, four);
        i += 64;
    }

    while i + 16 <= n {
        let k = aes256_enc(rk, _mm_shuffle_epi8(base, swap));
        let pt = _mm_xor_si128(_mm_loadu_si128(in_out.as_ptr().add(i).cast()), k);
        _mm_storeu_si128(in_out.as_mut_ptr().add(i).cast(), pt);
        base = _mm_add_epi32(base, one);
        i += 16;
    }
    if i < n {
        let k = aes256_enc(rk, _mm_shuffle_epi8(base, swap));
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&in_out[i..]);
        let pt = _mm_xor_si128(_mm_loadu_si128(buf.as_ptr().cast()), k);
        let mut out_buf = [0u8; 16];
        _mm_storeu_si128(out_buf.as_mut_ptr().cast(), pt);
        in_out[i..].copy_from_slice(&out_buf[..n - i]);
    }

    Ok(())
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

    fn have_features() -> bool {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1")
    }

    macro_rules! skip_unless_aesni {
        () => {
            if !have_features() {
                eprintln!("Skipping AES-NI test: CPU features not available");
                return;
            }
        };
    }

    fn make_rk(key: &[u8; 32]) -> [__m128i; 15] {
        // Load the precomputed software round keys into __m128i registers.
        // This is safe on any x86_64 (SSE2 is baseline).
        let soft = crate::aes::aes256::key_expand(key);
        let mut rk = [unsafe { _mm_setzero_si128() }; 15];
        for i in 0..15 {
            rk[i] = unsafe { _mm_loadu_si128(soft[i].as_ptr().cast()) };
        }
        rk
    }

    fn make_h_powers(key: &[u8; 32]) -> [__m128i; 8] {
        let (bytes, _) = crate::aes::aes256::precompute_ghash_powers(key);
        let mut hp = [unsafe { _mm_setzero_si128() }; 8];
        for i in 0..8 {
            hp[i] = unsafe { _mm_loadu_si128(bytes[i].as_ptr().cast()) };
        }
        hp
    }

    // ── AES-NI block encrypt matches NIST SP 800-38A ECB-AES256 ──────────────

    #[test]
    fn aesni_ecb_vectors() {
        skip_unless_aesni!();

        let key: [u8; 32] = hb("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let rk = make_rk(&key);

        let vectors: &[([u8; 16], [u8; 16])] = &[
            (hb("6bc1bee22e409f96e93d7e117393172a"), hb("f3eed1bdb5d2a03c064b5a7e3db181f8")),
            (hb("ae2d8a571e03ac9c9eb76fac45af8e51"), hb("591ccb10d410ed26dc5ba74a31362870")),
            (hb("30c81c46a35ce411e5fbc1191a0a52ef"), hb("b6ed21b99ca6f4f9f153e7b1beafed1d")),
            (hb("f69f2445df4f9b17ad2b417be66c3710"), hb("23304b7a39f9f3ff067d8d8f9e24ecc7")),
        ];

        for (pt, ct_exp) in vectors {
            let pt_xmm = unsafe { _mm_loadu_si128(pt.as_ptr().cast()) };
            let ct_xmm = unsafe { aes256_enc(&rk, pt_xmm) };
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
        GcmVec {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            pt: "",
            aad: "",
            ct: "",
            tag: "530f8afbc74536b9a963b4f1c4cb738b",
        },
        GcmVec {
            key: "0000000000000000000000000000000000000000000000000000000000000000",
            nonce: "000000000000000000000000",
            pt: "00000000000000000000000000000000",
            aad: "",
            ct: "cea7403d4d606b6e074ec5d3baf39d18",
            tag: "d0d1c8a799996bf0265b98b5d48ab919",
        },
        GcmVec {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            nonce: "cafebabefacedbaddecaf888",
            pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            aad: "",
            ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            tag: "b094dac5d93471bdec1a502270e3cc6c",
        },
        GcmVec {
            key: "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            nonce: "cafebabefacedbaddecaf888",
            pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            tag: "76fc6ece0f4e1768cddf8853bb2d551b",
        },
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

            let rk = make_rk(&key);
            let hp = make_h_powers(&key);

            let mut buf = pt.clone();
            let tag = unsafe { encrypt_aesni(&rk, &hp, &mut buf, &nonce, &aad) };
            assert_eq!(buf, exp_ct, "AES-NI ct  key={}", v.key);
            assert_eq!(tag, exp_tag, "AES-NI tag key={}", v.key);

            let mut buf2 = exp_ct.clone();
            unsafe { decrypt_aesni(&rk, &hp, &mut buf2, &exp_tag, &nonce, &aad) }.expect("AES-NI decrypt failed");
            assert_eq!(buf2, pt, "AES-NI pt  key={}", v.key);
        }
    }

    #[test]
    fn aesni_tag_mismatch() {
        skip_unless_aesni!();

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let rk = make_rk(&key);
        let hp = make_h_powers(&key);
        let mut buf = b"hello world".to_vec();
        let tag = unsafe { encrypt_aesni(&rk, &hp, &mut buf, &nonce, &[]) };
        let mut bad = tag;
        bad[7] ^= 0x01;
        assert!(unsafe { decrypt_aesni(&rk, &hp, &mut buf.clone(), &bad, &nonce, &[]) }.is_err());
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
        let soft_tag = cipher.encrypt_in_place_soft(&mut soft_buf, &nonce, &aad);

        let rk = make_rk(&key);
        let hp = make_h_powers(&key);
        let mut ni_buf = pt.clone();
        let ni_tag = unsafe { encrypt_aesni(&rk, &hp, &mut ni_buf, &nonce, &aad) };

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

        let rk = make_rk(&key);
        let hp = make_h_powers(&key);

        let mut buf = pt.clone();
        let tag = unsafe { encrypt_aesni(&rk, &hp, &mut buf, &nonce, aad) };
        unsafe { decrypt_aesni(&rk, &hp, &mut buf, &tag, &nonce, aad) }.expect("large roundtrip decrypt failed");
        assert_eq!(buf, pt);
    }
}
