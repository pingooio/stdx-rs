#![allow(unsafe_op_in_unsafe_fn)]

/// aarch64 AES-256-GCM using ARMv8 Crypto extensions.
///
/// Same 4-block parallel CTR and 4-block aggregated GHASH strategy as the
/// x86_64 path (see `aes256_amd64.rs` for details). The ARMv8 equivalents:
/// - `vaeseq_u8` / `vaesmcq_u8` for AES
/// - `vmull_p64` for carry-less multiplication
/// - `vrbitq_u8` for per-byte bit reversal
/// - `vqtbl1q_u8` for byte permutation (counter swap)
///
/// The caller supplies precomputed round keys and GHASH powers,
/// eliminating key expansion and H derivation from every call.
use core::arch::aarch64::*;

use crate::AeadError;

type RoundKeysArm = [uint8x16_t; 15];

/// Byte-reversal shuffle mask: maps byte i ↔ byte 15-i (full 16-byte reversal).
const SWAP_MASK: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

#[target_feature(enable = "aes,neon")]
#[inline]
unsafe fn aes256_enc(rk: &RoundKeysArm, block: uint8x16_t) -> uint8x16_t {
    let zero = vdupq_n_u8(0);

    let mut b = veorq_u8(block, rk[0]);
    for round_key in rk.iter().take(14).skip(1) {
        b = vaesmcq_u8(vaeseq_u8(b, zero));
        b = veorq_u8(b, *round_key);
    }

    b = vaeseq_u8(b, zero);
    veorq_u8(b, rk[14])
}

#[inline]
unsafe fn clmul64_pmull(a: u64, b: u64) -> u128 {
    let product = vmull_p64(core::mem::transmute(a), core::mem::transmute(b));
    core::mem::transmute(product)
}

#[inline]
unsafe fn gcm_reduce(product_lo: u128, product_hi: u128) -> u128 {
    let poly = 0x87u64;
    let t1 = clmul64_pmull(product_hi as u64, poly);
    let t2 = clmul64_pmull((product_hi >> 64) as u64, poly);
    let t2_lo = t2 << 64;
    let t2_hi = t2 >> 64;
    let t3 = clmul64_pmull(t2_hi as u64, poly);
    product_lo ^ t1 ^ t2_lo ^ t3
}

#[inline]
unsafe fn clmul_gcm_pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    let a_u64 = vreinterpretq_u64_u8(a);
    let b_u64 = vreinterpretq_u64_u8(b);
    let a_lo = vgetq_lane_u64(a_u64, 0);
    let a_hi = vgetq_lane_u64(a_u64, 1);
    let b_lo = vgetq_lane_u64(b_u64, 0);
    let b_hi = vgetq_lane_u64(b_u64, 1);

    let lo = clmul64_pmull(a_lo, b_lo);
    let hi = clmul64_pmull(a_hi, b_hi);
    let mid = clmul64_pmull(a_lo ^ a_hi, b_lo ^ b_hi);

    let mid_true = mid ^ lo ^ hi;
    let product_lo = lo ^ (mid_true << 64);
    let product_hi = hi ^ (mid_true >> 64);
    let reduced = gcm_reduce(product_lo, product_hi);

    // Stay in registers: convert u128 → uint8x16_t without store/load.
    let lo = reduced as u64;
    let hi = (reduced >> 64) as u64;
    vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(lo), vcreate_u64(hi)))
}

/// Single-block GHASH feed (tail processing).
unsafe fn ghash_update(mut state: uint8x16_t, h: uint8x16_t, data: &[u8]) -> uint8x16_t {
    let n = data.len();
    let mut i = 0usize;

    while i + 16 <= n {
        let block = vrbitq_u8(vld1q_u8(data.as_ptr().add(i)));
        state = clmul_gcm_pmull(veorq_u8(state, block), h);
        i += 16;
    }

    if i < n {
        let mut padded = [0u8; 16];
        padded[..n - i].copy_from_slice(&data[i..]);
        let block = vrbitq_u8(vld1q_u8(padded.as_ptr()));
        state = clmul_gcm_pmull(veorq_u8(state, block), h);
    }

    state
}

/// 4-block aggregated GHASH.
///
///   state' = state·H⁴ ⊕ B₁·H⁴ ⊕ B₂·H³ ⊕ B₃·H² ⊕ B₄·H
#[inline]
unsafe fn ghash_4blocks(
    state: uint8x16_t,
    b1: uint8x16_t,
    b2: uint8x16_t,
    b3: uint8x16_t,
    b4: uint8x16_t,
    h_powers: &[uint8x16_t; 8],
) -> uint8x16_t {
    let b1 = vrbitq_u8(b1);
    let b2 = vrbitq_u8(b2);
    let b3 = vrbitq_u8(b3);
    let b4 = vrbitq_u8(b4);

    let h1 = h_powers[0];
    let h2 = h_powers[1];
    let h3 = h_powers[2];
    let h4 = h_powers[3];

    let t0 = clmul_gcm_pmull(state, h4);
    let t1 = clmul_gcm_pmull(b1, h4);
    let t2 = clmul_gcm_pmull(b2, h3);
    let t3 = clmul_gcm_pmull(b3, h2);
    let t4 = clmul_gcm_pmull(b4, h1);

    veorq_u8(t0, veorq_u8(t1, veorq_u8(t2, veorq_u8(t3, t4))))
}

/// 8-block aggregated GHASH.
///
///   state' = state·H⁸ ⊕ B₁·H⁸ ⊕ B₂·H⁷ ⊕ ... ⊕ B₈·H
#[inline]
unsafe fn ghash_8blocks(
    state: uint8x16_t,
    b1: uint8x16_t,
    b2: uint8x16_t,
    b3: uint8x16_t,
    b4: uint8x16_t,
    b5: uint8x16_t,
    b6: uint8x16_t,
    b7: uint8x16_t,
    b8: uint8x16_t,
    h_powers: &[uint8x16_t; 8],
) -> uint8x16_t {
    let b1 = vrbitq_u8(b1);
    let b2 = vrbitq_u8(b2);
    let b3 = vrbitq_u8(b3);
    let b4 = vrbitq_u8(b4);
    let b5 = vrbitq_u8(b5);
    let b6 = vrbitq_u8(b6);
    let b7 = vrbitq_u8(b7);
    let b8 = vrbitq_u8(b8);

    let h8 = h_powers[7];
    let h7 = h_powers[6];
    let h6 = h_powers[5];
    let h5 = h_powers[4];
    let h4 = h_powers[3];
    let h3 = h_powers[2];
    let h2 = h_powers[1];
    let h1 = h_powers[0];

    let t0 = clmul_gcm_pmull(state, h8);
    let t1 = clmul_gcm_pmull(b1, h8);
    let t2 = clmul_gcm_pmull(b2, h7);
    let t3 = clmul_gcm_pmull(b3, h6);
    let t4 = clmul_gcm_pmull(b4, h5);
    let t5 = clmul_gcm_pmull(b5, h4);
    let t6 = clmul_gcm_pmull(b6, h3);
    let t7 = clmul_gcm_pmull(b7, h2);
    let t8 = clmul_gcm_pmull(b8, h1);

    veorq_u8(
        t0,
        veorq_u8(
            t1,
            veorq_u8(t2, veorq_u8(t3, veorq_u8(t4, veorq_u8(t5, veorq_u8(t6, veorq_u8(t7, t8)))))),
        ),
    )
}

const MAX_GCM_LEN: usize = (u32::MAX as usize - 1) * 16;

// ── Encrypt ───────────────────────────────────────────────────────────────────

pub(crate) unsafe fn encrypt_armv8(
    rk: &[uint8x16_t; 15],
    h_powers: &[uint8x16_t; 8],
    in_out: &mut [u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> [u8; 16] {
    assert!(
        in_out.len() <= MAX_GCM_LEN,
        "GCM plaintext exceeds maximum allowed length (2^32 - 2 blocks)"
    );

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let ej0 = aes256_enc(rk, vld1q_u8(j0.as_ptr()));
    let mut ej0_bytes = [0u8; 16];
    vst1q_u8(ej0_bytes.as_mut_ptr(), ej0);

    // CTR starts at J0 + 1
    let ctr = ctr_inc(vld1q_u8(j0.as_ptr()));

    let swap = vld1q_u8(SWAP_MASK.as_ptr());
    let mut base = vqtbl1q_u8(ctr, swap);
    let zero = vdupq_n_u32(0);
    let one = vsetq_lane_u32(1, vdupq_n_u32(0), 0);
    let two = vsetq_lane_u32(2, vdupq_n_u32(0), 0);
    let three = vsetq_lane_u32(3, vdupq_n_u32(0), 0);
    let four = vsetq_lane_u32(4, vdupq_n_u32(0), 0);
    let five = vsetq_lane_u32(5, vdupq_n_u32(0), 0);
    let six = vsetq_lane_u32(6, vdupq_n_u32(0), 0);
    let seven = vsetq_lane_u32(7, vdupq_n_u32(0), 0);

    let mut state = vdupq_n_u8(0);
    state = ghash_update(state, h_powers[0], aad);

    let n = in_out.len();
    let mut i = 0usize;

    // 8-block fused pipeline
    while i + 128 <= n {
        let c1 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), zero)), swap);
        let c2 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), one)), swap);
        let c3 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), two)), swap);
        let c4 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), three)), swap);
        let c5 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), four)), swap);
        let c6 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), five)), swap);
        let c7 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), six)), swap);
        let c8 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), seven)), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);
        let k5 = aes256_enc(rk, c5);
        let k6 = aes256_enc(rk, c6);
        let k7 = aes256_enc(rk, c7);
        let k8 = aes256_enc(rk, c8);

        let p1 = vld1q_u8(in_out.as_ptr().add(i));
        let p2 = vld1q_u8(in_out.as_ptr().add(i + 16));
        let p3 = vld1q_u8(in_out.as_ptr().add(i + 32));
        let p4 = vld1q_u8(in_out.as_ptr().add(i + 48));
        let p5 = vld1q_u8(in_out.as_ptr().add(i + 64));
        let p6 = vld1q_u8(in_out.as_ptr().add(i + 80));
        let p7 = vld1q_u8(in_out.as_ptr().add(i + 96));
        let p8 = vld1q_u8(in_out.as_ptr().add(i + 112));

        let ct1 = veorq_u8(p1, k1);
        let ct2 = veorq_u8(p2, k2);
        let ct3 = veorq_u8(p3, k3);
        let ct4 = veorq_u8(p4, k4);
        let ct5 = veorq_u8(p5, k5);
        let ct6 = veorq_u8(p6, k6);
        let ct7 = veorq_u8(p7, k7);
        let ct8 = veorq_u8(p8, k8);

        vst1q_u8(in_out.as_mut_ptr().add(i), ct1);
        vst1q_u8(in_out.as_mut_ptr().add(i + 16), ct2);
        vst1q_u8(in_out.as_mut_ptr().add(i + 32), ct3);
        vst1q_u8(in_out.as_mut_ptr().add(i + 48), ct4);
        vst1q_u8(in_out.as_mut_ptr().add(i + 64), ct5);
        vst1q_u8(in_out.as_mut_ptr().add(i + 80), ct6);
        vst1q_u8(in_out.as_mut_ptr().add(i + 96), ct7);
        vst1q_u8(in_out.as_mut_ptr().add(i + 112), ct8);

        state = ghash_8blocks(state, ct1, ct2, ct3, ct4, ct5, ct6, ct7, ct8, h_powers);

        base = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), vsetq_lane_u32(8, vdupq_n_u32(0), 0)));
        i += 128;
    }

    // 4-block fused pipeline
    while i + 64 <= n {
        let c1 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), zero)), swap);
        let c2 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), one)), swap);
        let c3 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), two)), swap);
        let c4 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), three)), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);

        let p1 = vld1q_u8(in_out.as_ptr().add(i));
        let p2 = vld1q_u8(in_out.as_ptr().add(i + 16));
        let p3 = vld1q_u8(in_out.as_ptr().add(i + 32));
        let p4 = vld1q_u8(in_out.as_ptr().add(i + 48));

        let ct1 = veorq_u8(p1, k1);
        let ct2 = veorq_u8(p2, k2);
        let ct3 = veorq_u8(p3, k3);
        let ct4 = veorq_u8(p4, k4);

        vst1q_u8(in_out.as_mut_ptr().add(i), ct1);
        vst1q_u8(in_out.as_mut_ptr().add(i + 16), ct2);
        vst1q_u8(in_out.as_mut_ptr().add(i + 32), ct3);
        vst1q_u8(in_out.as_mut_ptr().add(i + 48), ct4);

        state = ghash_4blocks(state, ct1, ct2, ct3, ct4, h_powers);

        base = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), four));
        i += 64;
    }

    // Tail blocks (1-3)
    while i + 16 <= n {
        let k = aes256_enc(rk, vqtbl1q_u8(base, swap));
        let ct = veorq_u8(vld1q_u8(in_out.as_ptr().add(i)), k);
        vst1q_u8(in_out.as_mut_ptr().add(i), ct);

        let block = vrbitq_u8(ct);
        state = clmul_gcm_pmull(veorq_u8(state, block), h_powers[0]);

        base = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), one));
        i += 16;
    }
    if i < n {
        let k = aes256_enc(rk, vqtbl1q_u8(base, swap));
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&in_out[i..]);
        let ct = veorq_u8(vld1q_u8(buf.as_ptr()), k);
        let mut out_buf = [0u8; 16];
        vst1q_u8(out_buf.as_mut_ptr(), ct);
        in_out[i..].copy_from_slice(&out_buf[..n - i]);

        let mut padded = [0u8; 16];
        padded[..n - i].copy_from_slice(&in_out[i..]);
        let block = vrbitq_u8(vld1q_u8(padded.as_ptr()));
        state = clmul_gcm_pmull(veorq_u8(state, block), h_powers[0]);
    }

    // Length block
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((in_out.len() as u64) * 8).to_be_bytes());
    let len_br = vrbitq_u8(vld1q_u8(len_block.as_ptr()));
    state = clmul_gcm_pmull(veorq_u8(state, len_br), h_powers[0]);

    // Tag
    let tag = veorq_u8(vrbitq_u8(state), vld1q_u8(ej0_bytes.as_ptr()));
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), tag);
    out
}

// ── Decrypt ───────────────────────────────────────────────────────────────────

pub(crate) unsafe fn decrypt_armv8(
    rk: &[uint8x16_t; 15],
    h_powers: &[uint8x16_t; 8],
    in_out: &mut [u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<(), AeadError> {
    if in_out.len() > MAX_GCM_LEN {
        return Err(AeadError::InvalidCiphertext);
    }

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let ej0 = aes256_enc(rk, vld1q_u8(j0.as_ptr()));
    let mut ej0_bytes = [0u8; 16];
    vst1q_u8(ej0_bytes.as_mut_ptr(), ej0);

    // ── GHASH the ciphertext ──────────────────────────────────────────────
    let mut state = vdupq_n_u8(0);
    state = ghash_update(state, h_powers[0], aad);

    let n = in_out.len();
    let mut i = 0usize;

    while i + 128 <= n {
        let b1 = vld1q_u8(in_out.as_ptr().add(i));
        let b2 = vld1q_u8(in_out.as_ptr().add(i + 16));
        let b3 = vld1q_u8(in_out.as_ptr().add(i + 32));
        let b4 = vld1q_u8(in_out.as_ptr().add(i + 48));
        let b5 = vld1q_u8(in_out.as_ptr().add(i + 64));
        let b6 = vld1q_u8(in_out.as_ptr().add(i + 80));
        let b7 = vld1q_u8(in_out.as_ptr().add(i + 96));
        let b8 = vld1q_u8(in_out.as_ptr().add(i + 112));
        state = ghash_8blocks(state, b1, b2, b3, b4, b5, b6, b7, b8, h_powers);
        i += 128;
    }

    while i + 64 <= n {
        let b1 = vld1q_u8(in_out.as_ptr().add(i));
        let b2 = vld1q_u8(in_out.as_ptr().add(i + 16));
        let b3 = vld1q_u8(in_out.as_ptr().add(i + 32));
        let b4 = vld1q_u8(in_out.as_ptr().add(i + 48));
        state = ghash_4blocks(state, b1, b2, b3, b4, h_powers);
        i += 64;
    }

    while i + 16 <= n {
        let block = vrbitq_u8(vld1q_u8(in_out.as_ptr().add(i)));
        state = clmul_gcm_pmull(veorq_u8(state, block), h_powers[0]);
        i += 16;
    }
    if i < n {
        let mut padded = [0u8; 16];
        padded[..n - i].copy_from_slice(&in_out[i..]);
        let block = vrbitq_u8(vld1q_u8(padded.as_ptr()));
        state = clmul_gcm_pmull(veorq_u8(state, block), h_powers[0]);
    }

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((in_out.len() as u64) * 8).to_be_bytes());
    let len_br = vrbitq_u8(vld1q_u8(len_block.as_ptr()));
    state = clmul_gcm_pmull(veorq_u8(state, len_br), h_powers[0]);

    let computed_tag = veorq_u8(vrbitq_u8(state), vld1q_u8(ej0_bytes.as_ptr()));
    let mut computed = [0u8; 16];
    vst1q_u8(computed.as_mut_ptr(), computed_tag);

    // Constant-time comparison
    let mut diff = 0u8;
    for k in 0..16 {
        diff |= computed[k] ^ tag[k];
    }
    if diff != 0 {
        return Err(AeadError::InvalidCiphertext);
    }

    // ── CTR decrypt ────────────────────────────────────────────────────────
    let swap = vld1q_u8(SWAP_MASK.as_ptr());
    let ctr = ctr_inc(vld1q_u8(j0.as_ptr()));
    let mut base = vqtbl1q_u8(ctr, swap);
    let zero = vdupq_n_u32(0);
    let one = vsetq_lane_u32(1, vdupq_n_u32(0), 0);
    let two = vsetq_lane_u32(2, vdupq_n_u32(0), 0);
    let three = vsetq_lane_u32(3, vdupq_n_u32(0), 0);
    let four = vsetq_lane_u32(4, vdupq_n_u32(0), 0);
    let five = vsetq_lane_u32(5, vdupq_n_u32(0), 0);
    let six = vsetq_lane_u32(6, vdupq_n_u32(0), 0);
    let seven = vsetq_lane_u32(7, vdupq_n_u32(0), 0);

    let mut i = 0usize;

    while i + 128 <= n {
        let c1 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), zero)), swap);
        let c2 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), one)), swap);
        let c3 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), two)), swap);
        let c4 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), three)), swap);
        let c5 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), four)), swap);
        let c6 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), five)), swap);
        let c7 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), six)), swap);
        let c8 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), seven)), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);
        let k5 = aes256_enc(rk, c5);
        let k6 = aes256_enc(rk, c6);
        let k7 = aes256_enc(rk, c7);
        let k8 = aes256_enc(rk, c8);

        let ct1 = vld1q_u8(in_out.as_ptr().add(i));
        let ct2 = vld1q_u8(in_out.as_ptr().add(i + 16));
        let ct3 = vld1q_u8(in_out.as_ptr().add(i + 32));
        let ct4 = vld1q_u8(in_out.as_ptr().add(i + 48));
        let ct5 = vld1q_u8(in_out.as_ptr().add(i + 64));
        let ct6 = vld1q_u8(in_out.as_ptr().add(i + 80));
        let ct7 = vld1q_u8(in_out.as_ptr().add(i + 96));
        let ct8 = vld1q_u8(in_out.as_ptr().add(i + 112));

        vst1q_u8(in_out.as_mut_ptr().add(i), veorq_u8(ct1, k1));
        vst1q_u8(in_out.as_mut_ptr().add(i + 16), veorq_u8(ct2, k2));
        vst1q_u8(in_out.as_mut_ptr().add(i + 32), veorq_u8(ct3, k3));
        vst1q_u8(in_out.as_mut_ptr().add(i + 48), veorq_u8(ct4, k4));
        vst1q_u8(in_out.as_mut_ptr().add(i + 64), veorq_u8(ct5, k5));
        vst1q_u8(in_out.as_mut_ptr().add(i + 80), veorq_u8(ct6, k6));
        vst1q_u8(in_out.as_mut_ptr().add(i + 96), veorq_u8(ct7, k7));
        vst1q_u8(in_out.as_mut_ptr().add(i + 112), veorq_u8(ct8, k8));

        base = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), vsetq_lane_u32(8, vdupq_n_u32(0), 0)));
        i += 128;
    }

    while i + 64 <= n {
        let c1 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), zero)), swap);
        let c2 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), one)), swap);
        let c3 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), two)), swap);
        let c4 = vqtbl1q_u8(vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), three)), swap);

        let k1 = aes256_enc(rk, c1);
        let k2 = aes256_enc(rk, c2);
        let k3 = aes256_enc(rk, c3);
        let k4 = aes256_enc(rk, c4);

        let ct1 = vld1q_u8(in_out.as_ptr().add(i));
        let ct2 = vld1q_u8(in_out.as_ptr().add(i + 16));
        let ct3 = vld1q_u8(in_out.as_ptr().add(i + 32));
        let ct4 = vld1q_u8(in_out.as_ptr().add(i + 48));

        vst1q_u8(in_out.as_mut_ptr().add(i), veorq_u8(ct1, k1));
        vst1q_u8(in_out.as_mut_ptr().add(i + 16), veorq_u8(ct2, k2));
        vst1q_u8(in_out.as_mut_ptr().add(i + 32), veorq_u8(ct3, k3));
        vst1q_u8(in_out.as_mut_ptr().add(i + 48), veorq_u8(ct4, k4));

        base = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), four));
        i += 64;
    }

    while i + 16 <= n {
        let k = aes256_enc(rk, vqtbl1q_u8(base, swap));
        let pt = veorq_u8(vld1q_u8(in_out.as_ptr().add(i)), k);
        vst1q_u8(in_out.as_mut_ptr().add(i), pt);
        base = vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(base), one));
        i += 16;
    }
    if i < n {
        let k = aes256_enc(rk, vqtbl1q_u8(base, swap));
        let mut buf = [0u8; 16];
        buf[..n - i].copy_from_slice(&in_out[i..]);
        let pt = veorq_u8(vld1q_u8(buf.as_ptr()), k);
        let mut out_buf = [0u8; 16];
        vst1q_u8(out_buf.as_mut_ptr(), pt);
        in_out[i..].copy_from_slice(&out_buf[..n - i]);
    }

    Ok(())
}

// ── Counter helper ────────────────────────────────────────────────────────────

#[inline]
fn ctr_inc(counter: uint8x16_t) -> uint8x16_t {
    unsafe {
        let swap = vld1q_u8(SWAP_MASK.as_ptr());
        let swapped = vqtbl1q_u8(counter, swap);
        let one = vsetq_lane_u32(1, vdupq_n_u32(0), 0);
        let incremented = vaddq_u32(vreinterpretq_u32_u8(swapped), one);
        vqtbl1q_u8(vreinterpretq_u8_u32(incremented), swap)
    }
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

    fn make_rk(key: &[u8; 32]) -> [uint8x16_t; 15] {
        let soft = crate::aes::aes256::key_expand(key);
        let mut rk = [unsafe { vdupq_n_u8(0) }; 15];
        for i in 0..15 {
            rk[i] = unsafe { vld1q_u8(soft[i].as_ptr()) };
        }
        rk
    }

    fn make_h_powers(key: &[u8; 32]) -> [uint8x16_t; 8] {
        let (bytes, _) = crate::aes::aes256::precompute_ghash_powers(key);
        let mut hp = [unsafe { vdupq_n_u8(0) }; 8];
        for i in 0..8 {
            hp[i] = unsafe { vld1q_u8(bytes[i].as_ptr()) };
        }
        hp
    }

    #[test]
    fn arm_aes256_ecb_vector() {
        let key: [u8; 32] = hb("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let pt: [u8; 16] = hb("6bc1bee22e409f96e93d7e117393172a");
        let expected: [u8; 16] = hb("f3eed1bdb5d2a03c064b5a7e3db181f8");

        let rk = make_rk(&key);
        let ct = unsafe { aes256_enc(&rk, vld1q_u8(pt.as_ptr())) };
        let mut out = [0u8; 16];
        unsafe { vst1q_u8(out.as_mut_ptr(), ct) };

        assert_eq!(out, expected);
    }

    #[test]
    fn arm_matches_soft_gcm() {
        let key: [u8; 32] = hb("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce: [u8; 12] = hb("cafebabefacedbaddecaf888");
        let aad = h("feedfacedeadbeeffeedfacedeadbeef");
        let pt: Vec<u8> = (0u8..=255u8).collect();

        let cipher = crate::aes::aes256::Aes256Gcm::new(&key);
        let mut soft_buf = pt.clone();
        let soft_tag = cipher.encrypt_in_place_soft(&mut soft_buf, &nonce, &aad);

        let rk = make_rk(&key);
        let hp = make_h_powers(&key);
        let mut arm_buf = pt.clone();
        let arm_tag = unsafe { encrypt_armv8(&rk, &hp, &mut arm_buf, &nonce, &aad) };

        assert_eq!(arm_buf, soft_buf);
        assert_eq!(arm_tag, soft_tag);
    }
}
