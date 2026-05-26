#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::aarch64::*;

use crate::Error;

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

    Some(unsafe { encrypt_armv8(key, in_out, nonce, aad) })
}

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

    Some(unsafe { decrypt_armv8(key, in_out, tag, nonce, aad) })
}

#[inline]
fn have_features() -> bool {
    std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull")
}

type RoundKeysArm = [uint8x16_t; 15];

#[target_feature(enable = "aes")]
unsafe fn key_expand_armv8(key: &[u8; 32]) -> RoundKeysArm {
    let soft = super::aes256::key_expand(key);
    let mut rk = [vdupq_n_u8(0); 15];
    for i in 0..15 {
        rk[i] = vld1q_u8(soft[i].as_ptr());
    }
    rk
}

#[target_feature(enable = "aes")]
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
fn ctr_inc(counter: &mut [u8; 16]) {
    let c = u32::from_be_bytes(counter[12..16].try_into().unwrap());
    counter[12..16].copy_from_slice(&c.wrapping_add(1).to_be_bytes());
}

#[target_feature(enable = "aes")]
unsafe fn ctr_encrypt(rk: &RoundKeysArm, in_out: &mut [u8], counter: &mut [u8; 16]) {
    let n = in_out.len();
    let mut i = 0usize;

    while i + 16 <= n {
        let ks = aes256_enc(rk, vld1q_u8(counter.as_ptr()));
        let block = vld1q_u8(in_out.as_ptr().add(i));
        let out = veorq_u8(block, ks);
        vst1q_u8(in_out.as_mut_ptr().add(i), out);

        ctr_inc(counter);
        i += 16;
    }

    if i < n {
        let ks = aes256_enc(rk, vld1q_u8(counter.as_ptr()));
        let mut ks_buf = [0u8; 16];
        vst1q_u8(ks_buf.as_mut_ptr(), ks);

        for j in 0..(n - i) {
            in_out[i + j] ^= ks_buf[j];
        }
    }
}

#[target_feature(enable = "aes")]
#[inline]
unsafe fn clmul64_pmull(a: u64, b: u64) -> u128 {
    let product = vmull_p64(core::mem::transmute(a), core::mem::transmute(b));
    core::mem::transmute(product)
}

#[target_feature(enable = "aes")]
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

#[target_feature(enable = "aes")]
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

    let out = reduced.to_le_bytes();
    vld1q_u8(out.as_ptr())
}

#[target_feature(enable = "aes")]
unsafe fn ghash_update_hardware(mut state: uint8x16_t, h: uint8x16_t, data: &[u8]) -> uint8x16_t {
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

#[target_feature(enable = "aes")]
unsafe fn compute_tag_hardware(h: &[u8; 16], aad: &[u8], ciphertext: &[u8], ej0: &[u8; 16]) -> [u8; 16] {
    let h = vrbitq_u8(vld1q_u8(h.as_ptr()));
    let mut state = vdupq_n_u8(0);

    state = ghash_update_hardware(state, h, aad);
    state = ghash_update_hardware(state, h, ciphertext);

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    let len_block = vrbitq_u8(vld1q_u8(len_block.as_ptr()));
    state = clmul_gcm_pmull(veorq_u8(state, len_block), h);

    let tag = veorq_u8(vrbitq_u8(state), vld1q_u8(ej0.as_ptr()));
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), tag);
    out
}

#[target_feature(enable = "aes")]
unsafe fn encrypt_armv8(key: &[u8; 32], in_out: &mut [u8], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    let rk = key_expand_armv8(key);

    let h = {
        let h_vec = aes256_enc(&rk, vdupq_n_u8(0));
        let mut h = [0u8; 16];
        vst1q_u8(h.as_mut_ptr(), h_vec);
        h
    };

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let ej0 = {
        let ej0_vec = aes256_enc(&rk, vld1q_u8(j0.as_ptr()));
        let mut ej0 = [0u8; 16];
        vst1q_u8(ej0.as_mut_ptr(), ej0_vec);
        ej0
    };

    let mut ctr = j0;
    ctr_inc(&mut ctr);

    ctr_encrypt(&rk, in_out, &mut ctr);

    compute_tag_hardware(&h, aad, in_out, &ej0)
}

#[target_feature(enable = "aes")]
unsafe fn decrypt_armv8(
    key: &[u8; 32],
    in_out: &mut [u8],
    tag: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<(), Error> {
    let rk = key_expand_armv8(key);

    let h = {
        let h_vec = aes256_enc(&rk, vdupq_n_u8(0));
        let mut h = [0u8; 16];
        vst1q_u8(h.as_mut_ptr(), h_vec);
        h
    };

    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;

    let ej0 = {
        let ej0_vec = aes256_enc(&rk, vld1q_u8(j0.as_ptr()));
        let mut ej0 = [0u8; 16];
        vst1q_u8(ej0.as_mut_ptr(), ej0_vec);
        ej0
    };

    let expected_tag = compute_tag_hardware(&h, aad, in_out, &ej0);

    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Error::Unspecified);
    }

    let mut ctr = j0;
    ctr_inc(&mut ctr);
    ctr_encrypt(&rk, in_out, &mut ctr);

    Ok(())
}

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

    macro_rules! skip_unless_arm_aes {
        () => {
            if !have_features() {
                eprintln!("Skipping ARMv8 AES test: CPU features not available");
                return;
            }
        };
    }

    #[test]
    fn arm_aes256_ecb_vector() {
        skip_unless_arm_aes!();

        let key: [u8; 32] = hb("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let pt: [u8; 16] = hb("6bc1bee22e409f96e93d7e117393172a");
        let expected: [u8; 16] = hb("f3eed1bdb5d2a03c064b5a7e3db181f8");

        let rk = unsafe { key_expand_armv8(&key) };
        let ct = unsafe { aes256_enc(&rk, vld1q_u8(pt.as_ptr())) };
        let mut out = [0u8; 16];
        unsafe { vst1q_u8(out.as_mut_ptr(), ct) };

        assert_eq!(out, expected);
    }

    #[test]
    fn arm_matches_soft_gcm() {
        skip_unless_arm_aes!();

        let key: [u8; 32] = hb("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce: [u8; 12] = hb("cafebabefacedbaddecaf888");
        let aad = h("feedfacedeadbeeffeedfacedeadbeef");
        let pt: Vec<u8> = (0u8..=255u8).collect();

        let cipher = crate::aes::aes256::Aes256Gcm::new(&key);
        let mut soft_buf = pt.clone();
        let soft_tag = cipher.encrypt_in_place_detached_soft(&mut soft_buf, &nonce, &aad);

        let mut arm_buf = pt.clone();
        let arm_tag = unsafe { encrypt_armv8(&key, &mut arm_buf, &nonce, &aad) };

        assert_eq!(arm_buf, soft_buf);
        assert_eq!(arm_tag, soft_tag);
    }
}
