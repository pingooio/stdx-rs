//! Pure Rust implementation of Argon2id (RFC 9106).
//!
//! Argon2id is a memory-hard password hashing function that provides resistance
//! against both side-channel attacks and GPU/ASIC brute-force attacks.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec, vec::Vec};

use crate::blake2::Blake2b;
use crate::Hasher;

/// Argon2 version 1.3 (0x13)
const VERSION: u32 = 0x13;

/// Number of synchronization points (slices per pass)
const SYNC_POINTS: u32 = 4;

/// Block size in bytes (1024 bytes = 128 u64 values)
const BLOCK_SIZE: usize = 1024;

/// Argon2 type constants
const ARGON2D: u32 = 0;
const ARGON2I: u32 = 1;
const ARGON2ID: u32 = 2;

/// A 1024-byte block used in Argon2's memory matrix.
#[derive(Clone)]
struct Block {
    v: [u64; 128],
}

impl Block {
    fn zero() -> Self {
        Block { v: [0u64; 128] }
    }

    fn xor_with(&mut self, other: &Block) {
        for i in 0..128 {
            self.v[i] ^= other.v[i];
        }
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut block = Block::zero();
        for i in 0..128 {
            let offset = i * 8;
            block.v[i] = u64::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        block
    }

    fn to_bytes(&self) -> [u8; BLOCK_SIZE] {
        let mut out = [0u8; BLOCK_SIZE];
        for i in 0..128 {
            let bytes = self.v[i].to_le_bytes();
            let offset = i * 8;
            out[offset..offset + 8].copy_from_slice(&bytes);
        }
        out
    }
}

/// Parameters for Argon2id.
#[derive(Debug, Clone)]
pub struct Params {
    /// Number of passes (iterations). Must be >= 1.
    pub t_cost: u32,
    /// Memory size in KiB. Must be >= 8*p_cost.
    pub m_cost: u32,
    /// Degree of parallelism (number of lanes). Must be >= 1.
    pub p_cost: u32,
    /// Output tag length in bytes. Must be >= 4.
    pub tag_length: u32,
}

impl Params {
    /// Create new Argon2id parameters.
    pub fn new(t_cost: u32, m_cost: u32, p_cost: u32, tag_length: u32) -> Self {
        Params {
            t_cost,
            m_cost,
            p_cost,
            tag_length,
        }
    }
}

impl Default for Params {
    /// Default parameters: t=3, m=64 MiB, p=4, tag=32 bytes (SECOND RECOMMENDED option).
    fn default() -> Self {
        Params {
            t_cost: 3,
            m_cost: 65536,
            p_cost: 4,
            tag_length: 32,
        }
    }
}

/// Argon2 error type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "alloc")]
pub enum Argon2Error {
    /// Invalid parameter
    InvalidParams(&'static str),
    /// Invalid encoded string
    InvalidEncoding(&'static str),
    /// Password verification failed
    VerifyMismatch,
}

#[cfg(feature = "alloc")]
impl core::fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Argon2Error::InvalidParams(msg) => write!(f, "argon2: invalid params: {}", msg),
            Argon2Error::InvalidEncoding(msg) => write!(f, "argon2: invalid encoding: {}", msg),
            Argon2Error::VerifyMismatch => write!(f, "argon2: verification failed"),
        }
    }
}

// ============================================================
// Core Argon2 algorithm
// ============================================================

/// Derive a key using Argon2id.
///
/// This is the main entry point for Argon2id key derivation.
///
/// # Arguments
/// * `password` - The password to hash
/// * `salt` - Salt (recommended 16 bytes)
/// * `secret` - Optional secret key (can be empty)
/// * `ad` - Optional associated data (can be empty)
/// * `params` - Argon2id parameters
///
/// # Returns
/// The derived key as a Vec<u8> of length `params.tag_length`.
#[cfg(feature = "alloc")]
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    params: &Params,
) -> Result<Vec<u8>, Argon2Error> {
    argon2_core(ARGON2ID, password, salt, secret, ad, params)
}

/// Internal function supporting all argon2 types (for testing).
#[cfg(feature = "alloc")]
fn argon2_core(
    argon_type: u32,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    params: &Params,
) -> Result<Vec<u8>, Argon2Error> {
    // Validate parameters
    if params.t_cost < 1 {
        return Err(Argon2Error::InvalidParams("t_cost must be >= 1"));
    }
    if params.p_cost < 1 {
        return Err(Argon2Error::InvalidParams("p_cost must be >= 1"));
    }
    if params.tag_length < 4 {
        return Err(Argon2Error::InvalidParams("tag_length must be >= 4"));
    }
    if params.m_cost < 8 * params.p_cost {
        return Err(Argon2Error::InvalidParams("m_cost must be >= 8*p_cost"));
    }

    let p = params.p_cost;
    let t = params.t_cost;
    let m = params.m_cost;
    let tag_length = params.tag_length;

    // Step 1: Compute H_0
    let h0 = compute_h0(argon_type, password, salt, secret, ad, p, tag_length, m, t);

    // Step 2: Determine actual memory size m' (rounded down to multiple of 4*p)
    let m_prime = 4 * p * (m / (4 * p));
    let q = m_prime / p; // columns per lane

    // Allocate memory as m' blocks
    let mut memory: Vec<Block> = vec![Block::zero(); m_prime as usize];

    // Step 3 & 4: Compute B[i][0] and B[i][1] for all lanes
    for i in 0..p {
        // B[i][0] = H'^(1024)(H_0 || LE32(0) || LE32(i))
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(&h0);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&i.to_le_bytes());
        let block_bytes = variable_length_hash(&input, BLOCK_SIZE as u32);
        memory[(i * q) as usize] = Block::from_bytes(&block_bytes);

        // B[i][1] = H'^(1024)(H_0 || LE32(1) || LE32(i))
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(&h0);
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&i.to_le_bytes());
        let block_bytes = variable_length_hash(&input, BLOCK_SIZE as u32);
        memory[(i * q + 1) as usize] = Block::from_bytes(&block_bytes);
    }

    // Steps 5-6: Fill memory
    for pass in 0..t {
        for slice in 0..SYNC_POINTS {
            for lane in 0..p {
                fill_segment(
                    &mut memory,
                    argon_type,
                    pass,
                    lane,
                    slice,
                    p,
                    q,
                    t,
                    m_prime,
                );
            }
        }
    }

    // Step 7: Compute final block C = XOR of last column
    let mut final_block = memory[(q - 1) as usize].clone();
    for i in 1..p {
        let idx = (i * q + q - 1) as usize;
        final_block.xor_with(&memory[idx]);
    }

    // Step 8: Output tag = H'^T(C)
    let final_bytes = final_block.to_bytes();
    let tag = variable_length_hash(&final_bytes, tag_length);

    Ok(tag)
}

/// Fill a segment of the memory matrix.
#[cfg(feature = "alloc")]
fn fill_segment(
    memory: &mut [Block],
    argon_type: u32,
    pass: u32,
    lane: u32,
    slice: u32,
    lanes: u32,
    q: u32,       // columns per lane
    t: u32,       // total passes
    m_prime: u32, // total blocks
) {
    let segment_length = q / SYNC_POINTS;

    // For Argon2i and Argon2id (first half of first pass), precompute pseudo-random values
    let mut pseudo_rands: Vec<u64> = Vec::new();
    let need_pseudo_rands = argon_type == ARGON2I
        || (argon_type == ARGON2ID && pass == 0 && slice < 2);

    if need_pseudo_rands {
        pseudo_rands = generate_addresses(pass, lane, slice, lanes, t, argon_type, m_prime, segment_length);
    }

    let start_index = if pass == 0 && slice == 0 { 2 } else { 0 };

    for s in start_index..segment_length {
        let j = slice * segment_length + s; // current column index in this lane
        let cur_index = (lane * q + j) as usize;

        // Previous block index
        let prev_index = if j == 0 {
            (lane * q + q - 1) as usize
        } else {
            (lane * q + j - 1) as usize
        };

        // Determine J1 and J2
        let (j1, j2) = if need_pseudo_rands {
            let val = pseudo_rands[s as usize];
            ((val & 0xFFFFFFFF) as u32, (val >> 32) as u32)
        } else {
            // Argon2d mode: use first 64 bits of previous block
            let prev = &memory[prev_index];
            (prev.v[0] as u32, (prev.v[0] >> 32) as u32)
        };

        // Map J1, J2 to reference block index
        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            j2 % lanes
        };

        let ref_index = index_alpha(pass, slice, lanes, segment_length, j, q, ref_lane == lane, j1);
        let ref_block_index = (ref_lane * q + ref_index) as usize;

        // Compute new block
        let new_block = if pass == 0 {
            compress(&memory[prev_index], &memory[ref_block_index])
        } else {
            let mut new = compress(&memory[prev_index], &memory[ref_block_index]);
            new.xor_with(&memory[cur_index]);
            new
        };

        memory[cur_index] = new_block;
    }
}

/// Generate pseudo-random addresses for Argon2i/Argon2id data-independent addressing.
#[cfg(feature = "alloc")]
fn generate_addresses(
    pass: u32,
    lane: u32,
    slice: u32,
    lanes: u32,
    t: u32,
    argon_type: u32,
    m_prime: u32,
    segment_length: u32,
) -> Vec<u64> {
    let mut pseudo_rands = Vec::with_capacity(segment_length as usize);

    // Build input block
    let mut input = Block::zero();
    input.v[0] = pass as u64;
    input.v[1] = lane as u64;
    input.v[2] = slice as u64;
    input.v[3] = m_prime as u64;
    input.v[4] = t as u64;
    input.v[5] = argon_type as u64;

    let zero_block = Block::zero();
    // Generate addresses in groups of 128 (each block gives 128 u64 values)
    let mut counter = 1u64;
    while pseudo_rands.len() < segment_length as usize {
        input.v[6] = counter;
        let tmp = compress(&zero_block, &input);
        let addr_block = compress(&zero_block, &tmp);

        for i in 0..128 {
            if pseudo_rands.len() >= segment_length as usize {
                break;
            }
            pseudo_rands.push(addr_block.v[i]);
        }
        counter += 1;
    }

    pseudo_rands
}

/// Map J1 to a reference block index within the available set W.
fn index_alpha(
    pass: u32,
    slice: u32,
    _lanes: u32,
    segment_length: u32,
    index_in_segment: u32,
    q: u32,
    same_lane: bool,
    j1: u32,
) -> u32 {
    // Determine reference area size
    let reference_area_size = if pass == 0 {
        // First pass: can only reference blocks already computed
        if slice == 0 {
            // Same lane, same slice, only previous blocks
            index_in_segment.saturating_sub(1)
        } else {
            if same_lane {
                slice * segment_length + index_in_segment - 1
            } else {
                slice * segment_length - if index_in_segment == 0 { 1 } else { 0 }
            }
        }
    } else {
        // Subsequent passes: all blocks except the current one
        if same_lane {
            q - segment_length + index_in_segment - 1
        } else {
            q - segment_length - if index_in_segment == 0 { 1 } else { 0 }
        }
    };

    if reference_area_size == 0 {
        return 0;
    }

    // Map J1 to an index with bias toward recent blocks
    let j1_64 = j1 as u64;
    let x = (j1_64 * j1_64) >> 32;
    let y = (reference_area_size as u64 * x) >> 32;
    let relative_position = (reference_area_size as u64 - 1 - y) as u32;

    // Compute starting position
    let start_position = if pass == 0 {
        0
    } else {
        if slice == SYNC_POINTS - 1 {
            0
        } else {
            (slice + 1) * segment_length
        }
    };

    (start_position + relative_position) % q
}

/// Compute H_0 as defined in the RFC.
#[cfg(feature = "alloc")]
fn compute_h0(
    argon_type: u32,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    p: u32,
    tag_length: u32,
    m: u32,
    t: u32,
) -> [u8; 64] {
    let mut blake = Blake2b::new_keyed(&[], 64);

    blake.update(&p.to_le_bytes());
    blake.update(&tag_length.to_le_bytes());
    blake.update(&m.to_le_bytes());
    blake.update(&t.to_le_bytes());
    blake.update(&VERSION.to_le_bytes());
    blake.update(&argon_type.to_le_bytes());
    blake.update(&(password.len() as u32).to_le_bytes());
    blake.update(password);
    blake.update(&(salt.len() as u32).to_le_bytes());
    blake.update(salt);
    blake.update(&(secret.len() as u32).to_le_bytes());
    blake.update(secret);
    blake.update(&(ad.len() as u32).to_le_bytes());
    blake.update(ad);

    let hash = blake.sum();
    let mut result = [0u8; 64];
    result.copy_from_slice(&hash.as_ref()[..64]);
    result
}

/// Variable-length hash function H' as defined in RFC 9106 Section 3.3.
///
/// Uses Blake2b to produce output of arbitrary length.
#[cfg(feature = "alloc")]
fn variable_length_hash(input: &[u8], tag_length: u32) -> Vec<u8> {
    if tag_length <= 64 {
        // Short output: H'^T(A) = H^T(LE32(T)||A)
        let mut blake = Blake2b::new_keyed(&[], tag_length as usize);
        blake.update(&tag_length.to_le_bytes());
        blake.update(input);
        let hash = blake.sum();
        hash.as_ref()[..tag_length as usize].to_vec()
    } else {
        // Long output
        let r = (tag_length / 32) - 1; // ceil(T/32)-2, but since T>64, this simplifies
        // Actually: r = ceil(T/32) - 2
        // For T > 64: r = ceil(T/32) - 2
        let r = ((tag_length + 31) / 32) - 2;

        let mut result = Vec::with_capacity(tag_length as usize);

        // V_1 = H^(64)(LE32(T)||A)
        let mut blake = Blake2b::new_keyed(&[], 64);
        blake.update(&tag_length.to_le_bytes());
        blake.update(input);
        let hash = blake.sum();
        let mut v_prev = hash.as_ref()[..64].to_vec();

        // W_1 = first 32 bytes of V_1
        result.extend_from_slice(&v_prev[..32]);

        // V_2 through V_r
        for _ in 2..=r {
            let mut blake = Blake2b::new_keyed(&[], 64);
            blake.update(&v_prev);
            let hash = blake.sum();
            v_prev = hash.as_ref()[..64].to_vec();
            result.extend_from_slice(&v_prev[..32]);
        }

        // V_{r+1} = H^(T-32*r)(V_r)
        let remaining = tag_length - 32 * r;
        let mut blake = Blake2b::new_keyed(&[], remaining as usize);
        blake.update(&v_prev);
        let hash = blake.sum();
        result.extend_from_slice(&hash.as_ref()[..remaining as usize]);

        result
    }
}

// ============================================================
// Compression function G and Permutation P
// ============================================================

/// Compression function G(X, Y) -> Z XOR R
///
/// Operates on two 1024-byte blocks.
fn compress(x: &Block, y: &Block) -> Block {
    // R = X XOR Y
    let mut r = Block::zero();
    for i in 0..128 {
        r.v[i] = x.v[i] ^ y.v[i];
    }

    let mut q = r.clone();

    // Apply P to each row of 8x8 matrix of 16-byte registers
    // Each row has 8 registers of 16 bytes = 8*2 u64 = 16 u64 values
    for row in 0..8 {
        let base = row * 16;
        permutation_p(&mut q.v[base..base + 16]);
    }

    // Apply P to each column
    // Columns: position i in each row
    for col in 0..8 {
        let mut buf = [0u64; 16];
        for row in 0..8 {
            let src = row * 16 + col * 2;
            buf[row * 2] = q.v[src];
            buf[row * 2 + 1] = q.v[src + 1];
        }
        permutation_p(&mut buf);
        for row in 0..8 {
            let dst = row * 16 + col * 2;
            q.v[dst] = buf[row * 2];
            q.v[dst + 1] = buf[row * 2 + 1];
        }
    }

    // Z XOR R
    for i in 0..128 {
        q.v[i] ^= r.v[i];
    }

    q
}

/// Permutation P based on the round function of BLAKE2b.
///
/// Operates on 128 bytes (16 u64 values) viewed as a 4x4 matrix.
fn permutation_p(v: &mut [u64]) {
    // Column-wise
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);

    // Diagonal-wise
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// The GB mixing function for Argon2.
///
/// Unlike BLAKE2b's G, this uses multiplication for additional hardness.
#[inline(always)]
fn gb(v: &mut [u64], a: usize, b: usize, c: usize, d: usize) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(
        2u64.wrapping_mul((v[a] as u32 as u64).wrapping_mul(v[b] as u32 as u64)),
    );
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(
        2u64.wrapping_mul((v[c] as u32 as u64).wrapping_mul(v[d] as u32 as u64)),
    );
    v[b] = (v[b] ^ v[c]).rotate_right(24);

    v[a] = v[a].wrapping_add(v[b]).wrapping_add(
        2u64.wrapping_mul((v[a] as u32 as u64).wrapping_mul(v[b] as u32 as u64)),
    );
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(
        2u64.wrapping_mul((v[c] as u32 as u64).wrapping_mul(v[d] as u32 as u64)),
    );
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

// ============================================================
// PHC String Format encode/decode
// ============================================================

/// Encode an Argon2id hash in the PHC string format:
/// `$argon2id$v=19$m=<m_cost>,t=<t_cost>,p=<p_cost>$<salt_b64>$<hash_b64>`
///
/// Uses base64 encoding without padding (standard alphabet with +/ replaced by the
/// PHC-standard base64 which is actually the standard base64 without padding).
#[cfg(feature = "alloc")]
pub fn encode_phc(params: &Params, salt: &[u8], tag: &[u8]) -> String {
    let salt_b64 = base64_encode_no_pad(salt);
    let tag_b64 = base64_encode_no_pad(tag);
    alloc::format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        params.m_cost, params.t_cost, params.p_cost, salt_b64, tag_b64
    )
}

/// Decode an Argon2id PHC string format into (params, salt, tag).
///
/// Expected format: `$argon2id$v=19$m=<m>,t=<t>,p=<p>$<salt_b64>$<hash_b64>`
#[cfg(feature = "alloc")]
pub fn decode_phc(encoded: &str) -> Result<(Params, Vec<u8>, Vec<u8>), Argon2Error> {
    let parts: Vec<&str> = encoded.split('$').collect();
    // Parts: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
    if parts.len() != 6 {
        return Err(Argon2Error::InvalidEncoding("invalid PHC string format"));
    }
    if parts[0] != "" {
        return Err(Argon2Error::InvalidEncoding("must start with $"));
    }
    if parts[1] != "argon2id" {
        return Err(Argon2Error::InvalidEncoding("unsupported algorithm"));
    }
    if parts[2] != "v=19" {
        return Err(Argon2Error::InvalidEncoding("unsupported version"));
    }

    // Parse params
    let param_parts: Vec<&str> = parts[3].split(',').collect();
    if param_parts.len() != 3 {
        return Err(Argon2Error::InvalidEncoding("invalid parameters"));
    }

    let m_cost = parse_param(param_parts[0], "m=")?;
    let t_cost = parse_param(param_parts[1], "t=")?;
    let p_cost = parse_param(param_parts[2], "p=")?;

    let salt = base64_decode_no_pad(parts[4])
        .map_err(|_| Argon2Error::InvalidEncoding("invalid base64 in salt"))?;
    let tag = base64_decode_no_pad(parts[5])
        .map_err(|_| Argon2Error::InvalidEncoding("invalid base64 in hash"))?;

    let params = Params {
        t_cost,
        m_cost,
        p_cost,
        tag_length: tag.len() as u32,
    };

    Ok((params, salt, tag))
}

/// Hash a password and return the PHC-encoded string.
#[cfg(feature = "alloc")]
pub fn hash_password(password: &[u8], salt: &[u8], params: &Params) -> Result<String, Argon2Error> {
    let tag = derive_key(password, salt, &[], &[], params)?;
    Ok(encode_phc(params, salt, &tag))
}

/// Verify a password against a PHC-encoded hash string.
#[cfg(feature = "alloc")]
pub fn verify_password(password: &[u8], encoded: &str) -> Result<(), Argon2Error> {
    let (params, salt, expected_tag) = decode_phc(encoded)?;
    let computed_tag = derive_key(password, &salt, &[], &[], &params)?;
    if constant_time_eq::constant_time_eq(&computed_tag, &expected_tag) {
        Ok(())
    } else {
        Err(Argon2Error::VerifyMismatch)
    }
}

// ============================================================
// Base64 helpers (PHC format uses standard base64 without padding)
// ============================================================

#[cfg(feature = "alloc")]
fn base64_encode_no_pad(input: &[u8]) -> String {
    base64::encode_with_alphabet(input, base64::Alphabet::StandardNoPadding)
}

#[cfg(feature = "alloc")]
fn base64_decode_no_pad(input: &str) -> Result<Vec<u8>, ()> {
    base64::decode_with_alphabet(input.as_bytes(), base64::Alphabet::StandardNoPadding).map_err(|_| ())
}

#[cfg(feature = "alloc")]
fn parse_param(s: &str, prefix: &str) -> Result<u32, Argon2Error> {
    if !s.starts_with(prefix) {
        return Err(Argon2Error::InvalidEncoding("invalid parameter prefix"));
    }
    s[prefix.len()..]
        .parse::<u32>()
        .map_err(|_| Argon2Error::InvalidEncoding("invalid parameter value"))
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper for tests that need all 3 argon2 variants
    fn derive_key_typed(
        argon_type: u32,
        password: &[u8],
        salt: &[u8],
        secret: &[u8],
        ad: &[u8],
        t_cost: u32,
        m_cost: u32,
        p_cost: u32,
        tag_length: u32,
    ) -> Vec<u8> {
        let params = Params::new(t_cost, m_cost, p_cost, tag_length);
        argon2_core(argon_type, password, salt, secret, ad, &params).unwrap()
    }

    // RFC 9106 Section 5.3 - Argon2id test vector
    #[test]
    fn test_rfc9106_argon2id() {
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];

        let expected = hex::decode(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
        )
        .unwrap();

        let result = derive_key_typed(ARGON2ID, &password, &salt, &secret, &ad, 3, 32, 4, 32);
        assert_eq!(result, expected, "RFC 9106 Argon2id test vector failed");
    }

    // RFC 9106 Section 5.1 - Argon2d test vector
    #[test]
    fn test_rfc9106_argon2d() {
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];

        let expected = hex::decode(
            "512b391b6f11629753 71d30919734294f868e3be3984f3c1a13a4db9fabe4acb"
                .replace(" ", ""),
        )
        .unwrap();

        let result = derive_key_typed(ARGON2D, &password, &salt, &secret, &ad, 3, 32, 4, 32);
        assert_eq!(result, expected, "RFC 9106 Argon2d test vector failed");
    }

    // RFC 9106 Section 5.2 - Argon2i test vector
    #[test]
    fn test_rfc9106_argon2i() {
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];

        let expected = hex::decode(
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
        )
        .unwrap();

        let result = derive_key_typed(ARGON2I, &password, &salt, &secret, &ad, 3, 32, 4, 32);
        assert_eq!(result, expected, "RFC 9106 Argon2i test vector failed");
    }

    // Test vectors from Go's golang.org/x/crypto/argon2 test suite
    // password = "password", salt = "somesalt", no secret, no AD
    struct GoTestVector {
        mode: u32,
        time: u32,
        memory: u32,
        threads: u32,
        hash: &'static str,
    }

    const GO_TEST_VECTORS: &[GoTestVector] = &[
        GoTestVector { mode: ARGON2I, time: 1, memory: 64, threads: 1, hash: "b9c401d1844a67d50eae3967dc28870b22e508092e861a37" },
        GoTestVector { mode: ARGON2D, time: 1, memory: 64, threads: 1, hash: "8727405fd07c32c78d64f547f24150d3f2e703a89f981a19" },
        GoTestVector { mode: ARGON2ID, time: 1, memory: 64, threads: 1, hash: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb" },
        GoTestVector { mode: ARGON2I, time: 2, memory: 64, threads: 1, hash: "8cf3d8f76a6617afe35fac48eb0b7433a9a670ca4a07ed64" },
        GoTestVector { mode: ARGON2D, time: 2, memory: 64, threads: 1, hash: "3be9ec79a69b75d3752acb59a1fbb8b295a46529c48fbb75" },
        GoTestVector { mode: ARGON2ID, time: 2, memory: 64, threads: 1, hash: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7" },
        GoTestVector { mode: ARGON2I, time: 2, memory: 64, threads: 2, hash: "2089f3e78a799720f80af806553128f29b132cafe40d059f" },
        GoTestVector { mode: ARGON2D, time: 2, memory: 64, threads: 2, hash: "68e2462c98b8bc6bb60ec68db418ae2c9ed24fc6748a40e9" },
        GoTestVector { mode: ARGON2ID, time: 2, memory: 64, threads: 2, hash: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362" },
        GoTestVector { mode: ARGON2I, time: 3, memory: 256, threads: 2, hash: "f5bbf5d4c3836af13193053155b73ec7476a6a2eb93fd5e6" },
        GoTestVector { mode: ARGON2D, time: 3, memory: 256, threads: 2, hash: "f4f0669218eaf3641f39cc97efb915721102f4b128211ef2" },
        GoTestVector { mode: ARGON2ID, time: 3, memory: 256, threads: 2, hash: "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b" },
        GoTestVector { mode: ARGON2I, time: 4, memory: 4096, threads: 4, hash: "a11f7b7f3f93f02ad4bddb59ab62d121e278369288a0d0e7" },
        GoTestVector { mode: ARGON2D, time: 4, memory: 4096, threads: 4, hash: "935598181aa8dc2b720914aa6435ac8d3e3a4210c5b0fb2d" },
        GoTestVector { mode: ARGON2ID, time: 4, memory: 4096, threads: 4, hash: "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a" },
        GoTestVector { mode: ARGON2I, time: 4, memory: 1024, threads: 8, hash: "0cdd3956aa35e6b475a7b0c63488822f774f15b43f6e6e17" },
        GoTestVector { mode: ARGON2D, time: 4, memory: 1024, threads: 8, hash: "83604fc2ad0589b9d055578f4d3cc55bc616df3578a896e9" },
        GoTestVector { mode: ARGON2ID, time: 4, memory: 1024, threads: 8, hash: "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f" },
        GoTestVector { mode: ARGON2I, time: 2, memory: 64, threads: 3, hash: "5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6" },
        GoTestVector { mode: ARGON2D, time: 2, memory: 64, threads: 3, hash: "22474a423bda2ccd36ec9afd5119e5c8949798cadf659f51" },
        GoTestVector { mode: ARGON2ID, time: 2, memory: 64, threads: 3, hash: "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079" },
        GoTestVector { mode: ARGON2I, time: 3, memory: 1024, threads: 6, hash: "d236b29c2b2a09babee842b0dec6aa1e83ccbdea8023dced" },
        GoTestVector { mode: ARGON2D, time: 3, memory: 1024, threads: 6, hash: "a3351b0319a53229152023d9206902f4ef59661cdca89481" },
        GoTestVector { mode: ARGON2ID, time: 3, memory: 1024, threads: 6, hash: "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016" },
    ];

    #[test]
    fn test_go_vectors() {
        let password = b"password";
        let salt = b"somesalt";

        for (i, v) in GO_TEST_VECTORS.iter().enumerate() {
            let expected = hex::decode(v.hash).unwrap();
            let result = derive_key_typed(
                v.mode,
                password,
                salt,
                &[],
                &[],
                v.time,
                v.memory,
                v.threads,
                expected.len() as u32,
            );
            assert_eq!(
                result, expected,
                "Go test vector {} failed (mode={}, t={}, m={}, p={})",
                i, v.mode, v.time, v.memory, v.threads
            );
        }
    }

    // Test PHC string format encoding/decoding
    #[test]
    fn test_phc_encode_decode() {
        let params = Params::new(3, 65536, 4, 32);
        let salt = b"somesalt12345678";
        let tag = vec![0xAB; 32];

        let encoded = encode_phc(&params, salt, &tag);
        assert!(encoded.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"));

        let (decoded_params, decoded_salt, decoded_tag) = decode_phc(&encoded).unwrap();
        assert_eq!(decoded_params.t_cost, 3);
        assert_eq!(decoded_params.m_cost, 65536);
        assert_eq!(decoded_params.p_cost, 4);
        assert_eq!(decoded_params.tag_length, 32);
        assert_eq!(decoded_salt, salt);
        assert_eq!(decoded_tag, tag);
    }

    // Test hash_password and verify_password
    #[test]
    fn test_hash_and_verify() {
        let password = b"correct horse battery staple";
        let salt = b"randomsalt123456";
        let params = Params::new(1, 64, 1, 32);

        let encoded = hash_password(password, salt, &params).unwrap();
        assert!(verify_password(password, &encoded).is_ok());
        assert_eq!(
            verify_password(b"wrong password", &encoded),
            Err(Argon2Error::VerifyMismatch)
        );
    }

    // Test invalid PHC strings
    #[test]
    fn test_decode_phc_invalid() {
        assert!(decode_phc("").is_err());
        assert!(decode_phc("$argon2i$v=19$m=4096,t=3,p=1$salt$hash").is_err());
        assert!(decode_phc("$argon2id$v=16$m=4096,t=3,p=1$salt$hash").is_err());
        assert!(decode_phc("not a phc string").is_err());
    }

    // Test parameter validation
    #[test]
    fn test_invalid_params() {
        let password = b"password";
        let salt = b"salt";
        let params = Params::new(0, 64, 1, 32);
        assert!(derive_key(password, salt, &[], &[], &params).is_err());

        let params = Params::new(1, 4, 1, 32); // m_cost too small
        assert!(derive_key(password, salt, &[], &[], &params).is_err());

        let params = Params::new(1, 64, 1, 3); // tag_length too small
        assert!(derive_key(password, salt, &[], &[], &params).is_err());
    }

    // Test variable-length hash function H'
    #[test]
    fn test_variable_length_hash_short() {
        // For T <= 64, H'^T(A) = H^T(LE32(T)||A)
        let input = b"test input";
        let result = variable_length_hash(input, 32);
        assert_eq!(result.len(), 32);

        // Same input should give same output
        let result2 = variable_length_hash(input, 32);
        assert_eq!(result, result2);

        // Different length should give different output
        let result3 = variable_length_hash(input, 48);
        assert_eq!(result3.len(), 48);
        assert_ne!(&result[..], &result3[..32]);
    }

    // Test variable-length hash for long outputs
    #[test]
    fn test_variable_length_hash_long() {
        let input = b"test input for long hash";
        let result = variable_length_hash(input, 128);
        assert_eq!(result.len(), 128);

        let result2 = variable_length_hash(input, 1024);
        assert_eq!(result2.len(), 1024);
    }

    // Test that derive_key with Argon2id works with empty secret/ad
    #[test]
    fn test_argon2id_no_secret_no_ad() {
        let password = b"password";
        let salt = b"somesalt";
        let params = Params::new(1, 64, 1, 32);

        let result = derive_key(password, salt, &[], &[], &params).unwrap();
        assert_eq!(result.len(), 32);

        // Verify it matches the Go vector
        let expected = hex::decode("655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb").unwrap();
        let result2 = derive_key_typed(ARGON2ID, password, salt, &[], &[], 1, 64, 1, expected.len() as u32);
        assert_eq!(result2, expected);
    }

    // Test with 1 pass, minimum memory
    #[test]
    fn test_argon2id_single_pass() {
        let password = b"password";
        let salt = b"saltsalt";
        let params = Params::new(1, 8, 1, 32);
        let result = derive_key(password, salt, &[], &[], &params).unwrap();
        assert_eq!(result.len(), 32);
    }

    // Test multiple lanes
    #[test]
    fn test_argon2id_multiple_lanes() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let params = Params::new(1, 64, 4, 32);
        let result = derive_key(password, salt, &[], &[], &params).unwrap();
        assert_eq!(result.len(), 32);
    }

    // Test that different passwords produce different hashes
    #[test]
    fn test_different_passwords() {
        let salt = b"saltsaltsaltsalt";
        let params = Params::new(1, 64, 1, 32);

        let h1 = derive_key(b"password1", salt, &[], &[], &params).unwrap();
        let h2 = derive_key(b"password2", salt, &[], &[], &params).unwrap();
        assert_ne!(h1, h2);
    }

    // Test that different salts produce different hashes
    #[test]
    fn test_different_salts() {
        let password = b"password";
        let params = Params::new(1, 64, 1, 32);

        let h1 = derive_key(password, b"salt1234salt1234", &[], &[], &params).unwrap();
        let h2 = derive_key(password, b"salt5678salt5678", &[], &[], &params).unwrap();
        assert_ne!(h1, h2);
    }

    // Additional test with longer tag
    #[test]
    fn test_argon2id_long_tag() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let params = Params::new(1, 64, 1, 64);
        let result = derive_key(password, salt, &[], &[], &params).unwrap();
        assert_eq!(result.len(), 64);
    }

    // Test encoding roundtrip with known hash
    #[test]
    fn test_phc_roundtrip_with_known_vector() {
        let password = b"password";
        let salt = b"somesalt";
        let params = Params::new(1, 64, 1, 24);

        let tag = derive_key(password, salt, &[], &[], &params).unwrap();
        let encoded = encode_phc(&params, salt, &tag);
        let (dec_params, dec_salt, dec_tag) = decode_phc(&encoded).unwrap();

        assert_eq!(dec_params.m_cost, params.m_cost);
        assert_eq!(dec_params.t_cost, params.t_cost);
        assert_eq!(dec_params.p_cost, params.p_cost);
        assert_eq!(dec_salt, salt);
        assert_eq!(dec_tag, tag);
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    
    #[test]
    fn debug_h0() {
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];
        
        let h0 = compute_h0(ARGON2ID, &password, &salt, &secret, &ad, 4, 32, 32, 3);
        let expected = "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997";
        let got = hex::encode(&h0);
        eprintln!("H0 got:      {}", got);
        eprintln!("H0 expected: {}", expected);
        assert_eq!(got, expected, "H0 mismatch");
    }
}

#[cfg(test)]
mod debug_tests2 {
    use super::*;
    
    #[test]
    fn debug_first_block() {
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];
        
        let h0 = compute_h0(ARGON2ID, &password, &salt, &secret, &ad, 4, 32, 32, 3);
        
        // B[0][0] = H'^(1024)(H_0 || LE32(0) || LE32(0))
        let mut input = Vec::with_capacity(72);
        input.extend_from_slice(&h0);
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        let block_bytes = variable_length_hash(&input, 1024);
        
        let block = Block::from_bytes(&block_bytes);
        // RFC says: Block 0000 [  0]: 6b2e09f10671bd43
        let expected_first_u64: u64 = 0x6b2e09f10671bd43;
        eprintln!("B[0][0].v[0] = {:016x}", block.v[0]);
        eprintln!("Expected     = {:016x}", expected_first_u64);
        assert_eq!(block.v[0], expected_first_u64, "First block first u64 mismatch");
    }
}

#[cfg(test)]
mod debug_tests3 {
    use super::*;
    
    #[test]
    fn debug_fill_pass0() {
        // RFC test: Argon2id, p=4, m=32, t=3, tag=32
        // m'=32, q=8, segment_length=2
        let password = vec![0x01u8; 32];
        let salt = vec![0x02u8; 16];
        let secret = vec![0x03u8; 8];
        let ad = vec![0x04u8; 12];
        
        let p = 4u32;
        let m_prime = 32u32;
        let q = 8u32;
        let t = 3u32;
        
        let h0 = compute_h0(ARGON2ID, &password, &salt, &secret, &ad, p, 32, 32, t);
        
        let mut memory: Vec<Block> = vec![Block::zero(); m_prime as usize];
        
        // Fill initial blocks
        for i in 0..p {
            let mut input = Vec::with_capacity(72);
            input.extend_from_slice(&h0);
            input.extend_from_slice(&0u32.to_le_bytes());
            input.extend_from_slice(&i.to_le_bytes());
            let block_bytes = variable_length_hash(&input, 1024);
            memory[(i * q) as usize] = Block::from_bytes(&block_bytes);
            
            let mut input = Vec::with_capacity(72);
            input.extend_from_slice(&h0);
            input.extend_from_slice(&1u32.to_le_bytes());
            input.extend_from_slice(&i.to_le_bytes());
            let block_bytes = variable_length_hash(&input, 1024);
            memory[(i * q + 1) as usize] = Block::from_bytes(&block_bytes);
        }
        
        // Now do pass 0
        for slice in 0..4u32 {
            for lane in 0..p {
                fill_segment(&mut memory, ARGON2ID, 0, lane, slice, p, q, t, m_prime);
            }
        }
        
        // After pass 0: Block 0031 [127] = 81f88b28683ea8e5
        // Block 31 = lane 3, column 7 (3*8+7=31)
        eprintln!("Block 0031 [127] = {:016x}", memory[31].v[127]);
        eprintln!("Expected         = {:016x}", 0x81f88b28683ea8e5u64);
        
        // Block 0000 [0] after pass 0
        eprintln!("Block 0000 [0] = {:016x}", memory[0].v[0]);
        eprintln!("Expected       = {:016x}", 0x6b2e09f10671bd43u64);
        
        assert_eq!(memory[31].v[127], 0x81f88b28683ea8e5u64, "Block 31 last u64 after pass 0");
    }
}
