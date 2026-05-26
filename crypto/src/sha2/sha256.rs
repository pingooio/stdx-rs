#[cfg(target_arch = "aarch64")]
use super::sha256_arm64;
#[cfg(target_arch = "x86_64")]
use super::sha256_amd64;
use crate::{Hash, Hasher};

pub(crate) const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

#[inline]
pub(crate) fn process_block_scalar(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let mut i = 0usize;
    while i < 16 {
        let offset = i * 4;
        w[i] = u32::from_be_bytes([block[offset], block[offset + 1], block[offset + 2], block[offset + 3]]);
        i += 1;
    }

    while i < 64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        i += 1;
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    i = 0;
    while i < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);

        i += 1;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

impl Sha256 {
    #[inline]
    #[allow(unreachable_code)]
    fn process_block(&mut self, block: &[u8; 64]) {
        #[cfg(target_arch = "x86_64")]
        {
            if sha256_amd64::process_block_sha_ni(&mut self.state, block) {
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: aarch64 target in this repository assumes SHA2 instructions are present.
            unsafe {
                sha256_arm64::process_block(&mut self.state, block);
            }
            return;
        }

        process_block_scalar(&mut self.state, block);
    }
}

impl Hasher for Sha256 {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;

    #[inline]
    fn new() -> Self {
        return Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        };
    }

    #[inline]
    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let to_fill = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_fill].copy_from_slice(&data[..to_fill]);
            self.buffer_len += to_fill;
            data = &data[to_fill..];

            if self.buffer_len == 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&self.buffer);
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.process_block(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    #[inline]
    fn sum(mut self) -> Hash {
        let bit_len = self.total_len.wrapping_mul(8);

        let mut tail = [0u8; 128];
        tail[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        tail[self.buffer_len] = 0x80;

        let padding_len = if self.buffer_len < 56 {
            56 - self.buffer_len
        } else {
            120 - self.buffer_len
        };

        let length_offset = self.buffer_len + padding_len;
        tail[length_offset..length_offset + 8].copy_from_slice(&bit_len.to_be_bytes());

        let total_tail_len = length_offset + 8;
        for chunk in tail[..total_tail_len].chunks_exact(64) {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.process_block(&block);
        }

        let mut hash = Hash::new();
        for word in self.state.iter() {
            hash.append(&word.to_be_bytes());
        }

        return hash;
    }
}

#[cfg(test)]
mod tests {
    use super::Sha256;
    use crate::Hasher;

    fn vectors_sha256() -> Vec<(Vec<u8>, &'static str)> {
        vec![
            // RFC 6234 / common SHA-256 vectors
            (
                b"".to_vec(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"a".to_vec(),
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ),
            (
                b"abc".to_vec(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"message digest".to_vec(),
                "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            ),
            (
                b"abcdefghijklmnopqrstuvwxyz".to_vec(),
                "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
                "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                    .to_vec(),
                "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
            ),
            // NIST FIPS 180-4
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                    .to_vec(),
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
            (vec![b'a'; 1_000_000], "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
        ]
    }

    #[test]
    fn known_vectors_single_update() {
        for (input, expected) in vectors_sha256() {
            let mut hasher = Sha256::new();
            hasher.update(&input);
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn known_vectors_incremental() {
        for (bytes, expected) in vectors_sha256() {
            let mut hasher = Sha256::new();
            for chunk in bytes.chunks(3) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn block_boundary_lengths() {
        for len in [55usize, 56, 57, 63, 64, 65, 127, 128, 129] {
            let input = vec![b'a'; len];

            let mut whole = Sha256::new();
            whole.update(&input);
            let whole_sum = whole.sum();

            let mut split = Sha256::new();
            for chunk in input.chunks(7) {
                split.update(chunk);
            }
            let split_sum = split.sum();

            assert_eq!(whole_sum.as_ref(), split_sum.as_ref());
        }
    }
}
