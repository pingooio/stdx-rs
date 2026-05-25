use crate::{Hash, Hasher, MAX_HASH_LENGTH};

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha1 {
    #[inline]
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];

        let mut i = 0usize;
        while i < 16 {
            let offset = i * 4;
            w[i] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
            i += 1;
        }

        while i < 80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        i = 0;
        while i < 80 {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5a82_7999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ed9_eba1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc_u32)
            } else {
                (b ^ c ^ d, 0xca62_c1d6u32)
            };

            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;

            i += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Hasher for Sha1 {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 20;

    #[inline]
    fn new() -> Self {
        return Sha1 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
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
        // SHA-1 uses big-endian bit length
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

        let mut hash = [0u8; MAX_HASH_LENGTH];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_be_bytes();
            let offset = i * 4;
            hash[offset..offset + 4].copy_from_slice(&bytes);
        }

        return Hash {
            hash,
            length: Self::OUTPUT_SIZE,
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::Hasher;

    use super::Sha1;

    const VECTORS: [(&str, &str); 7] = [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        ("message digest", "c12252ceda8be8994d5fa0290a47231c1d16aae3"),
        ("abcdefghijklmnopqrstuvwxyz", "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "761c457bf73b14d27e9e9265c46f4b4dda11f940",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "50abf5706a150990a08b2c5ea40fa0e585554732",
        ),
    ];

    #[test]
    fn sha1_known_vectors_single_update() {
        for (input, expected) in VECTORS {
            let mut hasher = Sha1::new();
            hasher.update(input.as_bytes());
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha1_known_vectors_incremental() {
        for (input, expected) in VECTORS {
            let bytes = input.as_bytes();
            let mut hasher = Sha1::new();
            for chunk in bytes.chunks(3) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha1_hash_convenience() {
        for (input, expected) in VECTORS {
            let digest = Sha1::hash(input.as_bytes());
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha1_block_boundary_lengths() {
        for len in [55usize, 56, 57, 63, 64, 65, 127, 128, 129] {
            let input = vec![b'a'; len];

            let mut whole = Sha1::new();
            whole.update(&input);
            let whole_sum = whole.sum();

            let mut split = Sha1::new();
            for chunk in input.chunks(7) {
                split.update(chunk);
            }
            let split_sum = split.sum();

            assert_eq!(whole_sum.as_ref(), split_sum.as_ref());
        }
    }

    #[test]
    fn sha1_clone_independence() {
        let mut h1 = Sha1::new();
        h1.update(b"hello");
        let h2 = h1.clone();
        h1.update(b" world");
        let d1 = h1.sum();
        let d2 = h2.sum();
        // different suffixes must produce different digests
        assert_ne!(d1.as_ref(), d2.as_ref());
        // h2 only hashed "hello"
        let expected_hello = Sha1::hash(b"hello");
        assert_eq!(d2.as_ref(), expected_hello.as_ref());
    }
}
