use crate::{Hash, Hasher, MAX_HASH_LENGTH};

#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Md5 {
    #[inline]
    fn process_block(&mut self, block: &[u8; 64]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
            14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10,
            15, 21, 6, 10, 15, 21,
        ];

        const K: [u32; 64] = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
            0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
            0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
            0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
            0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
            0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];

        let mut m = [0u32; 16];
        let mut i = 0usize;
        while i < 16 {
            let offset = i * 4;
            m[i] = u32::from_le_bytes([block[offset], block[offset + 1], block[offset + 2], block[offset + 3]]);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        i = 0;
        while i < 64 {
            let (f, g) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7 * i) % 16)
            };

            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = tmp;

            i += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Hasher for Md5 {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 16;

    #[inline]
    fn new() -> Self {
        return Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
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
        tail[length_offset..length_offset + 8].copy_from_slice(&bit_len.to_le_bytes());

        let total_tail_len = length_offset + 8;
        for chunk in tail[..total_tail_len].chunks_exact(64) {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.process_block(&block);
        }

        let mut hash = [0u8; MAX_HASH_LENGTH];
        for (i, word) in self.state.iter().enumerate() {
            let bytes = word.to_le_bytes();
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
    use super::Md5;
    use crate::Hasher;

    const VECTORS: [(&str, &str); 7] = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];

    #[test]
    fn md5_known_vectors_single_update() {
        for (input, expected) in VECTORS {
            let mut hasher = Md5::new();
            hasher.update(input.as_bytes());
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn md5_known_vectors_incremental() {
        for (input, expected) in VECTORS {
            let bytes = input.as_bytes();
            let mut hasher = Md5::new();
            for chunk in bytes.chunks(3) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn md5_block_boundary_lengths() {
        for len in [55usize, 56, 57, 63, 64, 65, 127, 128, 129] {
            let input = vec![b'a'; len];

            let mut whole = Md5::new();
            whole.update(&input);
            let whole_sum = whole.sum();

            let mut split = Md5::new();
            for chunk in input.chunks(7) {
                split.update(chunk);
            }
            let split_sum = split.sum();

            assert_eq!(whole_sum.as_ref(), split_sum.as_ref());
        }
    }
}
