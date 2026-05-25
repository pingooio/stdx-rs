use crate::{Hash, Hasher, MAX_HASH_LENGTH};

const SHA256_K: [u32; 64] = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
];

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    #[inline]
    fn process_block(&mut self, block: &[u8; 64]) {
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
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

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

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Hasher for Sha256 {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = 32;

    #[inline]
    fn new() -> Self {
        return Sha256 {
            state: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
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

        let mut hash = [0u8; MAX_HASH_LENGTH];
        for (i, word) in self.state.iter().enumerate() {
            let offset = i * 4;
            hash[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
        }

        return Hash {
            hash,
            length: Self::OUTPUT_SIZE,
        };
    }
}

#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    total_len: u128,
}

impl Sha512 {
    #[inline]
    fn process_block(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        let mut i = 0usize;
        while i < 16 {
            let offset = i * 8;
            w[i] = u64::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
                block[offset + 4],
                block[offset + 5],
                block[offset + 6],
                block[offset + 7],
            ]);
            i += 1;
        }

        while i < 80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        i = 0;
        while i < 80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Hasher for Sha512 {
    const BLOCK_SIZE: usize = 128;
    const OUTPUT_SIZE: usize = 64;

    #[inline]
    fn new() -> Self {
        return Sha512 {
            state: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
        };
    }

    #[inline]
    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);

        if self.buffer_len > 0 {
            let to_fill = (128 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_fill].copy_from_slice(&data[..to_fill]);
            self.buffer_len += to_fill;
            data = &data[to_fill..];

            if self.buffer_len == 128 {
                let mut block = [0u8; 128];
                block.copy_from_slice(&self.buffer);
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 128 {
            let mut block = [0u8; 128];
            block.copy_from_slice(&data[..128]);
            self.process_block(&block);
            data = &data[128..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    #[inline]
    fn sum(mut self) -> Hash {
        let bit_len = self.total_len.wrapping_mul(8);

        let mut tail = [0u8; 256];
        tail[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        tail[self.buffer_len] = 0x80;

        let padding_len = if self.buffer_len < 112 {
            112 - self.buffer_len
        } else {
            240 - self.buffer_len
        };

        let length_offset = self.buffer_len + padding_len;
        tail[length_offset..length_offset + 16].copy_from_slice(&bit_len.to_be_bytes());

        let total_tail_len = length_offset + 16;
        for chunk in tail[..total_tail_len].chunks_exact(128) {
            let mut block = [0u8; 128];
            block.copy_from_slice(chunk);
            self.process_block(&block);
        }

        let mut hash = [0u8; MAX_HASH_LENGTH];
        for (i, word) in self.state.iter().enumerate() {
            let offset = i * 8;
            hash[offset..offset + 8].copy_from_slice(&word.to_be_bytes());
        }

        return Hash {
            hash,
            length: Self::OUTPUT_SIZE,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{Sha256, Sha512};
    use crate::Hasher;

    const VECTORS_SHA256: [(&str, &str); 7] = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (
            "message digest",
            "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        ),
    ];

    const VECTORS_SHA512: [(&str, &str); 7] = [
        (
            "",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
        (
            "a",
            "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
        ),
        (
            "abc",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
        (
            "message digest",
            "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
        ),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
        ),
    ];

    #[test]
    fn sha256_known_vectors_single_update() {
        for (input, expected) in VECTORS_SHA256 {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha256_known_vectors_incremental() {
        for (input, expected) in VECTORS_SHA256 {
            let bytes = input.as_bytes();
            let mut hasher = Sha256::new();
            for chunk in bytes.chunks(3) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha512_known_vectors_single_update() {
        for (input, expected) in VECTORS_SHA512 {
            let mut hasher = Sha512::new();
            hasher.update(input.as_bytes());
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha512_known_vectors_incremental() {
        for (input, expected) in VECTORS_SHA512 {
            let bytes = input.as_bytes();
            let mut hasher = Sha512::new();
            for chunk in bytes.chunks(5) {
                hasher.update(chunk);
            }
            let digest = hasher.sum();
            assert_eq!(hex::encode(digest.as_ref()), expected);
        }
    }

    #[test]
    fn sha2_block_boundary_lengths() {
        for len in [111usize, 112, 113, 127, 128, 129, 255, 256, 257] {
            let input = vec![b'a'; len];

            let mut whole_256 = Sha256::new();
            whole_256.update(&input);
            let whole_256_sum = whole_256.sum();

            let mut split_256 = Sha256::new();
            for chunk in input.chunks(7) {
                split_256.update(chunk);
            }
            let split_256_sum = split_256.sum();

            let mut whole_512 = Sha512::new();
            whole_512.update(&input);
            let whole_512_sum = whole_512.sum();

            let mut split_512 = Sha512::new();
            for chunk in input.chunks(11) {
                split_512.update(chunk);
            }
            let split_512_sum = split_512.sum();

            assert_eq!(whole_256_sum.as_ref(), split_256_sum.as_ref());
            assert_eq!(whole_512_sum.as_ref(), split_512_sum.as_ref());
        }
    }
}
