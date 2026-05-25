const KECCAK_F1600_ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const KECCAK_F1600_RHO_OFFSETS: [u32; 25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

#[inline]
fn xor_byte(state: &mut [u64; 25], index: usize, value: u8) {
    let lane = index / 8;
    let shift = (index % 8) * 8;
    state[lane] ^= (value as u64) << shift;
}

#[inline]
fn get_byte(state: &[u64; 25], index: usize) -> u8 {
    let lane = index / 8;
    let shift = (index % 8) * 8;
    ((state[lane] >> shift) & 0xff) as u8
}

#[inline]
pub(crate) fn keccak_f1600(state: &mut [u64; 25]) {
    let mut c = [0u64; 5];
    let mut d = [0u64; 5];
    let mut b = [0u64; 25];

    for round in 0..24 {
        let mut x = 0usize;
        while x < 5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            x += 1;
        }

        x = 0;
        while x < 5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            x += 1;
        }

        let mut y = 0usize;
        while y < 5 {
            x = 0;
            while x < 5 {
                state[x + 5 * y] ^= d[x];
                x += 1;
            }
            y += 1;
        }

        y = 0;
        while y < 5 {
            x = 0;
            while x < 5 {
                let idx = x + 5 * y;
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                b[new_x + 5 * new_y] = state[idx].rotate_left(KECCAK_F1600_RHO_OFFSETS[idx]);
                x += 1;
            }
            y += 1;
        }

        y = 0;
        while y < 5 {
            x = 0;
            while x < 5 {
                let idx = x + 5 * y;
                state[idx] = b[idx] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
                x += 1;
            }
            y += 1;
        }

        state[0] ^= KECCAK_F1600_ROUND_CONSTANTS[round];
    }
}

#[derive(Clone)]
pub(crate) struct Keccak {
    state: [u64; 25],
    rate: usize,
    delimiter: u8,
    absorb_pos: usize,
    squeeze_pos: usize,
    finalized: bool,
}

impl Keccak {
    #[inline]
    pub(crate) fn new(rate: usize, delimiter: u8) -> Self {
        debug_assert!(rate > 0 && rate < 200);
        return Keccak {
            state: [0u64; 25],
            rate,
            delimiter,
            absorb_pos: 0,
            squeeze_pos: 0,
            finalized: false,
        };
    }

    #[inline]
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        assert!(!self.finalized, "cannot absorb after squeeze has started");

        while !data.is_empty() {
            let take = (self.rate - self.absorb_pos).min(data.len());
            let mut i = 0usize;
            while i < take {
                xor_byte(&mut self.state, self.absorb_pos + i, data[i]);
                i += 1;
            }
            self.absorb_pos += take;
            data = &data[take..];

            if self.absorb_pos == self.rate {
                keccak_f1600(&mut self.state);
                self.absorb_pos = 0;
            }
        }
    }

    #[inline]
    fn finalize_if_needed(&mut self) {
        if self.finalized {
            return;
        }

        xor_byte(&mut self.state, self.absorb_pos, self.delimiter);
        if (self.delimiter & 0x80) != 0 && self.absorb_pos == (self.rate - 1) {
            keccak_f1600(&mut self.state);
        }
        xor_byte(&mut self.state, self.rate - 1, 0x80);
        keccak_f1600(&mut self.state);

        self.absorb_pos = 0;
        self.squeeze_pos = 0;
        self.finalized = true;
    }

    #[inline]
    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        self.finalize_if_needed();

        for byte in output {
            if self.squeeze_pos == self.rate {
                keccak_f1600(&mut self.state);
                self.squeeze_pos = 0;
            }

            *byte = get_byte(&self.state, self.squeeze_pos);
            self.squeeze_pos += 1;
        }
    }
}
