//! Hex encoding/decoding tables and helpers for UUID string representation.

/// Precomputed lowercase hex encoding table.
pub const HEX_ENCODE: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];

/// Precomputed hex decoding table (256-entry, O(1) lookup).
///
/// Maps each byte value to its decoded nibble (0–15) or `0xff` for invalid
/// characters. Accepts both uppercase and lowercase hex digits.
pub static HEX_DECODE: [u8; 256] = build_hex_decode_table();

const fn build_hex_decode_table() -> [u8; 256] {
    let mut table = [0xffu8; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0xff,
        };
        i += 1;
    }
    table
}

/// Decode two hex characters into a byte.
///
/// Returns `None` if either character is not a valid hex digit.
#[inline]
pub fn decode_pair(hi: u8, lo: u8) -> Option<u8> {
    let h = HEX_DECODE[hi as usize];
    let l = HEX_DECODE[lo as usize];
    if h == 0xff || l == 0xff {
        None
    } else {
        Some((h << 4) | l)
    }
}
