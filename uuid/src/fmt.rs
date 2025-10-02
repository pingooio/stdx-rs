use core::fmt;
use std::{
    ptr,
    string::{String, ToString},
};

use crate::{Error, Uuid};

impl Default for Uuid {
    #[inline]
    fn default() -> Self {
        Uuid::nil()
    }
}

impl AsRef<Uuid> for Uuid {
    #[inline]
    fn as_ref(&self) -> &Uuid {
        self
    }
}

impl AsRef<[u8]> for Uuid {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Uuid> for std::vec::Vec<u8> {
    fn from(value: Uuid) -> Self {
        value.0.to_vec()
    }
}

impl std::convert::TryFrom<std::vec::Vec<u8>> for Uuid {
    type Error = Error;

    fn try_from(value: std::vec::Vec<u8>) -> Result<Self, Self::Error> {
        Uuid::from_slice(&value)
    }
}

impl std::fmt::Debug for Uuid {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(self, f)
    }
}

impl std::fmt::Display for Uuid {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(self, f)
    }
}

impl From<Uuid> for String {
    #[inline]
    fn from(uuid: Uuid) -> Self {
        uuid.to_string()
    }
}

impl std::fmt::LowerHex for Uuid {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut hyphenated_buf = format_hyphenated(&self.0, false);
        let hyphenated_str = unsafe { std::str::from_utf8_unchecked_mut(&mut hyphenated_buf) };

        return f.write_str(hyphenated_str);
    }
}

impl fmt::UpperHex for Uuid {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut hyphenated_buf = format_hyphenated(&self.0, false);
        let hyphenated_str = unsafe { std::str::from_utf8_unchecked_mut(&mut hyphenated_buf) };
        let upper_hex = hyphenated_str.to_uppercase();

        return f.write_str(&upper_hex);
    }
}

impl Uuid {
    pub fn encode_lower<'buf>(&self, buffer: &'buf mut [u8]) -> &'buf mut str {
        encode_hyphenated(self.as_bytes(), buffer, false)
    }

    pub const fn encode_buffer() -> [u8; HYPHENATED_LENGTH] {
        [0; HYPHENATED_LENGTH]
    }
}

#[inline]
fn encode_hyphenated<'b>(src: &[u8; 16], buffer: &'b mut [u8], upper: bool) -> &'b mut str {
    let buf = &mut buffer[..HYPHENATED_LENGTH];
    let dst = buf.as_mut_ptr();

    // SAFETY: `buf` is guaranteed to be at least `LEN` bytes
    // SAFETY: The encoded buffer is ASCII encoded
    unsafe {
        ptr::write(dst.cast(), format_hyphenated(src, upper));
        std::str::from_utf8_unchecked_mut(buf)
    }
}

const HYPHENATED_LENGTH: usize = 36;

const UPPER: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F',
];
const LOWER: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];

const fn format_hyphenated(src: &[u8; 16], upper: bool) -> [u8; 36] {
    let lut = if upper { &UPPER } else { &LOWER };
    let groups = [(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)];
    let mut dst = [0; 36];

    let mut group_idx = 0;
    let mut i = 0;
    while group_idx < 5 {
        let (start, end) = groups[group_idx];
        let mut j = start;
        while j < end {
            let x = src[i];
            i += 1;

            dst[j] = lut[(x >> 4) as usize];
            dst[j + 1] = lut[(x & 0x0f) as usize];
            j += 2;
        }
        if group_idx < 4 {
            dst[end] = b'-';
        }
        group_idx += 1;
    }
    dst
}
