#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

#[cfg(all(feature = "serde", any(feature = "alloc", test)))]
mod serde;

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    Lower,
    Upper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidLength,
}

#[cfg(any(feature = "alloc", test))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid hex character"),
            Self::InvalidLength => f.write_str("odd number of hex characters"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

const ALPHABET_LOWER: [u8; 16] = *b"0123456789abcdef";
const ALPHABET_UPPER: [u8; 16] = *b"0123456789ABCDEF";

const DECODE_TABLE: [u8; 256] = {
    let mut table = [0x10u8; 256];
    let mut i: usize = 0;
    while i < 10 {
        table[b'0' as usize + i] = i as u8;
        i += 1;
    }
    i = 0;
    while i < 6 {
        table[b'a' as usize + i] = 10 + i as u8;
        table[b'A' as usize + i] = 10 + i as u8;
        i += 1;
    }
    table
};

#[cfg(any(feature = "alloc", test))]
pub fn encode(data: impl AsRef<[u8]>) -> alloc::string::String {
    encode_with_alphabet(data.as_ref(), Alphabet::Lower)
}

#[cfg(any(feature = "alloc", test))]
pub fn encode_with_alphabet(data: impl AsRef<[u8]>, alphabet: Alphabet) -> alloc::string::String {
    let data = data.as_ref();
    let mut output = alloc::vec![0u8; data.len() * 2];
    encode_into(&mut output, data, alphabet);
    unsafe { alloc::string::String::from_utf8_unchecked(output) }
}

/// Encodes `data` into a fixed-size array at compile time.
///
/// The generic parameter `OUT` is the output array length. It must be at
/// least `data.len() * 2` or a compile-time panic is raised.
///
/// # Example
///
/// ```rust
/// const HASH: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
/// const HEX: [u8; 8] = hex::encode_array::<8>(&HASH, hex::Alphabet::Lower);
/// assert_eq!(&HEX, b"deadbeef");
/// ```
pub const fn encode_array<const OUT: usize>(data: &[u8], alphabet: Alphabet) -> [u8; OUT] {
    if data.len() * 2 > OUT {
        panic!("encode_array: output array too small");
    }
    let mut result = [0u8; OUT];
    encode_into(&mut result, data, alphabet);
    result
}

pub const fn encode_into(output: &mut [u8], data: &[u8], alphabet: Alphabet) {
    assert!(output.len() >= data.len() * 2, "output buffer is too small");

    let table = match alphabet {
        Alphabet::Lower => &ALPHABET_LOWER,
        Alphabet::Upper => &ALPHABET_UPPER,
    };

    let mut i = 0;
    let len = data.len();

    while i + 16 <= len {
        let b0 = data[i];
        let b1 = data[i + 1];
        let b2 = data[i + 2];
        let b3 = data[i + 3];
        let b4 = data[i + 4];
        let b5 = data[i + 5];
        let b6 = data[i + 6];
        let b7 = data[i + 7];
        let b8 = data[i + 8];
        let b9 = data[i + 9];
        let b10 = data[i + 10];
        let b11 = data[i + 11];
        let b12 = data[i + 12];
        let b13 = data[i + 13];
        let b14 = data[i + 14];
        let b15 = data[i + 15];

        let o = i * 2;
        output[o] = table[(b0 >> 4) as usize];
        output[o + 1] = table[(b0 & 0x0F) as usize];
        output[o + 2] = table[(b1 >> 4) as usize];
        output[o + 3] = table[(b1 & 0x0F) as usize];
        output[o + 4] = table[(b2 >> 4) as usize];
        output[o + 5] = table[(b2 & 0x0F) as usize];
        output[o + 6] = table[(b3 >> 4) as usize];
        output[o + 7] = table[(b3 & 0x0F) as usize];
        output[o + 8] = table[(b4 >> 4) as usize];
        output[o + 9] = table[(b4 & 0x0F) as usize];
        output[o + 10] = table[(b5 >> 4) as usize];
        output[o + 11] = table[(b5 & 0x0F) as usize];
        output[o + 12] = table[(b6 >> 4) as usize];
        output[o + 13] = table[(b6 & 0x0F) as usize];
        output[o + 14] = table[(b7 >> 4) as usize];
        output[o + 15] = table[(b7 & 0x0F) as usize];
        output[o + 16] = table[(b8 >> 4) as usize];
        output[o + 17] = table[(b8 & 0x0F) as usize];
        output[o + 18] = table[(b9 >> 4) as usize];
        output[o + 19] = table[(b9 & 0x0F) as usize];
        output[o + 20] = table[(b10 >> 4) as usize];
        output[o + 21] = table[(b10 & 0x0F) as usize];
        output[o + 22] = table[(b11 >> 4) as usize];
        output[o + 23] = table[(b11 & 0x0F) as usize];
        output[o + 24] = table[(b12 >> 4) as usize];
        output[o + 25] = table[(b12 & 0x0F) as usize];
        output[o + 26] = table[(b13 >> 4) as usize];
        output[o + 27] = table[(b13 & 0x0F) as usize];
        output[o + 28] = table[(b14 >> 4) as usize];
        output[o + 29] = table[(b14 & 0x0F) as usize];
        output[o + 30] = table[(b15 >> 4) as usize];
        output[o + 31] = table[(b15 & 0x0F) as usize];

        i += 16;
    }

    while i < len {
        let b = data[i];
        let o = i * 2;
        output[o] = table[(b >> 4) as usize];
        output[o + 1] = table[(b & 0x0F) as usize];
        i += 1;
    }
}

#[cfg(any(feature = "alloc", test))]
pub fn decode(data: impl AsRef<[u8]>) -> Result<alloc::vec::Vec<u8>, Error> {
    let data = data.as_ref();
    let mut output = alloc::vec![0u8; data.len() / 2];
    decode_into(&mut output, data)?;
    Ok(output)
}

/// Decodes a hex string into a fixed-size array at compile time.
///
/// The generic parameter `OUT` is the output array length. It must equal
/// `data.len() / 2` or an error is returned.
///
/// # Example
///
/// ```rust
/// const RESULT: Result<[u8; 4], hex::Error> =
///     hex::decode_array::<4>(b"deadbeef");
/// assert_eq!(RESULT.unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
/// ```
pub const fn decode_array<const OUT: usize>(encoded_data: &[u8]) -> Result<[u8; OUT], Error> {
    if OUT != encoded_data.len() / 2 {
        return Err(Error::InvalidLength);
    }

    let mut result = [0u8; OUT];
    match decode_into(&mut result, encoded_data) {
        Ok(_) => {}
        Err(err) => return Err(err),
    }
    Ok(result)
}

pub const fn decode_into(output: &mut [u8], encoded_data: &[u8]) -> Result<(), Error> {
    let in_len = encoded_data.len();
    if in_len % 2 != 0 {
        return Err(Error::InvalidLength);
    }
    if output.len() < in_len / 2 {
        return Err(Error::InvalidLength);
    }

    let mut i = 0;

    while i + 32 <= in_len {
        let mut valid: u8 = 0;

        let h0 = DECODE_TABLE[encoded_data[i] as usize];
        let l0 = DECODE_TABLE[encoded_data[i + 1] as usize];
        valid |= h0 | l0;
        output[i / 2] = (h0 << 4) | l0;

        let h1 = DECODE_TABLE[encoded_data[i + 2] as usize];
        let l1 = DECODE_TABLE[encoded_data[i + 3] as usize];
        valid |= h1 | l1;
        output[i / 2 + 1] = (h1 << 4) | l1;

        let h2 = DECODE_TABLE[encoded_data[i + 4] as usize];
        let l2 = DECODE_TABLE[encoded_data[i + 5] as usize];
        valid |= h2 | l2;
        output[i / 2 + 2] = (h2 << 4) | l2;

        let h3 = DECODE_TABLE[encoded_data[i + 6] as usize];
        let l3 = DECODE_TABLE[encoded_data[i + 7] as usize];
        valid |= h3 | l3;
        output[i / 2 + 3] = (h3 << 4) | l3;

        let h4 = DECODE_TABLE[encoded_data[i + 8] as usize];
        let l4 = DECODE_TABLE[encoded_data[i + 9] as usize];
        valid |= h4 | l4;
        output[i / 2 + 4] = (h4 << 4) | l4;

        let h5 = DECODE_TABLE[encoded_data[i + 10] as usize];
        let l5 = DECODE_TABLE[encoded_data[i + 11] as usize];
        valid |= h5 | l5;
        output[i / 2 + 5] = (h5 << 4) | l5;

        let h6 = DECODE_TABLE[encoded_data[i + 12] as usize];
        let l6 = DECODE_TABLE[encoded_data[i + 13] as usize];
        valid |= h6 | l6;
        output[i / 2 + 6] = (h6 << 4) | l6;

        let h7 = DECODE_TABLE[encoded_data[i + 14] as usize];
        let l7 = DECODE_TABLE[encoded_data[i + 15] as usize];
        valid |= h7 | l7;
        output[i / 2 + 7] = (h7 << 4) | l7;

        let h8 = DECODE_TABLE[encoded_data[i + 16] as usize];
        let l8 = DECODE_TABLE[encoded_data[i + 17] as usize];
        valid |= h8 | l8;
        output[i / 2 + 8] = (h8 << 4) | l8;

        let h9 = DECODE_TABLE[encoded_data[i + 18] as usize];
        let l9 = DECODE_TABLE[encoded_data[i + 19] as usize];
        valid |= h9 | l9;
        output[i / 2 + 9] = (h9 << 4) | l9;

        let h10 = DECODE_TABLE[encoded_data[i + 20] as usize];
        let l10 = DECODE_TABLE[encoded_data[i + 21] as usize];
        valid |= h10 | l10;
        output[i / 2 + 10] = (h10 << 4) | l10;

        let h11 = DECODE_TABLE[encoded_data[i + 22] as usize];
        let l11 = DECODE_TABLE[encoded_data[i + 23] as usize];
        valid |= h11 | l11;
        output[i / 2 + 11] = (h11 << 4) | l11;

        let h12 = DECODE_TABLE[encoded_data[i + 24] as usize];
        let l12 = DECODE_TABLE[encoded_data[i + 25] as usize];
        valid |= h12 | l12;
        output[i / 2 + 12] = (h12 << 4) | l12;

        let h13 = DECODE_TABLE[encoded_data[i + 26] as usize];
        let l13 = DECODE_TABLE[encoded_data[i + 27] as usize];
        valid |= h13 | l13;
        output[i / 2 + 13] = (h13 << 4) | l13;

        let h14 = DECODE_TABLE[encoded_data[i + 28] as usize];
        let l14 = DECODE_TABLE[encoded_data[i + 29] as usize];
        valid |= h14 | l14;
        output[i / 2 + 14] = (h14 << 4) | l14;

        let h15 = DECODE_TABLE[encoded_data[i + 30] as usize];
        let l15 = DECODE_TABLE[encoded_data[i + 31] as usize];
        valid |= h15 | l15;
        output[i / 2 + 15] = (h15 << 4) | l15;

        if valid & 0xF0 != 0 {
            return Err(Error::InvalidInput);
        }

        i += 32;
    }

    while i < in_len {
        let h = DECODE_TABLE[encoded_data[i] as usize];
        let l = DECODE_TABLE[encoded_data[i + 1] as usize];
        if h >= 16 || l >= 16 {
            return Err(Error::InvalidInput);
        }
        output[i / 2] = (h << 4) | l;
        i += 2;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(b""), "");
        let mut out = [0u8; 0];
        encode_into(&mut out, b"", Alphabet::Lower);
    }

    #[test]
    fn encode_single_byte() {
        assert_eq!(encode(b"\x00"), "00");
        assert_eq!(encode(b"\xFF"), "ff");
        assert_eq!(encode(b"\xAB"), "ab");
        assert_eq!(encode_with_alphabet(b"\xAB", Alphabet::Upper), "AB");
    }

    #[test]
    fn encode_multiple_bytes() {
        assert_eq!(encode(b"hello"), "68656c6c6f");
        assert_eq!(encode_with_alphabet(b"hello", Alphabet::Upper), "68656C6C6F");
        assert_eq!(
            encode(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"),
            "00112233445566778899aabbccddeeff"
        );
    }

    #[test]
    fn encode_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let hex = encode(&data);
        assert_eq!(hex.len(), 512);
        for (i, &b) in data.iter().enumerate() {
            let hi = ALPHABET_LOWER[(b >> 4) as usize];
            let lo = ALPHABET_LOWER[(b & 0x0F) as usize];
            assert_eq!(hex.as_bytes()[i * 2], hi);
            assert_eq!(hex.as_bytes()[i * 2 + 1], lo);
        }
    }

    #[test]
    fn encode_into_exact_buffer() {
        let mut out = [0u8; 4];
        encode_into(&mut out, b"\xDE\xAD", Alphabet::Upper);
        assert_eq!(&out, b"DEAD");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode(b"").unwrap(), b"");
    }

    #[test]
    fn decode_single_byte() {
        assert_eq!(decode(b"00").unwrap(), b"\x00");
        assert_eq!(decode(b"ff").unwrap(), b"\xFF");
        assert_eq!(decode(b"FF").unwrap(), b"\xFF");
        assert_eq!(decode(b"ab").unwrap(), b"\xAB");
        assert_eq!(decode(b"AB").unwrap(), b"\xAB");
    }

    #[test]
    fn decode_multiple_bytes() {
        assert_eq!(decode(b"68656c6c6f").unwrap(), b"hello");
        assert_eq!(
            decode(b"00112233445566778899AABBCCDDEEFF").unwrap(),
            b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
        );
    }

    #[test]
    fn decode_into_exact_buffer() {
        let mut out = [0u8; 2];
        decode_into(&mut out, b"DEAD").unwrap();
        assert_eq!(&out, b"\xDE\xAD");
    }

    #[test]
    fn decode_invalid_character() {
        assert_eq!(decode(b"0g"), Err(Error::InvalidInput));
        assert_eq!(decode(b"GG"), Err(Error::InvalidInput));
        assert_eq!(decode(b"  "), Err(Error::InvalidInput));
    }

    #[test]
    fn decode_odd_length() {
        assert_eq!(decode(b"0"), Err(Error::InvalidLength));
        assert_eq!(decode(b"abc"), Err(Error::InvalidLength));
    }

    #[test]
    fn decode_trailing_invalid_in_large_buffer() {
        let mut input = alloc::vec![b'0'; 64];
        input[63] = b'g';
        assert_eq!(decode(&input), Err(Error::InvalidInput));
    }

    #[test]
    fn roundtrip() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let hex = encode(&data);
        let decoded = decode(hex.as_bytes()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_upper() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let hex = encode_with_alphabet(&data, Alphabet::Upper);
        let decoded = decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn roundtrip_various_sizes() {
        for len in [0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 65, 95, 96] {
            let data: Vec<u8> = (0..len as u8).collect();
            let hex = encode(&data);
            let decoded = decode(hex.as_bytes()).unwrap();
            assert_eq!(decoded, data, "roundtrip failed for len={}", len);
        }
    }

    #[test]
    fn decode_case_insensitivity() {
        assert_eq!(decode(b"abcdef"), decode(b"ABCDEF"));
        assert_eq!(decode(b"AbCdEf"), decode(b"aBcDeF"));
    }

    #[test]
    fn decode_into_too_small() {
        let mut out = [0u8; 1];
        assert_eq!(decode_into(&mut out, b"0000"), Err(Error::InvalidLength));
    }

    #[test]
    fn encode_into_panics_on_too_small() {
        use std::panic::{AssertUnwindSafe, catch_unwind};
        let mut out = [0u8; 1];
        let result = catch_unwind(AssertUnwindSafe(|| {
            encode_into(&mut out, b"hello", Alphabet::Lower);
        }));
        assert!(result.is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip() {
        #[derive(::serde::Serialize, ::serde::Deserialize)]
        struct Data(#[serde(with = "crate::serde")] Vec<u8>);

        let data = Data(b"hello world".to_vec());
        let json = ::serde_json::to_string(&data).unwrap();
        assert_eq!(json, "\"68656c6c6f20776f726c64\"");
        let deserialized: Data = ::serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.0, b"hello world");
    }

    #[test]
    fn const_encode() {
        const DATA: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        const HEX: [u8; 8] = encode_array::<8>(&DATA, Alphabet::Lower);
        const HEX_UPPER: [u8; 8] = encode_array::<8>(&DATA, Alphabet::Upper);
        assert_eq!(&HEX, b"deadbeef");
        assert_eq!(&HEX_UPPER, b"DEADBEEF");
    }

    #[test]
    fn const_encode_empty() {
        const HEX: [u8; 0] = encode_array::<0>(b"", Alphabet::Lower);
        assert_eq!(HEX.len(), 0);
    }

    #[test]
    fn const_encode_large_output() {
        const DATA: [u8; 2] = [0xAB, 0xCD];
        const HEX: [u8; 8] = encode_array::<8>(&DATA, Alphabet::Lower);
        assert_eq!(&HEX[..4], b"abcd");
        assert_eq!(&HEX[4..], &[0u8; 4]);
    }

    #[test]
    fn const_decode() {
        const RESULT: Result<[u8; 4], Error> = decode_array::<4>(b"deadbeef");
        assert_eq!(RESULT.unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn const_decode_empty() {
        const RESULT: Result<[u8; 0], Error> = decode_array::<0>(b"");
        assert_eq!(RESULT.unwrap().len(), 0);
    }

    #[test]
    fn const_decode_upper() {
        const RESULT: Result<[u8; 4], Error> = decode_array::<4>(b"DEADBEEF");
        assert_eq!(RESULT.unwrap(), [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn const_decode_invalid_character() {
        const ERR: Result<[u8; 1], Error> = decode_array::<1>(b"0g");
        assert_eq!(ERR, Err(Error::InvalidInput));
    }

    #[test]
    fn const_decode_odd_length() {
        const ERR: Result<[u8; 0], Error> = decode_array::<0>(b"0");
        assert_eq!(ERR, Err(Error::InvalidLength));
    }

    #[test]
    fn const_decode_wrong_output_size() {
        const ERR: Result<[u8; 2], Error> = decode_array::<2>(b"00");
        assert_eq!(ERR, Err(Error::InvalidLength));
    }
}
