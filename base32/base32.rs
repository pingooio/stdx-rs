use core::cmp::min;

#[derive(Copy, Clone)]
pub enum Alphabet {
    Crockford,
    Rfc4648 { padding: bool },
    Rfc4648Lower { padding: bool },
    Rfc4648Hex { padding: bool },
    Rfc4648HexLower { padding: bool },
    Z,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("input is not valid")]
    InvalidInput,
}

const CROCKFORD: &'static [u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const RFC4648: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RFC4648_LOWER: &'static [u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const RFC4648_HEX: &'static [u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
const RFC4648_HEX_LOWER: &'static [u8] = b"0123456789abcdefghijklmnopqrstuv";
const Z: &'static [u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

pub fn encode(data: &[u8]) -> String {
    return encode_private(
        Alphabet::Rfc4648 {
            padding: true,
        },
        data,
    );
}

pub fn encode_with_alphabet(data: &[u8], alphabet: Alphabet) -> String {
    return encode_private(alphabet, data);
}

pub fn decode(data: &str) -> Result<Vec<u8>, Error> {
    return decode_with_alphabet(
        data,
        Alphabet::Rfc4648 {
            padding: true,
        },
    );
}

pub fn decode_with_alphabet(data: &str, alphabet: Alphabet) -> Result<Vec<u8>, Error> {
    match decode_private(alphabet, data) {
        Some(data) => Ok(data),
        None => Err(Error::InvalidInput),
    }
}

fn encode_private(alphabet: Alphabet, data: &[u8]) -> String {
    let (alphabet, padding) = match alphabet {
        Alphabet::Crockford => (CROCKFORD, false),
        Alphabet::Rfc4648 {
            padding,
        } => (RFC4648, padding),
        Alphabet::Rfc4648Lower {
            padding,
        } => (RFC4648_LOWER, padding),
        Alphabet::Rfc4648Hex {
            padding,
        } => (RFC4648_HEX, padding),
        Alphabet::Rfc4648HexLower {
            padding,
        } => (RFC4648_HEX_LOWER, padding),
        Alphabet::Z => (Z, false),
    };
    let mut ret = Vec::with_capacity((data.len() + 3) / 4 * 5);

    for chunk in data.chunks(5) {
        let buf = {
            let mut buf = [0u8; 5];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b;
            }
            buf
        };
        ret.push(alphabet[((buf[0] & 0xF8) >> 3) as usize]);
        ret.push(alphabet[(((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)) as usize]);
        ret.push(alphabet[((buf[1] & 0x3E) >> 1) as usize]);
        ret.push(alphabet[(((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)) as usize]);
        ret.push(alphabet[(((buf[2] & 0x0F) << 1) | (buf[3] >> 7)) as usize]);
        ret.push(alphabet[((buf[3] & 0x7C) >> 2) as usize]);
        ret.push(alphabet[(((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)) as usize]);
        ret.push(alphabet[(buf[4] & 0x1F) as usize]);
    }

    if data.len() % 5 != 0 {
        let len = ret.len();
        let num_extra = 8 - (data.len() % 5 * 8 + 4) / 5;
        if padding {
            for i in 1..num_extra + 1 {
                ret[len - i] = b'=';
            }
        } else {
            ret.truncate(len - num_extra);
        }
    }

    String::from_utf8(ret).unwrap()
}

/*
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  :,  ;,  <,  =,  >,  ?,  @,  A,  B,  C,
     D,  E,  F,  G,  H,  I,  J,  K,  L,  M,  N,  O,  P,  Q,  R,  S,  T,  U,  V,  W,
     X,  Y,  Z,  [,  \,  ],  ^,  _,  `,  a,  b,  c,  d,  e,  f,  g,  h,  i,  j,  k,
     l,  m,  n,  o,  p,  q,  r,  s,  t,  u,  v,  w,  x,  y,  z,
*/

const CROCKFORD_INV: [i8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 1, 18, 19, 1, 20, 21, 0,
    22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 1, 18, 19, 1,
    20, 21, 0, 22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31,
];
const RFC4648_INV: [i8; 75] = [
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];
const RFC4648_INV_PAD: [i8; 75] = [
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, 0, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];
const RFC4648_INV_LOWER: [i8; 75] = [
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
const RFC4648_INV_LOWER_PAD: [i8; 75] = [
    -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
];
const RFC4648_INV_HEX: [i8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];
const RFC4648_INV_HEX_PAD: [i8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, 0, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];
const RFC4648_INV_HEX_LOWER: [i8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
];
const RFC4648_INV_HEX_LOWER_PAD: [i8; 75] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, 0, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
];
const Z_INV: [i8; 75] = [
    -1, 18, -1, 25, 26, 27, 30, 29, 7, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 24, 1, 12, 3, 8, 5, 6, 28, 21, 9,
    10, -1, 11, 2, 16, 13, 14, 4, 22, 17, 19, -1, 20, 15, 0, 23,
];

fn decode_private(alphabet: Alphabet, data: &str) -> Option<Vec<u8>> {
    if !data.is_ascii() {
        return None;
    }
    let data = data.as_bytes();
    let alphabet = match alphabet {
        Alphabet::Crockford => CROCKFORD_INV, // supports both upper and lower case
        Alphabet::Rfc4648 {
            padding,
        } => {
            if padding {
                RFC4648_INV_PAD
            } else {
                RFC4648_INV
            }
        }
        Alphabet::Rfc4648Lower {
            padding,
        } => {
            if padding {
                RFC4648_INV_LOWER_PAD
            } else {
                RFC4648_INV_LOWER
            }
        }
        Alphabet::Rfc4648Hex {
            padding,
        } => {
            if padding {
                RFC4648_INV_HEX_PAD
            } else {
                RFC4648_INV_HEX
            }
        }
        Alphabet::Rfc4648HexLower {
            padding,
        } => {
            if padding {
                RFC4648_INV_HEX_LOWER_PAD
            } else {
                RFC4648_INV_HEX_LOWER
            }
        }
        Alphabet::Z => Z_INV,
    };
    let mut unpadded_data_length = data.len();
    for i in 1..min(6, data.len()) + 1 {
        if data[data.len() - i] != b'=' {
            break;
        }
        unpadded_data_length -= 1;
    }
    let output_length = unpadded_data_length * 5 / 8;
    let mut ret = Vec::with_capacity((output_length + 4) / 5 * 5);
    for chunk in data.chunks(8) {
        let buf = {
            let mut buf = [0u8; 8];
            for (i, &c) in chunk.iter().enumerate() {
                match alphabet.get(c.wrapping_sub(b'0') as usize) {
                    Some(&-1) | None => return None,
                    Some(&value) => buf[i] = value as u8,
                };
            }
            buf
        };
        ret.push((buf[0] << 3) | (buf[1] >> 2));
        ret.push((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
        ret.push((buf[3] << 4) | (buf[4] >> 1));
        ret.push((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
        ret.push((buf[6] << 5) | buf[7]);
    }
    ret.truncate(output_length);
    Some(ret)
}

#[cfg(test)]
#[allow(dead_code, unused_attributes)]
mod test {
    use super::Alphabet::{Crockford, Rfc4648, Rfc4648Hex, Rfc4648HexLower, Rfc4648Lower, Z};
    use crate::{Error, decode_with_alphabet, encode_with_alphabet};
    // use quickcheck::{Arbitrary, Gen};
    // use std::fmt::{Debug, Error, Formatter};

    // #[derive(Clone)]
    // struct B32 {
    //     c: u8,
    // }

    // impl Arbitrary for B32 {
    //     fn arbitrary(g: &mut Gen) -> B32 {
    //         B32 {
    //             c: *g.choose(b"0123456789ABCDEFGHJKMNPQRSTVWXYZ").unwrap(),
    //         }
    //     }
    // }

    // impl Debug for B32 {
    //     fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
    //         (self.c as char).fmt(f)
    //     }
    // }

    #[test]
    fn masks_crockford() {
        assert_eq!(encode_with_alphabet(&[0xF8, 0x3E, 0x0F, 0x83, 0xE0], Crockford), "Z0Z0Z0Z0");
        assert_eq!(encode_with_alphabet(&[0x07, 0xC1, 0xF0, 0x7C, 0x1F], Crockford), "0Z0Z0Z0Z");
        assert_eq!(
            decode_with_alphabet("Z0Z0Z0Z0", Crockford).unwrap(),
            [0xF8, 0x3E, 0x0F, 0x83, 0xE0]
        );
        assert_eq!(
            decode_with_alphabet("0Z0Z0Z0Z", Crockford).unwrap(),
            [0x07, 0xC1, 0xF0, 0x7C, 0x1F]
        );
    }

    #[test]
    fn masks_rfc4648() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648 {
                    padding: false
                }
            ),
            "7A7H7A7H"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648 {
                    padding: false
                }
            ),
            "O7A7O7A7"
        );
        assert_eq!(
            decode_with_alphabet(
                "7A7H7A7H",
                Rfc4648 {
                    padding: false
                }
            )
            .unwrap(),
            [0xF8, 0x3E, 0x7F, 0x83, 0xE7]
        );
        assert_eq!(
            decode_with_alphabet(
                "O7A7O7A7",
                Rfc4648 {
                    padding: false
                }
            )
            .unwrap(),
            [0x77, 0xC1, 0xF7, 0x7C, 0x1F]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648 {
                    padding: false
                }
            ),
            "7A7H7AY"
        );
    }

    #[test]
    fn masks_rfc4648_pad() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648 {
                    padding: true
                }
            ),
            "7A7H7A7H"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648 {
                    padding: true
                }
            ),
            "O7A7O7A7"
        );
        assert_eq!(
            decode_with_alphabet(
                "7A7H7A7H",
                Rfc4648 {
                    padding: true
                }
            )
            .unwrap(),
            [0xF8, 0x3E, 0x7F, 0x83, 0xE7]
        );
        assert_eq!(
            decode_with_alphabet(
                "O7A7O7A7",
                Rfc4648 {
                    padding: true
                }
            )
            .unwrap(),
            [0x77, 0xC1, 0xF7, 0x7C, 0x1F]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648 {
                    padding: true
                }
            ),
            "7A7H7AY="
        );
    }

    #[test]
    fn masks_rfc4648_lower() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648Lower {
                    padding: false
                }
            ),
            "7a7h7a7h"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648Lower {
                    padding: false
                }
            ),
            "o7a7o7a7"
        );
        assert_eq!(
            decode_with_alphabet(
                "7a7h7a7h",
                Rfc4648Lower {
                    padding: false
                }
            )
            .unwrap(),
            [0xF8, 0x3E, 0x7F, 0x83, 0xE7]
        );
        assert_eq!(
            decode_with_alphabet(
                "o7a7o7a7",
                Rfc4648Lower {
                    padding: false
                }
            )
            .unwrap(),
            [0x77, 0xC1, 0xF7, 0x7C, 0x1F]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648Lower {
                    padding: false
                }
            ),
            "7a7h7ay"
        );
    }

    #[test]
    fn masks_rfc4648_lower_pad() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648Lower {
                    padding: true
                }
            ),
            "7a7h7a7h"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648Lower {
                    padding: true
                }
            ),
            "o7a7o7a7"
        );
        assert_eq!(
            decode_with_alphabet(
                "7a7h7a7h",
                Rfc4648Lower {
                    padding: true
                }
            )
            .unwrap(),
            [0xF8, 0x3E, 0x7F, 0x83, 0xE7]
        );
        assert_eq!(
            decode_with_alphabet(
                "o7a7o7a7",
                Rfc4648Lower {
                    padding: true
                }
            )
            .unwrap(),
            [0x77, 0xC1, 0xF7, 0x7C, 0x1F]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648Lower {
                    padding: true
                }
            ),
            "7a7h7ay="
        );
    }

    #[test]
    fn masks_rfc4648_hex() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648Hex {
                    padding: false
                }
            ),
            "V0V7V0V7"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648Hex {
                    padding: false
                }
            ),
            "EV0VEV0V"
        );
        assert_eq!(
            decode_with_alphabet(
                "7A7H7A7H",
                Rfc4648Hex {
                    padding: false
                }
            )
            .unwrap(),
            [0x3A, 0x8F, 0x13, 0xA8, 0xF1]
        );
        assert_eq!(
            decode_with_alphabet(
                "O7A7O7A7",
                Rfc4648Hex {
                    padding: false
                }
            )
            .unwrap(),
            [0xC1, 0xD4, 0x7C, 0x1D, 0x47]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648Hex {
                    padding: false
                }
            ),
            "V0V7V0O"
        );
    }

    #[test]
    fn masks_rfc4648_hex_pad() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648Hex {
                    padding: true
                }
            ),
            "V0V7V0V7"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648Hex {
                    padding: true
                }
            ),
            "EV0VEV0V"
        );
        assert_eq!(
            decode_with_alphabet(
                "7A7H7A7H",
                Rfc4648Hex {
                    padding: true
                }
            )
            .unwrap(),
            [0x3A, 0x8F, 0x13, 0xA8, 0xF1]
        );
        assert_eq!(
            decode_with_alphabet(
                "O7A7O7A7",
                Rfc4648Hex {
                    padding: true
                }
            )
            .unwrap(),
            [0xC1, 0xD4, 0x7C, 0x1D, 0x47]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648Hex {
                    padding: true
                }
            ),
            "V0V7V0O="
        );
    }

    #[test]
    fn masks_rfc4648_hex_lower() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648HexLower {
                    padding: false
                }
            ),
            "v0v7v0v7"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648HexLower {
                    padding: false
                }
            ),
            "ev0vev0v"
        );
        assert_eq!(
            decode_with_alphabet(
                "7a7h7a7h",
                Rfc4648HexLower {
                    padding: false
                }
            )
            .unwrap(),
            [0x3A, 0x8F, 0x13, 0xA8, 0xF1]
        );
        assert_eq!(
            decode_with_alphabet(
                "o7a7o7a7",
                Rfc4648HexLower {
                    padding: false
                }
            )
            .unwrap(),
            [0xC1, 0xD4, 0x7C, 0x1D, 0x47]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648HexLower {
                    padding: false
                }
            ),
            "v0v7v0o"
        );
    }

    #[test]
    fn masks_rfc4648_hex_lower_pad() {
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83, 0xE7],
                Rfc4648HexLower {
                    padding: true
                }
            ),
            "v0v7v0v7"
        );
        assert_eq!(
            encode_with_alphabet(
                &[0x77, 0xC1, 0xF7, 0x7C, 0x1F],
                Rfc4648HexLower {
                    padding: true
                }
            ),
            "ev0vev0v"
        );
        assert_eq!(
            decode_with_alphabet(
                "7a7h7a7h",
                Rfc4648HexLower {
                    padding: true
                }
            )
            .unwrap(),
            [0x3A, 0x8F, 0x13, 0xA8, 0xF1]
        );
        assert_eq!(
            decode_with_alphabet(
                "o7a7o7a7",
                Rfc4648HexLower {
                    padding: true
                }
            )
            .unwrap(),
            [0xC1, 0xD4, 0x7C, 0x1D, 0x47]
        );
        assert_eq!(
            encode_with_alphabet(
                &[0xF8, 0x3E, 0x7F, 0x83],
                Rfc4648HexLower {
                    padding: true
                }
            ),
            "v0v7v0o="
        );
    }

    #[test]
    fn masks_z() {
        assert_eq!(encode_with_alphabet(&[0xF8, 0x3E, 0x0F, 0x83, 0xE0], Z), "9y9y9y9y");
        assert_eq!(encode_with_alphabet(&[0x07, 0xC1, 0xF0, 0x7C, 0x1F], Z), "y9y9y9y9");
        assert_eq!(decode_with_alphabet("9y9y9y9y", Z).unwrap(), [0xF8, 0x3E, 0x0F, 0x83, 0xE0]);
        assert_eq!(decode_with_alphabet("y9y9y9y9", Z).unwrap(), [0x07, 0xC1, 0xF0, 0x7C, 0x1F]);
    }

    #[test]
    fn padding() {
        let num_padding = [0, 6, 4, 3, 1];
        for i in 1..6 {
            let encoded = encode_with_alphabet(
                (0..(i as u8)).collect::<Vec<u8>>().as_ref(),
                Rfc4648 {
                    padding: true,
                },
            );
            assert_eq!(encoded.len(), 8);
            for j in 0..(num_padding[i % 5]) {
                assert_eq!(encoded.as_bytes()[encoded.len() - j - 1], b'=');
            }
            for j in 0..(8 - num_padding[i % 5]) {
                assert!(encoded.as_bytes()[j] != b'=');
            }
        }
    }

    // #[test]
    // fn invertible_crockford() {
    //     fn test(data: Vec<u8>) -> bool {
    //         decode(Crockford, encode(Crockford, data.as_ref()).as_ref()).unwrap() == data
    //     }
    //     quickcheck::quickcheck(test as fn(Vec<u8>) -> bool)
    // }

    // #[test]
    // fn invertible_rfc4648() {
    //     fn test(data: Vec<u8>) -> bool {
    //         decode(
    //             Rfc4648 { padding: true },
    //             encode(Rfc4648 { padding: true }, data.as_ref()).as_ref(),
    //         )
    //         .unwrap()
    //             == data
    //     }
    //     quickcheck::quickcheck(test as fn(Vec<u8>) -> bool)
    // }
    // #[test]
    // fn invertible_unpadded_rfc4648() {
    //     fn test(data: Vec<u8>) -> bool {
    //         decode(
    //             Rfc4648 { padding: false },
    //             encode(Rfc4648 { padding: false }, data.as_ref()).as_ref(),
    //         )
    //         .unwrap()
    //             == data
    //     }
    //     quickcheck::quickcheck(test as fn(Vec<u8>) -> bool)
    // }

    // #[test]
    // fn lower_case() {
    //     fn test(data: Vec<B32>) -> bool {
    //         let data: String = data.iter().map(|e| e.c as char).collect();
    //         decode(Crockford, data.as_ref())
    //             == decode(Crockford, data.to_ascii_lowercase().as_ref())
    //     }
    //     quickcheck::quickcheck(test as fn(Vec<B32>) -> bool)
    // }

    #[test]
    #[allow(non_snake_case)]
    fn iIlL1_oO0() {
        assert_eq!(
            decode_with_alphabet("IiLlOo", Crockford),
            decode_with_alphabet("111100", Crockford)
        );
    }

    #[test]
    fn invalid_chars_crockford() {
        assert_eq!(decode_with_alphabet(",", Crockford), Err(Error::InvalidInput))
    }

    #[test]
    fn invalid_chars_rfc4648() {
        assert_eq!(
            decode_with_alphabet(
                ",",
                Rfc4648 {
                    padding: true
                }
            ),
            Err(Error::InvalidInput)
        )
    }

    #[test]
    fn invalid_chars_unpadded_rfc4648() {
        assert_eq!(
            decode_with_alphabet(
                ",",
                Rfc4648 {
                    padding: false
                }
            ),
            Err(Error::InvalidInput)
        )
    }
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;
