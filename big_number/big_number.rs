#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
use core::{
    fmt,
    ops::{Add, Div, Mul, Neg, Rem, Sub},
};

pub const MAX_LIMBS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Uint<const BITS: usize, const LIMBS: usize> {
    pub limbs: [u64; LIMBS],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Int<const BITS: usize, const LIMBS: usize>(Uint<BITS, LIMBS>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRadix,
    InvalidDigit,
    EmptyString,
    Overflow,
}

#[inline]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let sum = (a as u128) + (b as u128) + (carry as u128);
    (sum as u64, (sum >> 64) as u64)
}

#[inline]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let diff = (1u128 << 64) + (a as u128) - (b as u128) - (borrow as u128);
    (diff as u64, 1u64.wrapping_sub((diff >> 64) as u64))
}

#[inline]
pub const fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
    let value = (acc as u128) + (a as u128) * (b as u128) + (carry as u128);
    (value as u64, (value >> 64) as u64)
}

#[inline]
const fn ct_select_u64(a: u64, b: u64, choice: bool) -> u64 {
    let mask = 0u64.wrapping_sub(choice as u64);
    b ^ ((a ^ b) & mask)
}

#[inline]
const fn digit_to_char(digit: u64, upper: bool) -> char {
    match digit {
        0..=9 => (b'0' + digit as u8) as char,
        _ if upper => (b'A' + (digit as u8 - 10)) as char,
        _ => (b'a' + (digit as u8 - 10)) as char,
    }
}

#[inline]
fn char_to_digit(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u32),
        b'a'..=b'z' => Some((byte - b'a' + 10) as u32),
        b'A'..=b'Z' => Some((byte - b'A' + 10) as u32),
        _ => None,
    }
}

const fn uint_from_u128<const BITS: usize, const LIMBS: usize>(value: u128) -> Uint<BITS, LIMBS> {
    let mut limbs = [0u64; LIMBS];
    if LIMBS > 0 {
        limbs[0] = value as u64;
    }
    if LIMBS > 1 {
        limbs[1] = (value >> 64) as u64;
    }
    Uint {
        limbs,
    }
}

fn u128_to_word(value: u128) -> u64 {
    u64::try_from(value).expect("primitive operand exceeds u64")
}

fn i128_abs_to_word(value: i128) -> (u64, bool) {
    (u128_to_word(value.unsigned_abs()), value.is_negative())
}

impl<const BITS: usize, const LIMBS: usize> Uint<BITS, LIMBS> {
    const _LIMBS_CHECK: () = assert!(LIMBS == (BITS + 63) / 64, "LIMBS must equal ceil(BITS/64)");

    pub const ZERO: Self = Self {
        limbs: [0u64; LIMBS],
    };
    pub const ONE: Self = Self::from_u64(1);
    pub const MAX: Self = Self {
        limbs: [u64::MAX; LIMBS],
    };

    #[inline]
    pub const fn from_limbs(limbs: [u64; LIMBS]) -> Self {
        Self {
            limbs,
        }
    }

    #[inline]
    pub const fn from_u64(v: u64) -> Self {
        let mut limbs = [0u64; LIMBS];
        if LIMBS > 0 {
            limbs[0] = v;
        }
        Self {
            limbs,
        }
    }

    #[inline]
    pub fn from_be_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), BITS / 8);
        let mut limbs = [0u64; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            let start = bytes.len() - ((i + 1) * 8);
            let mut limb = [0u8; 8];
            limb.copy_from_slice(&bytes[start..start + 8]);
            limbs[i] = u64::from_be_bytes(limb);
            i += 1;
        }
        Self {
            limbs,
        }
    }

    #[inline]
    pub fn from_le_slice(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), BITS / 8);
        let mut limbs = [0u64; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            let start = i * 8;
            let mut limb = [0u8; 8];
            limb.copy_from_slice(&bytes[start..start + 8]);
            limbs[i] = u64::from_le_bytes(limb);
            i += 1;
        }
        Self {
            limbs,
        }
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BITS / 8);
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            out.extend_from_slice(&self.limbs[i].to_be_bytes());
        }
        out
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BITS / 8);
        let mut i = 0;
        while i < LIMBS {
            out.extend_from_slice(&self.limbs[i].to_le_bytes());
            i += 1;
        }
        out
    }

    #[inline]
    pub fn to_be_bytes_fixed<const N: usize>(&self) -> [u8; N] {
        assert_eq!(N, BITS / 8);
        let mut out = [0u8; N];
        let mut i = 0;
        while i < LIMBS {
            let start = N - ((i + 1) * 8);
            out[start..start + 8].copy_from_slice(&self.limbs[i].to_be_bytes());
            i += 1;
        }
        out
    }

    #[inline]
    pub fn to_le_bytes_fixed<const N: usize>(&self) -> [u8; N] {
        assert_eq!(N, BITS / 8);
        let mut out = [0u8; N];
        let mut i = 0;
        while i < LIMBS {
            let start = i * 8;
            out[start..start + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
            i += 1;
        }
        out
    }

    #[inline]
    pub fn bit(&self, index: usize) -> bool {
        if index >= BITS {
            return false;
        }
        ((self.limbs[index / 64] >> (index % 64)) & 1) == 1
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        let mut acc = 0u64;
        let mut i = 0;
        while i < LIMBS {
            acc |= self.limbs[i];
            i += 1;
        }
        acc == 0
    }

    #[inline]
    pub fn is_odd(&self) -> bool {
        (self.limbs[0] & 1) == 1
    }

    #[inline]
    pub fn ct_ge(&self, rhs: &Self) -> bool {
        let (_, borrow) = self.sub_raw(rhs);
        borrow == 0
    }

    #[inline]
    pub fn ct_eq(&self, rhs: &Self) -> bool {
        let mut diff = 0u64;
        let mut i = 0;
        while i < LIMBS {
            diff |= self.limbs[i] ^ rhs.limbs[i];
            i += 1;
        }
        diff == 0
    }

    #[inline]
    pub fn ct_select(a: &Self, b: &Self, choice: bool) -> Self {
        let mut limbs = [0u64; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            limbs[i] = ct_select_u64(a.limbs[i], b.limbs[i], choice);
            i += 1;
        }
        Self {
            limbs,
        }
    }

    #[inline]
    pub fn add_raw(&self, rhs: &Self) -> (Self, u64) {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u64;
        let mut i = 0;
        while i < LIMBS {
            let (word, next_carry) = adc(self.limbs[i], rhs.limbs[i], carry);
            out[i] = word;
            carry = next_carry;
            i += 1;
        }
        (
            Self {
                limbs: out,
            },
            carry,
        )
    }

    #[inline]
    pub fn sub_raw(&self, rhs: &Self) -> (Self, u64) {
        let mut out = [0u64; LIMBS];
        let mut borrow = 0u64;
        let mut i = 0;
        while i < LIMBS {
            let (word, next_borrow) = sbb(self.limbs[i], rhs.limbs[i], borrow);
            out[i] = word;
            borrow = next_borrow;
            i += 1;
        }
        (
            Self {
                limbs: out,
            },
            borrow,
        )
    }

    #[inline]
    pub fn add_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let (sum, carry) = self.add_raw(rhs);
        let (reduced, borrow) = sum.sub_raw(modulus);
        Self::ct_select(&reduced, &sum, carry == 1 || borrow == 0)
    }

    #[inline]
    pub fn sub_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let (diff, borrow) = self.sub_raw(rhs);
        let (corrected, _) = diff.add_raw(modulus);
        Self::ct_select(&corrected, &diff, borrow == 1)
    }

    #[inline]
    pub fn double_mod(&self, modulus: &Self) -> Self {
        self.add_mod(self, modulus)
    }

    fn mul_wide_internal(&self, rhs: &Self) -> [u64; MAX_LIMBS] {
        assert!(LIMBS * 2 <= MAX_LIMBS);
        let mut out = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < LIMBS {
            let mut carry = 0u64;
            let mut j = 0;
            while j < LIMBS {
                let (word, next_carry) = mac(out[i + j], self.limbs[i], rhs.limbs[j], carry);
                out[i + j] = word;
                carry = next_carry;
                j += 1;
            }
            let mut k = i + LIMBS;
            while k < MAX_LIMBS {
                let (word, next_carry) = adc(out[k], 0, carry);
                out[k] = word;
                carry = next_carry;
                k += 1;
            }
            i += 1;
        }
        out
    }

    fn reduce_wide_internal(product: &[u64; MAX_LIMBS], modulus: &Self) -> Self {
        let total_bits = LIMBS * 128;
        let mut rem = Self::ZERO;
        let mut bit_index = total_bits;
        while bit_index > 0 {
            bit_index -= 1;
            let limb_idx = bit_index / 64;
            let bit_pos = bit_index % 64;
            let bit = ((product[limb_idx] >> bit_pos) & 1) as u64;

            let mut shifted = [0u64; LIMBS];
            let mut carry = bit;
            let mut i = 0;
            while i < LIMBS {
                let next = rem.limbs[i] >> 63;
                shifted[i] = (rem.limbs[i] << 1) | carry;
                carry = next;
                i += 1;
            }
            let shifted_rem = Self {
                limbs: shifted,
            };
            let (reduced, borrow) = shifted_rem.sub_raw(modulus);
            rem = Self::ct_select(&reduced, &shifted_rem, carry == 1 || borrow == 0);
        }
        rem
    }

    #[inline]
    pub fn mul_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let product = self.mul_wide_internal(rhs);
        Self::reduce_wide_internal(&product, modulus)
    }

    #[inline]
    pub fn add_word(&self, word: u64) -> (Self, u64) {
        let mut out = self.limbs;
        let (first, mut carry) = adc(out[0], word, 0);
        out[0] = first;
        let mut i = 1;
        while i < LIMBS {
            let (next, next_carry) = adc(out[i], 0, carry);
            out[i] = next;
            carry = next_carry;
            i += 1;
        }
        (
            Self {
                limbs: out,
            },
            carry,
        )
    }

    #[inline]
    pub fn sub_word(&self, word: u64) -> (Self, u64) {
        let mut out = self.limbs;
        let (first, mut borrow) = sbb(out[0], word, 0);
        out[0] = first;
        let mut i = 1;
        while i < LIMBS {
            let (next, next_borrow) = sbb(out[i], 0, borrow);
            out[i] = next;
            borrow = next_borrow;
            i += 1;
        }
        (
            Self {
                limbs: out,
            },
            borrow,
        )
    }

    #[inline]
    pub fn mul_word(&self, word: u64) -> (Self, u64) {
        let mut out = [0u64; LIMBS];
        let mut carry = 0u64;
        let mut i = 0;
        while i < LIMBS {
            let (next, next_carry) = mac(0, self.limbs[i], word, carry);
            out[i] = next;
            carry = next_carry;
            i += 1;
        }
        (
            Self {
                limbs: out,
            },
            carry,
        )
    }

    #[inline]
    pub fn div_rem_word(&self, word: u64) -> (Self, u64) {
        assert!(word != 0, "division by zero");
        let mut out = [0u64; LIMBS];
        let mut rem = 0u64;
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            let dividend = ((rem as u128) << 64) | self.limbs[i] as u128;
            out[i] = (dividend / word as u128) as u64;
            rem = (dividend % word as u128) as u64;
        }
        (
            Self {
                limbs: out,
            },
            rem,
        )
    }

    pub fn from_str_radix(src: &str, radix: u32) -> Result<Self, Error> {
        if !(2..=36).contains(&radix) {
            return Err(Error::InvalidRadix);
        }
        if src.is_empty() {
            return Err(Error::EmptyString);
        }

        let mut out = Self::ZERO;
        for byte in src.bytes() {
            let digit = char_to_digit(byte).ok_or(Error::InvalidDigit)?;
            if digit >= radix {
                return Err(Error::InvalidDigit);
            }
            let (mul, high) = out.mul_word(radix as u64);
            if high != 0 {
                return Err(Error::Overflow);
            }
            let (next, carry) = mul.add_word(digit as u64);
            if carry != 0 {
                return Err(Error::Overflow);
            }
            out = next;
        }
        Ok(out)
    }

    #[cfg(feature = "alloc")]
    pub fn to_string_radix(&self, radix: u32) -> String {
        assert!((2..=36).contains(&radix), "invalid radix");
        if self.is_zero() {
            return String::from("0");
        }

        let mut value = *self;
        let mut digits = Vec::new();
        while !value.is_zero() {
            let (quotient, remainder) = value.div_rem_word(radix as u64);
            digits.push(digit_to_char(remainder, false));
            value = quotient;
        }
        digits.into_iter().rev().collect()
    }
}

#[cfg(feature = "alloc")]
impl<const BITS: usize, const LIMBS: usize> fmt::Display for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_radix(10))
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::LowerHex for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        let mut started = false;
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            let limb = self.limbs[i];
            if started {
                write!(f, "{limb:016x}")?;
            } else if limb != 0 {
                write!(f, "{limb:x}")?;
                started = true;
            }
        }
        if !started {
            f.write_str("0")?;
        }
        Ok(())
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::UpperHex for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        let mut started = false;
        let mut i = LIMBS;
        while i > 0 {
            i -= 1;
            let limb = self.limbs[i];
            if started {
                write!(f, "{limb:016X}")?;
            } else if limb != 0 {
                write!(f, "{limb:X}")?;
                started = true;
            }
        }
        if !started {
            f.write_str("0")?;
        }
        Ok(())
    }
}

impl<const BITS: usize, const LIMBS: usize> fmt::Debug for Uint<BITS, LIMBS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uint(0x{self:x})")
    }
}

impl<const BITS: usize, const LIMBS: usize> Int<BITS, LIMBS> {
    const _LIMBS_CHECK: () = assert!(LIMBS == (BITS + 63) / 64, "LIMBS must equal ceil(BITS/64)");

    pub const ZERO: Self = Self(Uint::ZERO);
    pub const ONE: Self = Self(Uint::ONE);
    pub const MINUS_ONE: Self = Self(Uint::MAX);

    #[inline]
    const fn from_uint_bits(bits: Uint<BITS, LIMBS>) -> Self {
        Self(bits)
    }

    #[inline]
    fn from_u128(value: u128) -> Self {
        Self(uint_from_u128(value))
    }

    #[inline]
    fn from_i128(value: i128) -> Self {
        if value.is_negative() {
            let magnitude = uint_from_u128::<BITS, LIMBS>(value.unsigned_abs());
            Self(Self::ZERO.0.sub_raw(&magnitude).0)
        } else {
            Self(uint_from_u128(value as u128))
        }
    }

    #[inline]
    pub fn is_negative(&self) -> bool {
        (self.0.limbs[LIMBS - 1] >> 63) == 1
    }

    #[inline]
    pub fn abs(&self) -> Uint<BITS, LIMBS> {
        if self.is_negative() {
            Self::ZERO.0.sub_raw(&self.0).0
        } else {
            self.0
        }
    }
}

impl<const BITS: usize, const LIMBS: usize> Add for Uint<BITS, LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_raw(&rhs).0
    }
}

impl<const BITS: usize, const LIMBS: usize> Sub for Uint<BITS, LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_raw(&rhs).0
    }
}

impl<const BITS: usize, const LIMBS: usize> Mul for Uint<BITS, LIMBS> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let product = self.mul_wide_internal(&rhs);
        let mut limbs = [0u64; LIMBS];
        let mut i = 0;
        while i < LIMBS {
            limbs[i] = product[i];
            i += 1;
        }
        Self {
            limbs,
        }
    }
}

impl<const BITS: usize, const LIMBS: usize> Add for Int<BITS, LIMBS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::from_uint_bits(self.0.add_raw(&rhs.0).0)
    }
}

impl<const BITS: usize, const LIMBS: usize> Sub for Int<BITS, LIMBS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::from_uint_bits(self.0.sub_raw(&rhs.0).0)
    }
}

impl<const BITS: usize, const LIMBS: usize> Neg for Int<BITS, LIMBS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::from_uint_bits(Int::ZERO.0.sub_raw(&self.0).0)
    }
}

macro_rules! impl_uint_ops_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<const BITS: usize, const LIMBS: usize> Add<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn add(self, rhs: $ty) -> Self::Output {
                    self.add_word(u128_to_word(rhs as u128)).0
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Sub<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn sub(self, rhs: $ty) -> Self::Output {
                    self.sub_word(u128_to_word(rhs as u128)).0
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Mul<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn mul(self, rhs: $ty) -> Self::Output {
                    self.mul_word(u128_to_word(rhs as u128)).0
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Div<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn div(self, rhs: $ty) -> Self::Output {
                    self.div_rem_word(u128_to_word(rhs as u128)).0
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Rem<$ty> for Uint<BITS, LIMBS> {
                type Output = u64;
                fn rem(self, rhs: $ty) -> Self::Output {
                    self.div_rem_word(u128_to_word(rhs as u128)).1
                }
            }
        )*
    };
}

macro_rules! impl_uint_ops_signed {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<const BITS: usize, const LIMBS: usize> Add<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn add(self, rhs: $ty) -> Self::Output {
                    let (word, negative) = i128_abs_to_word(rhs as i128);
                    if negative {
                        self.sub_word(word).0
                    } else {
                        self.add_word(word).0
                    }
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Sub<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn sub(self, rhs: $ty) -> Self::Output {
                    let (word, negative) = i128_abs_to_word(rhs as i128);
                    if negative {
                        self.add_word(word).0
                    } else {
                        self.sub_word(word).0
                    }
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Mul<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn mul(self, rhs: $ty) -> Self::Output {
                    self.mul_word(i128_abs_to_word(rhs as i128).0).0
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Div<$ty> for Uint<BITS, LIMBS> {
                type Output = Self;
                fn div(self, rhs: $ty) -> Self::Output {
                    self.div_rem_word(i128_abs_to_word(rhs as i128).0).0
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Rem<$ty> for Uint<BITS, LIMBS> {
                type Output = u64;
                fn rem(self, rhs: $ty) -> Self::Output {
                    self.div_rem_word(i128_abs_to_word(rhs as i128).0).1
                }
            }
        )*
    };
}

macro_rules! impl_int_ops_unsigned {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<const BITS: usize, const LIMBS: usize> Add<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn add(self, rhs: $ty) -> Self::Output {
                    self + Self::from_u128(rhs as u128)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Sub<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn sub(self, rhs: $ty) -> Self::Output {
                    self - Self::from_u128(rhs as u128)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Mul<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn mul(self, rhs: $ty) -> Self::Output {
                    let (product, _) = self.abs().mul_word(u128_to_word(rhs as u128));
                    let bits = if self.is_negative() {
                        Uint::ZERO.sub_raw(&product).0
                    } else {
                        product
                    };
                    Self::from_uint_bits(bits)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Div<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn div(self, rhs: $ty) -> Self::Output {
                    let (quotient, _) = self.abs().div_rem_word(u128_to_word(rhs as u128));
                    let bits = if self.is_negative() {
                        Uint::ZERO.sub_raw(&quotient).0
                    } else {
                        quotient
                    };
                    Self::from_uint_bits(bits)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Rem<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn rem(self, rhs: $ty) -> Self::Output {
                    let (_, remainder) = self.abs().div_rem_word(u128_to_word(rhs as u128));
                    let bits = Uint::from_u64(remainder);
                    let bits = if self.is_negative() {
                        Uint::ZERO.sub_raw(&bits).0
                    } else {
                        bits
                    };
                    Self::from_uint_bits(bits)
                }
            }
        )*
    };
}

macro_rules! impl_int_ops_signed {
    ($($ty:ty),* $(,)?) => {
        $(
            impl<const BITS: usize, const LIMBS: usize> Add<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn add(self, rhs: $ty) -> Self::Output {
                    self + Self::from_i128(rhs as i128)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Sub<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn sub(self, rhs: $ty) -> Self::Output {
                    self - Self::from_i128(rhs as i128)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Mul<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn mul(self, rhs: $ty) -> Self::Output {
                    let (word, negative) = i128_abs_to_word(rhs as i128);
                    let (product, _) = self.abs().mul_word(word);
                    let make_negative = self.is_negative() ^ negative;
                    let bits = if make_negative {
                        Uint::ZERO.sub_raw(&product).0
                    } else {
                        product
                    };
                    Self::from_uint_bits(bits)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Div<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn div(self, rhs: $ty) -> Self::Output {
                    let (word, negative) = i128_abs_to_word(rhs as i128);
                    let (quotient, _) = self.abs().div_rem_word(word);
                    let make_negative = self.is_negative() ^ negative;
                    let bits = if make_negative {
                        Uint::ZERO.sub_raw(&quotient).0
                    } else {
                        quotient
                    };
                    Self::from_uint_bits(bits)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> Rem<$ty> for Int<BITS, LIMBS> {
                type Output = Self;
                fn rem(self, rhs: $ty) -> Self::Output {
                    let (word, _) = i128_abs_to_word(rhs as i128);
                    let (_, remainder) = self.abs().div_rem_word(word);
                    let bits = Uint::from_u64(remainder);
                    let bits = if self.is_negative() {
                        Uint::ZERO.sub_raw(&bits).0
                    } else {
                        bits
                    };
                    Self::from_uint_bits(bits)
                }
            }
        )*
    };
}

impl_uint_ops_unsigned!(u8, u16, u32, u64, u128);
impl_uint_ops_signed!(i8, i16, i32, i64, i128);
impl_int_ops_unsigned!(u8, u16, u32, u64, u128);
impl_int_ops_signed!(i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;
    type U256 = Uint<256, 4>;
    type U128 = Uint<128, 2>;
    type I128 = Int<128, 2>;

    const P256_MODULUS: U256 = U256::from_limbs([
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ]);
    const P256_ORDER: U256 = U256::from_limbs([
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ]);
    const P256_P_MINUS_TWO: U256 = U256::from_limbs([
        0xffff_ffff_ffff_fffd,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ]);
    const P256_P_PLUS_ONE_OVER_FOUR: U256 = U256::from_limbs([
        0x0000_0000_0000_0000,
        0x0000_0000_4000_0000,
        0x4000_0000_0000_0000,
        0x3fff_ffff_c000_0000,
    ]);
    const ED25519_P: U256 = U256::from_limbs([
        0xffff_ffff_ffff_ffed,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x7fff_ffff_ffff_ffff,
    ]);

    fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut out = [0u8; N];
        let bytes = input.as_bytes();
        let mut i = 0;
        while i < N {
            let hi = char_to_digit(bytes[i * 2]).unwrap() as u8;
            let lo = char_to_digit(bytes[i * 2 + 1]).unwrap() as u8;
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    #[test]
    fn raw_arithmetic_reports_carry_and_borrow() {
        let (sum, carry) = U128::MAX.add_raw(&U128::ONE);
        assert_eq!(sum, U128::ZERO);
        assert_eq!(carry, 1);

        let (diff, borrow) = U128::ZERO.sub_raw(&U128::ONE);
        assert_eq!(diff, U128::MAX);
        assert_eq!(borrow, 1);

        let (low, high) = U128::MAX.mul_word(2);
        assert_eq!(low, U128::from_limbs([0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff]));
        assert_eq!(high, 1);
    }

    #[test]
    fn modular_arithmetic_matches_known_values() {
        assert_eq!(P256_P_MINUS_TWO.add_mod(&U256::from_u64(2), &P256_MODULUS), U256::ZERO);
        assert_eq!(
            P256_MODULUS.sub_mod(&U256::from_u64(1), &P256_MODULUS),
            P256_MODULUS - U256::ONE
        );
        assert_eq!(P256_P_MINUS_TWO.double_mod(&P256_MODULUS), P256_MODULUS - U256::from_u64(4));
        assert_eq!(P256_P_PLUS_ONE_OVER_FOUR.mul_mod(&U256::from_u64(4), &P256_MODULUS), U256::ONE);
        assert_eq!(P256_ORDER.add_mod(&U256::ONE, &P256_ORDER), U256::ONE);
    }

    #[test]
    fn string_round_trips_for_common_radices() {
        let values = [
            U256::ZERO,
            U256::ONE,
            U256::MAX,
            U256::from_be_slice(&decode_hex::<32>(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            )),
        ];

        for value in values {
            for radix in [2, 10, 16] {
                let encoded = value.to_string_radix(radix);
                let decoded = U256::from_str_radix(&encoded, radix).unwrap();
                assert_eq!(decoded, value);
            }
        }
    }

    #[test]
    fn operator_overloads_work_with_primitives() {
        let value = U128::from_u64(10);
        assert_eq!(value + 5u64, U128::from_u64(15));
        assert_eq!(value - (-5i32), U128::from_u64(15));
        assert_eq!(value * -3i32, U128::from_u64(30));
        assert_eq!(value / -3i32, U128::from_u64(3));
        assert_eq!(value % -3i32, 1);

        let signed = I128::from_i128(-10);
        assert_eq!(signed + 3u32, I128::from_i128(-7));
        assert_eq!(signed - (-5i32), I128::from_i128(-5));
        assert_eq!(signed * -2i32, I128::from_i128(20));
        assert_eq!(signed / -4i32, I128::from_i128(2));
        assert_eq!(signed % 4u32, I128::from_i128(-2));
    }

    #[test]
    fn constant_time_helpers_select_and_compare() {
        let a = U256::from_u64(7);
        let b = U256::from_u64(11);
        assert_eq!(U256::ct_select(&a, &b, true), a);
        assert_eq!(U256::ct_select(&a, &b, false), b);
        assert!(a.ct_eq(&a));
        assert!(!a.ct_eq(&b));
        assert!(b.ct_ge(&a));
        assert!(!a.ct_ge(&b));
    }

    #[test]
    fn from_str_radix_rejects_invalid_inputs() {
        assert_eq!(U128::from_str_radix("", 10), Err(Error::EmptyString));
        assert_eq!(U128::from_str_radix("10", 1), Err(Error::InvalidRadix));
        assert_eq!(U128::from_str_radix("2", 2), Err(Error::InvalidDigit));
        assert_eq!(U128::from_str_radix("zz", 10), Err(Error::InvalidDigit));
        assert_eq!(
            U128::from_str_radix("340282366920938463463374607431768211456", 10),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn byte_round_trips_match_p256_constants() {
        let modulus_hex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        let order_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

        let modulus_bytes = decode_hex::<32>(modulus_hex);
        let order_bytes = decode_hex::<32>(order_hex);

        let modulus = U256::from_be_slice(&modulus_bytes);
        let order = U256::from_be_slice(&order_bytes);

        assert_eq!(modulus, P256_MODULUS);
        assert_eq!(order, P256_ORDER);
        assert_eq!(modulus.to_be_bytes_fixed::<32>(), modulus_bytes);
        assert_eq!(order.to_be_bytes_fixed::<32>(), order_bytes);
        assert_eq!(format!("{modulus:x}"), modulus_hex);
        assert_eq!(format!("{order:X}"), order_hex.to_uppercase());
    }

    #[test]
    fn little_endian_round_trip_works() {
        let value = U256::from_be_slice(&decode_hex::<32>(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ));
        let le = value.to_le_bytes_fixed::<32>();
        assert_eq!(U256::from_le_slice(&le), value);
    }

    #[test]
    fn modular_addition_vectors() {
        struct Test {
            a: U256,
            b: U256,
            m: U256,
            expected: U256,
        }
        let tests = [
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: P256_MODULUS,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::ONE,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::from_u64(2),
            },
            Test {
                a: P256_MODULUS - U256::ONE,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::ZERO,
            },
            Test {
                a: P256_MODULUS - U256::ONE,
                b: U256::from_u64(2),
                m: P256_MODULUS,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: P256_ORDER,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::ONE,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::from_u64(2),
            },
            Test {
                a: U256::MAX,
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::from_limbs([
                    0x0c46_353d_039c_daaf,
                    0x4319_0552_58e8_617b,
                    0x0000_0000_0000_0000,
                    0x0000_0000_ffff_ffff,
                ]),
            },
            Test {
                a: P256_ORDER - U256::ONE,
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::ZERO,
            },
            Test {
                a: P256_ORDER - U256::ONE,
                b: U256::from_u64(2),
                m: P256_ORDER,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: ED25519_P,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: ED25519_P,
                expected: U256::ONE,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                m: ED25519_P,
                expected: U256::from_u64(2),
            },
            Test {
                a: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::from_limbs([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            },
            Test {
                a: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::from_limbs([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            },
            Test {
                a: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                b: U256::ONE,
                m: ED25519_P,
                expected: U256::from_limbs([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            },
            Test {
                a: ED25519_P - U256::ONE,
                b: ED25519_P - U256::ONE,
                m: ED25519_P,
                expected: (ED25519_P - U256::ONE).double_mod(&ED25519_P),
            },
        ];
        for t in &tests {
            assert_eq!(t.a.add_mod(&t.b, &t.m), t.expected, "add_mod({:x}, {:x}, {:x})", t.a, t.b, t.m);
        }
    }

    #[test]
    fn modular_subtraction_vectors() {
        struct Test {
            a: U256,
            b: U256,
            m: U256,
            expected: U256,
        }
        let tests = [
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: P256_MODULUS,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                m: P256_MODULUS,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: P256_MODULUS - U256::ONE,
            },
            Test {
                a: P256_MODULUS - U256::ONE,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: P256_MODULUS - U256::from_u64(2),
            },
            Test {
                a: U256::ONE,
                b: P256_MODULUS - U256::ONE,
                m: P256_MODULUS,
                expected: U256::from_u64(2),
            },
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: P256_ORDER,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                m: P256_ORDER,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: P256_ORDER,
                expected: P256_ORDER - U256::ONE,
            },
            Test {
                a: P256_ORDER - U256::ONE,
                b: U256::ONE,
                m: P256_ORDER,
                expected: P256_ORDER - U256::from_u64(2),
            },
            Test {
                a: U256::ONE,
                b: P256_ORDER - U256::ONE,
                m: P256_ORDER,
                expected: U256::from_u64(2),
            },
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: ED25519_P,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                m: ED25519_P,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: ED25519_P,
                expected: ED25519_P - U256::ONE,
            },
            Test {
                a: ED25519_P - U256::ONE,
                b: U256::ONE,
                m: ED25519_P,
                expected: ED25519_P - U256::from_u64(2),
            },
            Test {
                a: U256::ONE,
                b: ED25519_P - U256::ONE,
                m: ED25519_P,
                expected: U256::from_u64(2),
            },
        ];
        for t in &tests {
            assert_eq!(t.a.sub_mod(&t.b, &t.m), t.expected, "sub_mod({:x}, {:x}, {:x})", t.a, t.b, t.m);
        }
    }

    #[test]
    fn modular_multiplication_vectors() {
        struct Test {
            a: U256,
            b: U256,
            m: U256,
            expected: U256,
        }
        let tests = [
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: P256_MODULUS,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                m: P256_MODULUS,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::ONE,
            },
            Test {
                a: U256::from_u64(2),
                b: U256::from_u64(3),
                m: P256_MODULUS,
                expected: U256::from_u64(6),
            },
            Test {
                a: U256::MAX,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: U256::from_limbs([
                    0x0000_0000_0000_0000,
                    0xffff_ffff_0000_0000,
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_ffff_fffe,
                ]),
            },
            Test {
                a: P256_MODULUS - U256::ONE,
                b: U256::ONE,
                m: P256_MODULUS,
                expected: P256_MODULUS - U256::ONE,
            },
            Test {
                a: P256_MODULUS - U256::ONE,
                b: P256_MODULUS - U256::ONE,
                m: P256_MODULUS,
                expected: U256::ONE,
            },
            Test {
                a: P256_MODULUS + U256::ONE,
                b: P256_MODULUS + U256::ONE,
                m: P256_MODULUS,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: P256_ORDER,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                m: P256_ORDER,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                m: P256_ORDER,
                expected: U256::ONE,
            },
            Test {
                a: U256::from_u64(2),
                b: U256::from_u64(3),
                m: P256_ORDER,
                expected: U256::from_u64(6),
            },
            Test {
                a: P256_ORDER - U256::ONE,
                b: U256::ONE,
                m: P256_ORDER,
                expected: P256_ORDER - U256::ONE,
            },
            Test {
                a: P256_ORDER - U256::ONE,
                b: P256_ORDER - U256::ONE,
                m: P256_ORDER,
                expected: U256::ONE,
            },
            Test {
                a: P256_ORDER + U256::ONE,
                b: P256_ORDER + U256::ONE,
                m: P256_ORDER,
                expected: U256::ONE,
            },
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                m: ED25519_P,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                m: ED25519_P,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                m: ED25519_P,
                expected: U256::ZERO,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                m: ED25519_P,
                expected: U256::ONE,
            },
            Test {
                a: U256::from_u64(2),
                b: U256::from_u64(3),
                m: ED25519_P,
                expected: U256::from_u64(6),
            },
            Test {
                a: ED25519_P - U256::ONE,
                b: U256::ONE,
                m: ED25519_P,
                expected: ED25519_P - U256::ONE,
            },
            Test {
                a: ED25519_P - U256::ONE,
                b: ED25519_P - U256::ONE,
                m: ED25519_P,
                expected: U256::ONE,
            },
            Test {
                a: ED25519_P + U256::ONE,
                b: ED25519_P + U256::ONE,
                m: ED25519_P,
                expected: U256::ONE,
            },
            Test {
                a: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                b: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                m: P256_MODULUS,
                expected: U256::from_limbs([
                    0x0000_0000_0000_0001,
                    0xffff_ffff_ffff_fffe,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            },
        ];
        for t in &tests {
            assert_eq!(t.a.mul_mod(&t.b, &t.m), t.expected, "mul_mod({:x}, {:x}, {:x})", t.a, t.b, t.m);
        }
    }

    #[test]
    fn raw_addition_vectors() {
        struct Test {
            a: U256,
            b: U256,
            expected_sum: U256,
            expected_carry: u64,
        }
        let tests = [
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                expected_sum: U256::ZERO,
                expected_carry: 0,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                expected_sum: U256::ONE,
                expected_carry: 0,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                expected_sum: U256::from_u64(2),
                expected_carry: 0,
            },
            Test {
                a: U256::MAX,
                b: U256::ZERO,
                expected_sum: U256::MAX,
                expected_carry: 0,
            },
            Test {
                a: U256::MAX,
                b: U256::ONE,
                expected_sum: U256::ZERO,
                expected_carry: 1,
            },
            Test {
                a: U256::MAX,
                b: U256::MAX,
                expected_sum: U256::MAX - U256::ONE,
                expected_carry: 1,
            },
            Test {
                a: U256::MAX - U256::ONE,
                b: U256::ONE,
                expected_sum: U256::MAX,
                expected_carry: 0,
            },
            Test {
                a: U256::ONE,
                b: U256::MAX,
                expected_sum: U256::ZERO,
                expected_carry: 1,
            },
            Test {
                a: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                b: U256::ONE,
                expected_sum: U256::from_limbs([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                expected_carry: 0,
            },
            Test {
                a: U256::from_limbs([
                    0xffff_ffff_ffff_ffff,
                    0xffff_ffff_ffff_ffff,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                b: U256::ONE,
                expected_sum: U256::from_limbs([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                ]),
                expected_carry: 0,
            },
        ];
        for t in &tests {
            let (sum, carry) = t.a.add_raw(&t.b);
            assert_eq!(sum, t.expected_sum, "add_raw({:x}, {:x}).sum", t.a, t.b);
            assert_eq!(carry, t.expected_carry, "add_raw({:x}, {:x}).carry", t.a, t.b);
        }
    }

    #[test]
    fn raw_subtraction_vectors() {
        struct Test {
            a: U256,
            b: U256,
            expected_diff: U256,
            expected_borrow: u64,
        }
        let tests = [
            Test {
                a: U256::ZERO,
                b: U256::ZERO,
                expected_diff: U256::ZERO,
                expected_borrow: 0,
            },
            Test {
                a: U256::ONE,
                b: U256::ZERO,
                expected_diff: U256::ONE,
                expected_borrow: 0,
            },
            Test {
                a: U256::ONE,
                b: U256::ONE,
                expected_diff: U256::ZERO,
                expected_borrow: 0,
            },
            Test {
                a: U256::ZERO,
                b: U256::ONE,
                expected_diff: U256::MAX,
                expected_borrow: 1,
            },
            Test {
                a: U256::MAX,
                b: U256::MAX,
                expected_diff: U256::ZERO,
                expected_borrow: 0,
            },
            Test {
                a: U256::MAX,
                b: U256::ZERO,
                expected_diff: U256::MAX,
                expected_borrow: 0,
            },
            Test {
                a: U256::MAX,
                b: U256::MAX - U256::ONE,
                expected_diff: U256::ONE,
                expected_borrow: 0,
            },
            Test {
                a: U256::ONE,
                b: U256::MAX,
                expected_diff: U256::from_u64(2),
                expected_borrow: 1,
            },
        ];
        for t in &tests {
            let (diff, borrow) = t.a.sub_raw(&t.b);
            assert_eq!(diff, t.expected_diff, "sub_raw({:x}, {:x}).diff", t.a, t.b);
            assert_eq!(borrow, t.expected_borrow, "sub_raw({:x}, {:x}).borrow", t.a, t.b);
        }
    }

    #[test]
    fn string_roundtrip_vectors() {
        struct Test {
            value: U256,
            radix: u32,
            expected: &'static str,
        }
        let tests = [
            Test {
                value: U256::ZERO,
                radix: 2,
                expected: "0",
            },
            Test {
                value: U256::ZERO,
                radix: 10,
                expected: "0",
            },
            Test {
                value: U256::ZERO,
                radix: 16,
                expected: "0",
            },
            Test {
                value: U256::ONE,
                radix: 2,
                expected: "1",
            },
            Test {
                value: U256::ONE,
                radix: 10,
                expected: "1",
            },
            Test {
                value: U256::ONE,
                radix: 16,
                expected: "1",
            },
            Test {
                value: U256::MAX,
                radix: 10,
                expected: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
            },
            Test {
                value: U256::MAX,
                radix: 16,
                expected: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            },
            Test {
                value: P256_MODULUS,
                radix: 10,
                expected: "115792089210356248762697446949407573530086143415290314195533631308867097853951",
            },
            Test {
                value: P256_MODULUS,
                radix: 16,
                expected: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            },
            Test {
                value: P256_ORDER,
                radix: 10,
                expected: "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            },
            Test {
                value: P256_ORDER,
                radix: 16,
                expected: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            },
            Test {
                value: ED25519_P,
                radix: 10,
                expected: "57896044618658097711785492504343953926634992332820282019728792003956564819949",
            },
            Test {
                value: ED25519_P,
                radix: 16,
                expected: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
            },
        ];
        for t in &tests {
            let encoded = t.value.to_string_radix(t.radix);
            assert_eq!(encoded, t.expected, "to_string_radix({:x}, {})", t.value, t.radix);
            let decoded = U256::from_str_radix(t.expected, t.radix).unwrap();
            assert_eq!(decoded, t.value, "from_str_radix round-trip");
        }
    }

    #[test]
    fn mul_mod_edge_cases() {
        assert_eq!(P256_P_PLUS_ONE_OVER_FOUR.mul_mod(&U256::from_u64(4), &P256_MODULUS), U256::ONE);

        let (a, _) = U256::MAX.mul_word(2);
        assert_eq!(a.add_mod(&U256::ZERO, &P256_MODULUS), U256::MAX.double_mod(&P256_MODULUS));
    }
}
