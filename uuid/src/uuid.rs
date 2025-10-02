mod fmt;
mod parse;
mod serde;
mod v4;
mod v7;
mod v8;
// _mod error;

#[derive(Clone, Copy, Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("uuid: Size is not valid")]
    InvalidSize,
    #[error("uuid: Invalid uuid")]
    InvalidUuid,
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Uuid([u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Version {
    /// The "nil" (all zeros) UUID.
    Nil = 0u8,
    /// Version 4: Random.
    V4 = 4,
    /// Version 7: Timestamp and random.
    V7 = 7,
    /// Version 8: Custom
    V8 = 8,
    /// The "max" (all ones) UUID.
    Max = 0xff,
}

impl Uuid {
    /// The 'nil UUID' (all zeros).
    ///
    /// The nil UUID is a special form of UUID that is specified to have all
    /// 128 bits set to zero.
    ///
    /// # References
    ///
    /// * [Nil UUID in RFC4122](https://tools.ietf.org/html/rfc4122.html#section-4.1.7)
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// # use uuid::Uuid;
    /// let uuid = Uuid::nil();
    ///
    /// assert_eq!(
    ///     "00000000-0000-0000-0000-000000000000",
    ///     uuid.hyphenated().to_string(),
    /// );
    /// ```
    pub const fn nil() -> Uuid {
        Uuid([0; 16])
    }

    pub const fn get_version(&self) -> Option<Version> {
        match self.0[6] >> 4 {
            0 if self.is_nil() => Some(Version::Nil),
            4 => Some(Version::V4),
            7 => Some(Version::V7),
            0xf => Some(Version::Max),
            _ => None,
        }
    }

    pub const fn is_nil(&self) -> bool {
        self.as_u128() == u128::MIN
    }

    pub const fn as_u128(&self) -> u128 {
        u128::from_be_bytes(self.0)
    }

    pub const fn from_u128(v: u128) -> Self {
        Uuid::from_bytes([
            (v >> 120) as u8,
            (v >> 112) as u8,
            (v >> 104) as u8,
            (v >> 96) as u8,
            (v >> 88) as u8,
            (v >> 80) as u8,
            (v >> 72) as u8,
            (v >> 64) as u8,
            (v >> 56) as u8,
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ])
    }

    #[inline]
    pub const fn from_bytes(bytes: [u8; 16]) -> Uuid {
        Uuid(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn from_slice(b: &[u8]) -> Result<Uuid, Error> {
        if b.len() != 16 {
            return Err(Error::InvalidSize);
        }

        let mut bytes = [0; 16];
        bytes.copy_from_slice(b);
        return Ok(Uuid(bytes));
    }

    pub fn parse_str(input: &str) -> Result<Uuid, Error> {
        Self::try_parse(input.as_bytes())
            .map(|bytes| Uuid(bytes))
            .map_err(|_| Error::InvalidUuid)
    }

    const fn try_parse(input: &[u8]) -> Result<[u8; 16], Error> {
        match (input.len(), input) {
            (36, s) => parse::parse_hyphenated(s),
            // Any other shaped input is immediately invalid
            _ => Err(Error::InvalidUuid),
        }
    }
}

// The following types and methods are used to mimick the uuid crate so we can override our dependencies
// with stdx's uuid
impl Uuid {
    pub fn hyphenated(&self) -> String {
        return self.to_string();
    }

    pub fn as_hyphenated(&self) -> String {
        return self.to_string();
    }

    pub fn simple(&self) -> Self {
        return self.clone();
    }

    pub fn as_simple(&self) -> Self {
        return self.clone();
    }
}

pub type Bytes = [u8; 16];

#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Variant {
    /// Reserved by the NCS for backward compatibility.
    NCS = 0u8,
    /// As described in the RFC 9562 Specification (default).
    /// (for backward compatibility it is not yet renamed)
    RFC4122,
    /// Reserved by Microsoft for backward compatibility.
    Microsoft,
    /// Reserved for future expansion.
    Future,
}

// Compatibility layer for the aws-sdk
pub struct Builder(Uuid);

impl Builder {
    pub const fn from_random_bytes(random_bytes: Bytes) -> Self {
        Builder(Uuid::from_bytes(random_bytes))
            .with_variant(Variant::RFC4122)
            .with_version(Version::V4)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }

    pub const fn with_variant(mut self, v: Variant) -> Self {
        let byte = (self.0).0[8];

        (self.0).0[8] = match v {
            Variant::NCS => byte & 0x7f,
            Variant::RFC4122 => (byte & 0x3f) | 0x80,
            Variant::Microsoft => (byte & 0x1f) | 0xc0,
            Variant::Future => byte | 0xe0,
        };

        self
    }

    pub const fn with_version(mut self, v: Version) -> Self {
        (self.0).0[6] = ((self.0).0[6] & 0x0f) | ((v as u8) << 4);

        self
    }
}
