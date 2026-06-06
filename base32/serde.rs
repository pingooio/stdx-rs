use alloc::vec::Vec;
use core::fmt;

use serde::{
    Deserializer, Serializer,
    de::{self, Visitor},
};

use crate::{Alphabet, decode, encode};

const FORMAT: Alphabet = Alphabet::Rfc4648;

pub fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&encode(data, FORMAT))
    } else {
        serializer.serialize_bytes(data)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(Base32Visitor)
    } else {
        deserializer.deserialize_bytes(Base32Visitor)
    }
}

struct Base32Visitor;

impl<'de> Visitor<'de> for Base32Visitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a base32 string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        decode(v.as_bytes(), FORMAT).map_err(de::Error::custom)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }
}
