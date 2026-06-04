use alloc::{vec, vec::Vec};
use core::fmt;

use serde::{
    Deserializer, Serializer,
    de::{self, Visitor},
};

use crate::{Alphabet, decode_into, encode_into};

const FORMAT: Alphabet = Alphabet::Lower;

pub fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        let mut buf = vec![0u8; data.len() * 2];
        encode_into(&mut buf, data, FORMAT);
        serializer.serialize_str(unsafe { core::str::from_utf8_unchecked(&buf) })
    } else {
        serializer.serialize_bytes(data)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(HexVisitor)
    } else {
        deserializer.deserialize_bytes(HexVisitor)
    }
}

struct HexVisitor;

impl<'de> Visitor<'de> for HexVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a hex string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        let mut output = vec![0u8; v.len() / 2];
        decode_into(&mut output, v.as_bytes(), FORMAT).map_err(de::Error::custom)?;
        Ok(output)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }
}
