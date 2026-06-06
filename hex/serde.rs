use alloc::{vec, vec::Vec};
use core::fmt;

use serde::{
    Deserializer, Serializer,
    de::{self, Visitor},
};

use crate::{decode, encode};

#[cfg_attr(
    all(feature = "alloc", feature = "serde"),
    doc = r##"
# Example

```
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Foo {
    #[serde(with = "hex")]
    bar: Vec<u8>,
}
```
"##
)]

pub fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.serialize_str(&encode(data))
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
        decode(v.as_bytes()).map_err(de::Error::custom)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }
}
