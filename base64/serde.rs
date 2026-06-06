use alloc::{vec, vec::Vec};
use core::fmt;

use serde::{
    Deserializer, Serializer,
    de::{self, Visitor},
};

use crate::{Alphabet, decode_into, encode_into, encoded_length};

#[cfg_attr(
    all(feature = "alloc", feature = "serde"),
    doc = r##"
# Example

```
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Foo {
    #[serde(with = "base64")]
    bar: Vec<u8>,
}
```
"##
)]

const FORMAT: Alphabet = Alphabet::Standard;

pub fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        let len = encoded_len(data.len(), true);
        let mut buf = vec![0u8; len];
        encode_into(&mut buf, data, FORMAT);
        serializer.serialize_str(unsafe { core::str::from_utf8_unchecked(&buf) })
    } else {
        serializer.serialize_bytes(data)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(Base64Visitor)
    } else {
        deserializer.deserialize_bytes(Base64Visitor)
    }
}

struct Base64Visitor;

impl<'de> Visitor<'de> for Base64Visitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a base64 string")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        let padding = matches!(FORMAT, Alphabet::Standard | Alphabet::Url);
        let (content_len, _) = crate::strip_padding_info(v.as_bytes(), padding).map_err(de::Error::custom)?;
        let output_len = crate::decoded_length(content_len).map_err(de::Error::custom)?;
        let mut output = vec![0u8; output_len];
        decode_into(&mut output, v.as_bytes(), FORMAT).map_err(de::Error::custom)?;
        Ok(output)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }
}
