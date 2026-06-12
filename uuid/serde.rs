//! Serialization and deserialization with [`serde`].
//!
//! Enabled via the `serde` feature flag.
//!
//! [`Uuid`]s are serialized as their canonical 8-4-4-4-12 lowercase hex string
//! (e.g. `"f47ac10b-58cc-4372-a567-0e02b2c3d479"`).
//!
//! Deserialization accepts both the canonical string form (JSON, YAML, TOML)
//! and a raw 16-byte buffer (bincode, messagepack).

use core::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

use crate::Uuid;

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct UuidVisitor;

impl<'de> Visitor<'de> for UuidVisitor {
    type Value = Uuid;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a UUID as a 36-character hex string or 16-byte buffer")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Uuid, E> {
        Uuid::parse(v).map_err(de::Error::custom)
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Uuid, E> {
        // serde_json forwards string content here as 36 raw bytes;
        // binary formats (bincode, msgpack) pass the raw 16-byte buffer.
        match v.len() {
            16 => Uuid::from_slice(v).map_err(de::Error::custom),
            36 => Uuid::parse(v).map_err(de::Error::custom),
            _ => Err(de::Error::custom("expected 16 bytes (binary) or 36 bytes (hex string)")),
        }
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        deserializer.deserialize_bytes(UuidVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde_json;

    use super::*;

    const S: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[test]
    fn round_trip() {
        let uuid = Uuid::parse(S).unwrap();
        let json = serde_json::to_string(&uuid).unwrap();
        assert_eq!(json, format!("\"{S}\""));
        let got: Uuid = serde_json::from_str(&json).unwrap();
        assert_eq!(got, uuid);
    }

    #[test]
    fn deserialize_from_str() {
        let json = format!("\"{S}\"");
        let uuid: Uuid = serde_json::from_str(&json).unwrap();
        assert_eq!(uuid.to_string(), S);
    }

    #[test]
    fn deserialize_array_rejected() {
        let json = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let result: Result<Uuid, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn nil_round_trip() {
        let uuid = Uuid::nil();
        let json = serde_json::to_string(&uuid).unwrap();
        assert_eq!(json, "\"00000000-0000-0000-0000-000000000000\"");
        let got: Uuid = serde_json::from_str(&json).unwrap();
        assert_eq!(got, uuid);
    }
}
