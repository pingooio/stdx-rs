use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

/// A JSON-RPC request or response identifier.
///
/// Per the spec, an `Id` MUST be a `String`, `Number`, or `Null`.
/// Fractional numbers SHOULD NOT be used.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Id {
    /// An integer identifier.
    Number(i64),
    /// A string identifier.
    String(String),
    /// A null identifier (discouraged per spec).
    Null,
}

impl Id {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Null => write!(f, "null"),
        }
    }
}

impl From<i64> for Id {
    fn from(n: i64) -> Self {
        Self::Number(n)
    }
}

impl From<i32> for Id {
    fn from(n: i32) -> Self {
        Self::Number(n as i64)
    }
}

impl From<u64> for Id {
    fn from(n: u64) -> Self {
        Self::Number(n as i64)
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Number(n) => serializer.serialize_i64(*n),
            Self::String(s) => serializer.serialize_str(s),
            Self::Null => serializer.serialize_unit(),
        }
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdVisitor;

        impl<'de> Visitor<'de> for IdVisitor {
            type Value = Id;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON-RPC id: a string, an integer, or null")
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(Id::Number(v))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(Id::Number(v as i64))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                if v.fract() == 0.0 {
                    Ok(Id::Number(v as i64))
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Float(v), &self))
                }
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(Id::String(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(Id::String(v))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Id::Null)
            }
        }

        deserializer.deserialize_any(IdVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_serde_number() {
        let json = "42";
        let id: Id = serde_json::from_str(json).unwrap();
        assert_eq!(id, Id::Number(42));
        assert_eq!(serde_json::to_string(&id).unwrap(), json);
    }

    #[test]
    fn test_id_serde_string() {
        let json = r#""abc""#;
        let id: Id = serde_json::from_str(json).unwrap();
        assert_eq!(id, Id::String("abc".into()));
        assert_eq!(serde_json::to_string(&id).unwrap(), json);
    }

    #[test]
    fn test_id_serde_null() {
        let json = "null";
        let id: Id = serde_json::from_str(json).unwrap();
        assert_eq!(id, Id::Null);
        assert_eq!(serde_json::to_string(&id).unwrap(), json);
    }

    #[test]
    fn test_id_deserialize_float_rejected() {
        let err = serde_json::from_str::<Id>("1.5").unwrap_err();
        assert!(err.to_string().contains("floating point"));
    }

    #[test]
    fn test_id_deserialize_whole_float_accepted() {
        let id: Id = serde_json::from_str("1.0").unwrap();
        assert_eq!(id, Id::Number(1));
    }

    #[test]
    fn test_id_from_i64() {
        let id: Id = 42i64.into();
        assert_eq!(id, Id::Number(42));
    }

    #[test]
    fn test_id_from_str() {
        let id: Id = "foo".into();
        assert_eq!(id, Id::String("foo".into()));
    }

    #[test]
    fn test_id_display_number() {
        assert_eq!(Id::Number(42).to_string(), "42");
    }

    #[test]
    fn test_id_display_string() {
        assert_eq!(Id::String("abc".into()).to_string(), "abc");
    }

    #[test]
    fn test_id_display_null() {
        assert_eq!(Id::Null.to_string(), "null");
    }

    #[test]
    fn test_id_as_i64_some() {
        assert_eq!(Id::Number(10).as_i64(), Some(10));
    }

    #[test]
    fn test_id_as_i64_none() {
        assert_eq!(Id::String("x".into()).as_i64(), None);
        assert_eq!(Id::Null.as_i64(), None);
    }

    #[test]
    fn test_id_as_str_some() {
        assert_eq!(Id::String("x".into()).as_str(), Some("x"));
    }

    #[test]
    fn test_id_as_str_none() {
        assert_eq!(Id::Number(1).as_str(), None);
        assert_eq!(Id::Null.as_str(), None);
    }
}
