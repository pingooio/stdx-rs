use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
};
use serde_json::value::RawValue;

use crate::{ErrorCode, Id};

/// A JSON-RPC 2.0 error object.
///
/// `code` and `message` are required. `data` is optional and MAY contain
/// additional structured information about the error.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Error {
    /// The error code. Pre-defined codes use the range -32768 to -32000.
    pub code: i32,
    /// A short single-sentence description of the error.
    pub message: String,
    /// Optional additional error data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Box<RawValue>>,
}

impl Error {
    /// Creates a new `Error` with the given code and message.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Creates a new `Error` with additional data.
    pub fn with_data(code: i32, message: impl Into<String>, data: impl Serialize) -> serde_json::Result<Self> {
        Ok(Self {
            code,
            message: message.into(),
            data: Some(RawValue::from_string(serde_json::to_string(&data)?)?),
        })
    }

    /// Creates a parse error response.
    pub fn parse_error() -> Self {
        Self::new(ErrorCode::PARSE_ERROR, ErrorCode::default_message(ErrorCode::PARSE_ERROR))
    }

    /// Creates an invalid request error response.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::INVALID_REQUEST, message)
    }

    /// Creates a method not found error response.
    pub fn method_not_found(method: impl Into<String>) -> Self {
        Self::new(ErrorCode::METHOD_NOT_FOUND, format!("Method not found: {}", method.into()))
    }

    /// Creates an invalid params error response.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::INVALID_PARAMS, message)
    }

    /// Creates an internal error response.
    pub fn internal_error() -> Self {
        Self::new(ErrorCode::INTERNAL_ERROR, ErrorCode::default_message(ErrorCode::INTERNAL_ERROR))
    }

    /// Returns `true` if this error uses a reserved pre-defined code.
    pub fn is_reserved_code(&self) -> bool {
        ErrorCode::is_reserved(self.code)
    }
}

/// A JSON-RPC 2.0 response.
///
/// A response is either a success (containing a `result`) or a failure
/// (containing an `error`). Per the spec, `result` and `error` MUST NOT
/// both be present.
///
/// The `jsonrpc` field is always serialized as `"2.0"`.
#[derive(Clone, Debug)]
pub enum Response {
    /// A successful response with a result payload.
    Success {
        /// The result value from the method invocation.
        result: Box<RawValue>,
        /// The request identifier.
        id: Id,
    },
    /// An error response.
    Error {
        /// The error details.
        error: Error,
        /// The request identifier (null if the id could not be determined).
        id: Id,
    },
}

impl Response {
    /// Creates a success response.
    pub fn success(id: Id, result: impl Serialize) -> serde_json::Result<Self> {
        Ok(Self::Success {
            result: RawValue::from_string(serde_json::to_string(&result)?)?,
            id,
        })
    }

    /// Creates an error response.
    pub fn error(id: Id, error: Error) -> Self {
        Self::Error {
            error,
            id,
        }
    }

    /// Returns the result if this is a success response.
    pub fn result(&self) -> Option<&RawValue> {
        match self {
            Self::Success {
                result, ..
            } => Some(result),
            Self::Error {
                ..
            } => None,
        }
    }

    /// Returns the error if this is an error response.
    pub fn error_ref(&self) -> Option<&Error> {
        match self {
            Self::Error {
                error, ..
            } => Some(error),
            Self::Success {
                ..
            } => None,
        }
    }

    /// Returns the id of the response.
    pub fn id(&self) -> &Id {
        match self {
            Self::Success {
                id, ..
            }
            | Self::Error {
                id, ..
            } => id,
        }
    }

    /// Returns `true` if this is a success response.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// Returns `true` if this is an error response.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }
}

impl Serialize for Response {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Success {
                result,
                id,
            } => {
                use serde::ser::SerializeStruct;
                let mut s = serializer.serialize_struct("Response", 3)?;
                s.serialize_field("jsonrpc", "2.0")?;
                s.serialize_field("result", result)?;
                s.serialize_field("id", id)?;
                s.end()
            }
            Self::Error {
                error,
                id,
            } => {
                use serde::ser::SerializeStruct;
                let mut s = serializer.serialize_struct("Response", 3)?;
                s.serialize_field("jsonrpc", "2.0")?;
                s.serialize_field("error", error)?;
                s.serialize_field("id", id)?;
                s.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ResponseVisitor;

        impl<'de> Visitor<'de> for ResponseVisitor {
            type Value = Response;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON-RPC 2.0 response object with jsonrpc, result/error, and id")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut result: Option<Box<RawValue>> = None;
                let mut error: Option<Error> = None;
                let mut id: Option<Id> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "jsonrpc" => {
                            let _version: String = map.next_value()?;
                        }
                        "result" => {
                            if error.is_some() {
                                return Err(de::Error::custom("response contains both result and error"));
                            }
                            let raw: Box<RawValue> = map.next_value()?;
                            result = Some(raw);
                        }
                        "error" => {
                            if result.is_some() {
                                return Err(de::Error::custom("response contains both result and error"));
                            }
                            error = Some(map.next_value()?);
                        }
                        "id" => {
                            id = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let id = id.ok_or_else(|| de::Error::missing_field("id"))?;

                match (result, error) {
                    (Some(result), None) => Ok(Response::Success {
                        result,
                        id,
                    }),
                    (None, Some(error)) => Ok(Response::Error {
                        error,
                        id,
                    }),
                    (Some(_), Some(_)) => Err(de::Error::custom("response contains both result and error")),
                    (None, None) => Err(de::Error::custom("response missing both result and error")),
                }
            }
        }

        deserializer.deserialize_struct("Response", &["jsonrpc", "result", "error", "id"], ResponseVisitor)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn test_error_object_new() {
        let err = Error::new(-32000, "Something went wrong");
        assert_eq!(err.code, -32000);
        assert_eq!(err.message, "Something went wrong");
        assert!(err.data.is_none());
    }

    #[test]
    fn test_error_object_with_data() {
        let err = Error::with_data(-32000, "Server error", json!({"detail": "oops"})).unwrap();
        assert_eq!(err.code, -32000);
        assert!(err.data.is_some());
    }

    #[test]
    fn test_error_object_serialize() {
        let err = Error::new(-32601, "Method not found");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], json!(-32601));
        assert_eq!(json["message"], json!("Method not found"));
        assert!(json.get("data").is_none());
    }

    #[test]
    fn test_error_object_serialize_with_data() {
        let err = Error::with_data(-32000, "Err", json!(42)).unwrap();
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["data"], json!(42));
    }

    #[test]
    fn test_error_object_deserialize() {
        let json = json!({"code": -32601, "message": "Method not found"});
        let err: Error = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
        assert!(err.data.is_none());
    }

    #[test]
    fn test_error_object_deserialize_with_data() {
        let json = json!({"code": -32000, "message": "Err", "data": 42});
        let err: Error = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, -32000);
        assert!(err.data.is_some());
    }

    #[test]
    fn test_error_object_parse_error() {
        let err = Error::parse_error();
        assert_eq!(err.code, -32700);
    }

    #[test]
    fn test_error_object_invalid_request() {
        let err = Error::invalid_request("missing jsonrpc");
        assert_eq!(err.code, -32600);
        assert!(err.message.contains("missing jsonrpc"));
    }

    #[test]
    fn test_error_object_method_not_found() {
        let err = Error::method_not_found("foo");
        assert_eq!(err.code, -32601);
        assert!(err.message.contains("foo"));
    }

    #[test]
    fn test_error_object_invalid_params() {
        let err = Error::invalid_params("expected array");
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("expected array"));
    }

    #[test]
    fn test_error_object_internal_error() {
        let err = Error::internal_error();
        assert_eq!(err.code, -32603);
    }

    #[test]
    fn test_error_object_is_reserved_code() {
        assert!(Error::parse_error().is_reserved_code());
        assert!(!Error::new(1, "app error").is_reserved_code());
    }

    #[test]
    fn test_response_success_serialize() {
        let resp = Response::success(Id::Number(1), json!(42)).unwrap();
        assert!(resp.is_success());
        assert!(!resp.is_error());
        assert_eq!(resp.id(), &Id::Number(1));
        assert!(resp.result().is_some());
        assert!(resp.error_ref().is_none());

        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(value["jsonrpc"], json!("2.0"));
        assert_eq!(value["result"], json!(42));
        assert_eq!(value["id"], json!(1));
    }

    #[test]
    fn test_response_error_serialize() {
        let err = Error::new(-32601, "Method not found");
        let resp = Response::error(Id::Null, err);
        assert!(resp.is_error());
        assert!(!resp.is_success());
        assert_eq!(resp.id(), &Id::Null);
        assert!(resp.result().is_none());
        assert!(resp.error_ref().is_some());

        let value = serde_json::to_value(&resp).unwrap();
        assert_eq!(value["jsonrpc"], json!("2.0"));
        assert!(value.get("result").is_none());
        assert_eq!(value["error"]["code"], json!(-32601));
        assert_eq!(value["error"]["message"], json!("Method not found"));
        assert_eq!(value["id"], json!(null));
    }

    #[test]
    fn test_response_success_no_extra_fields() {
        let resp = Response::success(Id::Number(1), "hello").unwrap();
        let value: Value = serde_json::to_value(&resp).unwrap();
        assert!(value.get("error").is_none());
    }

    #[test]
    fn test_response_error_no_extra_fields() {
        let err = Error::new(-32600, "Invalid Request");
        let resp = Response::error(Id::Null, err);
        let value: Value = serde_json::to_value(&resp).unwrap();
        assert!(value.get("result").is_none());
    }

    #[test]
    fn test_response_deserialize_success() {
        let json = json!({"jsonrpc": "2.0", "result": 42, "id": 1});
        let resp: Response = serde_json::from_value(json).unwrap();
        assert!(resp.is_success());
        assert_eq!(resp.id(), &Id::Number(1));
        assert!(resp.result().is_some());
    }

    #[test]
    fn test_response_deserialize_error() {
        let json = json!({"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": "1"});
        let resp: Response = serde_json::from_value(json).unwrap();
        assert!(resp.is_error());
        assert_eq!(resp.id(), &Id::String("1".into()));
        let err = resp.error_ref().unwrap();
        assert_eq!(err.code, -32601);
    }

    #[test]
    fn test_response_deserialize_missing_both_result_and_error() {
        let json = json!({"jsonrpc": "2.0", "id": 1});
        let err = serde_json::from_value::<Response>(json).unwrap_err();
        assert!(err.to_string().contains("missing both result and error"));
    }

    #[test]
    fn test_response_deserialize_both_result_and_error() {
        let json = json!({"jsonrpc": "2.0", "result": 1, "error": {"code": 0, "message": "x"}, "id": 1});
        let err = serde_json::from_value::<Response>(json).unwrap_err();
        assert!(err.to_string().contains("both result and error"));
    }

    #[test]
    fn test_response_deserialize_missing_id() {
        let json = json!({"jsonrpc": "2.0", "result": 42});
        let err = serde_json::from_value::<Response>(json).unwrap_err();
        assert!(err.to_string().contains("id"));
    }
}
