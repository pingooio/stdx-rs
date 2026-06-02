/// Standard JSON-RPC 2.0 error codes.
///
/// The range from -32768 to -32000 is reserved for pre-defined errors.
/// The range from -32000 to -32099 is reserved for server errors.
/// All other codes are available for application-defined errors.
pub struct ErrorCode;

impl ErrorCode {
    /// Invalid JSON was received by the server.
    /// An error occurred on the server while parsing the JSON text.
    pub const PARSE_ERROR: i32 = -32700;

    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;

    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;

    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i32 = -32602;

    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;

    /// The lowest reserved server error code.
    pub const SERVER_ERROR_MIN: i32 = -32099;

    /// The highest reserved server error code.
    pub const SERVER_ERROR_MAX: i32 = -32000;

    /// Returns `true` if the given code is in the reserved pre-defined error range.
    pub fn is_reserved(code: i32) -> bool {
        (-32768..=-32000).contains(&code)
    }

    /// Returns `true` if the given code is in the server error range.
    pub fn is_server_error(code: i32) -> bool {
        (-32099..=-32000).contains(&code)
    }

    /// Returns a human-readable default message for a given standard error code.
    pub fn default_message(code: i32) -> &'static str {
        match code {
            Self::PARSE_ERROR => "Parse error",
            Self::INVALID_REQUEST => "Invalid Request",
            Self::METHOD_NOT_FOUND => "Method not found",
            Self::INVALID_PARAMS => "Invalid params",
            Self::INTERNAL_ERROR => "Internal error",
            _ => "Server error",
        }
    }
}
