//! JSON-RPC 2.0 types and server.
//!
//! This crate provides pure data types for JSON-RPC 2.0 messages,
//! plus an optional [`Server`] for method registration and synchronous dispatch.

pub mod error_code;
pub mod id;
pub mod request;
pub mod response;
pub mod server;

pub use error_code::ErrorCode;
pub use id::Id;
pub use request::{Request, RequestId, RequestMessage};
pub use response::{Error, Response};
pub use server::{ResponseMessage, Server, ServerConfig};
