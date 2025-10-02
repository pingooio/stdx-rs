//! `x-www-form-urlencoded` meets Serde

#![warn(unused_extern_crates)]
#![forbid(unsafe_code)]

pub mod de;
pub mod ser;

#[doc(inline)]
pub use crate::de::{Deserializer, from_bytes, from_reader, from_str};
#[doc(inline)]
pub use crate::ser::{Serializer, to_string};
