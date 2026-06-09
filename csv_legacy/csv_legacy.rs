//! A lightweight CSV parser and writer, compatible with `no_std` environments.
//!
//! # Quick start
//!
//! ```no_run
//! use csv_legacy::Reader;
//!
//! let data = b"name,age\nAlice,30\nBob,25\n";
//! let mut sum = 0u32;
//!
//! for result in Reader::new(data).rows() {
//!     let row = result?;
//!     // Access raw fields (including surrounding quotes) via indexing
//!     let name = &row[0];  // &str
//!     // Or via get_raw
//!     if let Some(name) = row.get_raw(0) {
//!         // name: &str
//!     }
//! }
//! # Ok::<_, csv_legacy::ReadError>(())
//! ```
//!
//! Rows are yielded via [`Reader::rows`], which returns an iterator over
//! [`Row`] values. Each [`Row`] owns its data and can outlive the reader.
//!
//! # Streaming from `std::io::Read`
//!
//! With the `std` feature (enabled by default), you can stream CSV data
//! from any `std::io::Read` source without loading the entire input:
//!
//! ```no_run
//! # use std::fs::File;
//! # use csv_legacy::Reader;
//! let file = File::open("data.csv")?;
//! for result in Reader::from_reader(file).rows() {
//!     let row = result?;
//!     // ...
//! }
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```
//!
//! # Unescaped fields
//!
//! Use [`Row::fields`] to iterate over unescaped fields (quotes stripped,
//! `""` resolved):
//!
//! ```no_run
//! # use csv_legacy::Reader;
//! let data = b"\"hello\",\"foo\"\"bar\"\n";
//! for result in Reader::new(data).rows() {
//!     let row = result?;
//!     let fields: Vec<String> = row.fields().map(|f| f.into_owned()).collect();
//!     // fields: ["hello", "foo\"bar"]
//! }
//! # Ok::<_, csv_legacy::ReadError>(())
//! ```
//!
//! # Writing CSV
//!
//! The [`Writer`] (requires `std`) writes CSV data to any `std::io::Write`
//! sink, automatically quoting fields that contain delimiters, quotes,
//! or newlines:
//!
//! ```no_run
//! # use csv_legacy::Writer;
//! let mut w = Writer::new(Vec::new());
//! w.write_row(["name", "age", "city"])?;
//! w.write_row(["Alice", "30", "New York, NY"])?;
//! let bytes = w.into_inner()?;
//! # Ok::<_, csv_legacy::WriteError>(())
//! ```
//!
//! # Feature flags
//!
//! | Flag    | Default | Description                              |
//! |---------|---------|------------------------------------------|
//! | `std`   | on      | Enables `From<std::io::Error>`, `Writer`, and [`Reader::from_reader`]. |
//!
//! # Errors
//!
//! Parsing errors are surfaced per row via [`ReadError`]. The error
//! includes the line number and kind (unterminated quote, trailing
//! content after a quoted field, invalid UTF-8, or I/O error).
//!
//! # `no_std` support
//!
//! Disable default features to use the crate in a `no_std` environment.
//! The crate still requires `alloc` for its internal buffers.
//!
//! [`Reader::from_reader`]: Reader::from_reader
//! [`Row::fields`]: Row::fields
//!
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod error;
mod reader;

#[cfg(feature = "std")]
mod writer;

pub use error::{ReadError, ReadErrorKind, WriteError};
pub use reader::{Fields, Reader, Row, RowIntoIter, Rows};
#[cfg(feature = "std")]
pub use writer::Writer;
