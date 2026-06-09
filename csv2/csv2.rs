#![cfg_attr(not(feature = "std"), no_std)]
//! A fast, low-allocation CSV parser with optional serde support.
//!
//! # Quick start
//!
//! ```rust
//! let data = b"name,age,city\nAlice,30,NYC\nBob,25,LA\n";
//! let mut reader = csv2::Reader::from_reader(std::io::Cursor::new(data));
//!
//! for row in reader.rows() {
//!     for field in row.fields().unwrap() {
//!         // field: &str — already unescaped, no surrounding quotes, `""` resolved
//!     }
//!     let fields: Vec<String> = row.all().unwrap();
//! }
//! ```
//!
//! # Features
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `std` | on | Enables `std::io::Read`, `Writer`, and `std::error::Error` impls. |
//! | `serde` | off | Enables `Row::deserialize()` for `#[derive(Deserialize)]`. |
//!
//! # Streaming from `std::io::Read`
//!
//! ```no_run
//! use std::fs::File;
//! use csv2::Reader;
//!
//! let file = File::open("data.csv")?;
//! let mut reader = Reader::from_reader(file);
//!
//! for row in reader.rows() {
//!     let name = row.fields()?.next().unwrap();
//!     println!("{name}");
//! }
//! # Ok::<_, csv2::ReadError>(())
//! ```
//!
//! # Headers
//!
//! ```no_run
//! use csv2::Reader;
//! let data = b"name,age\nAlice,30\n";
//! let mut reader = Reader::from_reader(std::io::Cursor::new(data));
//! let headers = reader.parse_headers()?;
//! for row in reader.rows() {
//! }
//! # Ok::<_, csv2::ReadError>(())
//! ```
//!
//! # Serde (requires `serde` feature)
//!
//! ```no_run
//! # #[cfg(feature = "serde")] {
//! use csv2::Reader;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct Record { name: String, age: u32 }
//!
//! let mut reader = Reader::from_reader(std::io::Cursor::new(b"name,age\nAlice,30\n"));
//! reader.parse_headers()?;
//!
//! for row in reader.rows() {
//!     let rec: Record = row.deserialize()?;
//!     println!("{} is {}", rec.name, rec.age);
//! }
//! # }
//! # Ok::<_, csv2::ReadError>(())
//! ```
//!
//! When [`parse_headers`] is called before iterating, struct fields are
//! matched to CSV columns by name. Without it, fields are mapped positionally.
//!
//! # Writer
//!
//! ```no_run
//! use csv2::Writer;
//!
//! let mut w = Writer::new(Vec::new());
//! w.write_row(["name", "age"])?;
//! w.write_row(["Alice", "30"])?;
//! let bytes = w.into_inner()?;
//! # Ok::<_, csv2::WriteError>(())
//! ```
//!
//! # Design
//!
//! * **Zero per-row allocations**: `rows()` reuses internal buffers.
//! * **Eager unescaping**: quotes are stripped and `""` resolved during parsing.
//! * **SIMD scanning**: uses `memchr3` to bulk-scan for delimiters, quotes, and newlines.
//! * **Borrowed rows**: `Row<'_>` borrows from the `Reader` and cannot outlive it.
//! * **Streaming**: rows are parsed on-demand from `std::io::Read`.

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod error;
mod reader;

#[cfg(feature = "std")]
mod writer;

#[cfg(feature = "serde")]
mod serde;

pub use error::{ReadError, ReadErrorKind, WriteError};
pub use reader::{Fields, Reader, Row, Rows};
#[cfg(feature = "std")]
pub use writer::Writer;
