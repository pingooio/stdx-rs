#![cfg(feature = "serde")]

extern crate alloc;

use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, Error as _, SeqAccess, Visitor};

use crate::{error::ReadError, reader::Row};

impl Row<'_> {
    /// Deserialize this row into a `T`.
    ///
    /// If [`parse_headers`](crate::Reader::parse_headers) was called
    /// before iterating, struct fields are matched by column name.
    /// Otherwise, fields are mapped positionally.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use csv::Reader;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Record { name: String, age: u32 }
    ///
    /// let mut reader = Reader::from_reader(std::io::Cursor::new(b"name,age\nAlice,30\n"));
    /// reader.parse_headers()?;
    /// for row in reader.rows() {
    ///     let rec: Record = row.deserialize()?;
    ///     println!("{} is {}", rec.name, rec.age);
    /// }
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn deserialize<T>(&self) -> Result<T, ReadError>
    where
        T: serde::de::DeserializeOwned,
    {
        let owned: Vec<String> = self.fields()?.map(|s| s.to_string()).collect();

        if let Some(header_map) = self.header_map {
            let mut deser = HeaderRow {
                fields: &owned,
                header_map,
                struct_fields: &[],
                index: 0,
            };
            T::deserialize(&mut deser)
                .map_err(|e| ReadError::new(crate::error::ReadErrorKind::Deserialize(e.msg), 0, 0))
        } else {
            let mut deser = PositionalRow {
                fields: &owned,
                index: 0,
            };
            T::deserialize(&mut deser)
                .map_err(|e| ReadError::new(crate::error::ReadErrorKind::Deserialize(e.msg), 0, 0))
        }
    }
}

struct HeaderRow<'de> {
    fields: &'de [String],
    header_map: &'de BTreeMap<String, usize>,
    struct_fields: &'static [&'static str],
    index: usize,
}

impl<'de> Deserializer<'de> for &mut HeaderRow<'de> {
    type Error = CsvError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_struct("", &[], visitor)
    }

    fn deserialize_struct<V>(
        mut self,
        _name: &'static str,
        struct_fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.struct_fields = struct_fields;
        self.index = 0;
        visitor.visit_seq(&mut self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

impl<'de> SeqAccess<'de> for HeaderRow<'de> {
    type Error = CsvError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        if self.index >= self.struct_fields.len() {
            return Ok(None);
        }
        let field_name = self.struct_fields[self.index];
        self.index += 1;
        let val = self
            .header_map
            .get(field_name)
            .and_then(|&idx| self.fields.get(idx).map(|s| s.as_str()))
            .unwrap_or("");
        seed.deserialize(FieldDeserializer(val)).map(Some)
    }
}

struct PositionalRow<'de> {
    fields: &'de [String],
    index: usize,
}

impl<'de> Deserializer<'de> for &mut PositionalRow<'de> {
    type Error = CsvError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_struct("", &[], visitor)
    }

    fn deserialize_struct<V>(
        mut self,
        _name: &'static str,
        _struct_fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.index = 0;
        visitor.visit_seq(&mut self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

impl<'de> SeqAccess<'de> for PositionalRow<'de> {
    type Error = CsvError;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        if self.index >= self.fields.len() {
            return Ok(None);
        }
        let val = self.fields[self.index].as_str();
        self.index += 1;
        seed.deserialize(FieldDeserializer(val)).map(Some)
    }
}

/// Deserializes a single CSV field value with proper type coercion.
///
/// Strings are parsed into the requested type so that fields like
/// `"30"` can be deserialized into `u32`.
struct FieldDeserializer<'a>(&'a str);

macro_rules! forward_parse {
    ($($method:ident => $visit:ident :: $ty:ty),*) => {
        $(
            fn $method<V>(self, visitor: V) -> Result<V::Value, Self::Error>
            where V: Visitor<'de>,
            {
                let v: $ty = self.0.parse().map_err(|_| {
                    CsvError::custom(concat!("invalid ", stringify!($ty)))
                })?;
                visitor.$visit(v)
            }
        )*
    };
}

impl<'de, 'a: 'de> Deserializer<'de> for FieldDeserializer<'a> {
    type Error = CsvError;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.0)
    }

    forward_parse! {
        deserialize_bool   => visit_bool   :: bool,
        deserialize_i8     => visit_i8     :: i8,
        deserialize_i16    => visit_i16    :: i16,
        deserialize_i32    => visit_i32    :: i32,
        deserialize_i64    => visit_i64    :: i64,
        deserialize_u8     => visit_u8     :: u8,
        deserialize_u16    => visit_u16    :: u16,
        deserialize_u32    => visit_u32    :: u32,
        deserialize_u64    => visit_u64    :: u64,
        deserialize_f32    => visit_f32    :: f32,
        deserialize_f64    => visit_f64    :: f64
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let ch = self.0.chars().next().ok_or_else(|| CsvError::custom("empty char"))?;
        visitor.visit_char(ch)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.0)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_string(self.0.to_owned())
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_bytes(self.0.as_bytes())
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_byte_buf(self.0.as_bytes().to_vec())
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        if self.0.is_empty() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(CsvError::custom("cannot deserialize sequence from a single field"))
    }

    fn deserialize_tuple<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(CsvError::custom("cannot deserialize tuple from a single field"))
    }

    fn deserialize_tuple_struct<V>(self, _name: &'static str, _len: usize, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(CsvError::custom("cannot deserialize tuple struct from a single field"))
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(CsvError::custom("cannot deserialize map from a single field"))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(CsvError::custom("cannot deserialize struct from a single field"))
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(CsvError::custom("cannot deserialize enum from a single field"))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_borrowed_str(self.0)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

#[derive(Debug)]
pub struct CsvError {
    pub(crate) msg: String,
}

impl de::Error for CsvError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        CsvError {
            msg: msg.to_string(),
        }
    }
}

impl fmt::Display for CsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CsvError {}

#[cfg(all(not(feature = "std"), feature = "serde"))]
impl core::error::Error for CsvError {}
