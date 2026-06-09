#![cfg(feature = "serde")]

use std::collections::HashMap;

use serde::de::{self, DeserializeSeed, Deserializer, SeqAccess, Visitor};

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
    /// use csv2::Reader;
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
            T::deserialize(&mut deser).map_err(|_| ReadError::new(crate::error::ReadErrorKind::TrailingContent, 0, 0))
        } else {
            let mut deser = PositionalRow {
                fields: &owned,
                index: 0,
            };
            T::deserialize(&mut deser).map_err(|_| ReadError::new(crate::error::ReadErrorKind::TrailingContent, 0, 0))
        }
    }
}

struct HeaderRow<'de> {
    fields: &'de [String],
    header_map: &'de HashMap<String, usize>,
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
        seed.deserialize(de::value::StrDeserializer::new(val)).map(Some)
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
        seed.deserialize(de::value::StrDeserializer::new(val)).map(Some)
    }
}

#[derive(Debug)]
pub struct CsvError;

impl de::Error for CsvError {
    fn custom<T: std::fmt::Display>(_msg: T) -> Self {
        CsvError
    }
}

impl std::fmt::Display for CsvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CSV deserialization error")
    }
}

impl std::error::Error for CsvError {}
