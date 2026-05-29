use alloc::{collections::BTreeMap, vec::Vec};
use std::{borrow::Cow, fmt};

use serde::{
    de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor},
    ser::{self, Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeTupleStruct},
};

pub type EncodeResult<T> = Result<T, String>;

#[derive(Debug)]
pub struct SerError(pub String);

impl fmt::Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

use std::error::Error as StdError;

impl StdError for SerError {}

impl ser::Error for SerError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        SerError(msg.to_string())
    }
}

const FIRST_SIZE: usize = 29;
const SECOND_SIZE: usize = FIRST_SIZE + 256;
const THIRD_SIZE: usize = SECOND_SIZE + (1 << 16);

#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Pointer(u32),
    String(Cow<'a, str>),
    Float64(f64),
    Bytes(Cow<'a, [u8]>),
    Uint16(u16),
    Uint32(u32),
    Int32(i32),
    Map(BTreeMap<Cow<'a, str>, Value<'a>>),
    Uint64(u64),
    Uint128(u128),
    Slice(Vec<Value<'a>>),
    Bool(bool),
    Float32(f32),
}

impl<'a> From<&'a str> for Value<'a> {
    fn from(s: &'a str) -> Self {
        Value::String(Cow::Borrowed(s))
    }
}

impl<'a> From<String> for Value<'a> {
    fn from(s: String) -> Self {
        Value::String(Cow::Owned(s))
    }
}

impl<'a> From<&'a [u8]> for Value<'a> {
    fn from(v: &'a [u8]) -> Self {
        Value::Bytes(Cow::Borrowed(v))
    }
}

impl<'a> From<Vec<u8>> for Value<'a> {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(Cow::Owned(v))
    }
}

impl<'a> From<u16> for Value<'a> {
    fn from(v: u16) -> Self {
        Value::Uint16(v)
    }
}

impl<'a> From<u32> for Value<'a> {
    fn from(v: u32) -> Self {
        Value::Uint32(v)
    }
}

impl<'a> From<i32> for Value<'a> {
    fn from(v: i32) -> Self {
        Value::Int32(v)
    }
}

impl<'a> From<u64> for Value<'a> {
    fn from(v: u64) -> Self {
        Value::Uint64(v)
    }
}

impl<'a> From<u128> for Value<'a> {
    fn from(v: u128) -> Self {
        Value::Uint128(v)
    }
}

impl<'a> From<f64> for Value<'a> {
    fn from(v: f64) -> Self {
        Value::Float64(v)
    }
}

impl<'a> From<f32> for Value<'a> {
    fn from(v: f32) -> Self {
        Value::Float32(v)
    }
}

impl<'a> From<bool> for Value<'a> {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

/// Construct a `Value::Map` from key-value pairs.
///
/// Keys are converted with `.into()` into `Cow<str>`, so string literals and
/// owned `String` values both work. Values are converted via `Into<Value>`.
///
/// # Examples
///
/// ```
/// use maxminddb::map;
///
/// let v = map! {
///     "country" => "US",
///     "code"    => 1u16,
/// };
/// assert!(matches!(v, maxminddb::Value::Map(_)));
/// ```
#[macro_export]
macro_rules! map {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let mut __map = ::std::collections::BTreeMap::new();
        $(
            __map.insert(
                ($key).into(),
                ::std::convert::Into::<$crate::encoder::Value<'_>>::into($val),
            );
        )*
        $crate::encoder::Value::Map(__map)
    }};
}

impl<'de> Deserialize<'de> for Value<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value<'de>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a MaxMind DB value")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value<'de>, E> {
                Ok(Value::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value<'de>, E> {
                if let Ok(v) = i32::try_from(v) {
                    Ok(Value::Int32(v))
                } else {
                    Ok(Value::Uint64(v as u64))
                }
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value<'de>, E> {
                Ok(Value::Uint64(v))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value<'de>, E> {
                Ok(Value::Float64(v))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Value<'de>, E> {
                Ok(Value::String(Cow::Owned(v.to_string())))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Value<'de>, E> {
                Ok(Value::String(Cow::Owned(v)))
            }

            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Value<'de>, E> {
                Ok(Value::String(Cow::Borrowed(v)))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Value<'de>, E> {
                Ok(Value::Bytes(Cow::Owned(v.to_vec())))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Value<'de>, E> {
                Ok(Value::Bytes(Cow::Owned(v)))
            }

            fn visit_borrowed_bytes<E: de::Error>(self, v: &'de [u8]) -> Result<Value<'de>, E> {
                Ok(Value::Bytes(Cow::Borrowed(v)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value<'de>, A::Error> {
                let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(1));
                while let Some(elem) = seq.next_element::<Value<'de>>()? {
                    items.push(elem);
                }
                Ok(Value::Slice(items))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value<'de>, A::Error> {
                let mut entries = BTreeMap::new();
                while let Some((key, val)) = map.next_entry::<Cow<'de, str>, Value<'de>>()? {
                    entries.insert(key, val);
                }
                Ok(Value::Map(entries))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

// ---------------------------------------------------------------------------
// Serializer — convert any `Serialize` into `Value<'static>`
// ---------------------------------------------------------------------------

pub struct ValueSerializer;

impl<'a> ser::Serializer for &'a ValueSerializer {
    type Ok = Value<'static>;
    type Error = SerError;

    type SerializeSeq = MapOrSlice<'static>;
    type SerializeTuple = MapOrSlice<'static>;
    type SerializeTupleStruct = MapOrSlice<'static>;
    type SerializeTupleVariant = ser::Impossible<Value<'static>, SerError>;
    type SerializeMap = MapOrSlice<'static>;
    type SerializeStruct = MapOrSlice<'static>;
    type SerializeStructVariant = ser::Impossible<Value<'static>, SerError>;

    fn serialize_bool(self, v: bool) -> Result<Value<'static>, SerError> {
        Ok(Value::Bool(v))
    }

    fn serialize_i8(self, v: i8) -> Result<Value<'static>, SerError> {
        Ok(Value::Int32(v as i32))
    }

    fn serialize_i16(self, v: i16) -> Result<Value<'static>, SerError> {
        Ok(Value::Int32(v as i32))
    }

    fn serialize_i32(self, v: i32) -> Result<Value<'static>, SerError> {
        Ok(Value::Int32(v))
    }

    fn serialize_i64(self, v: i64) -> Result<Value<'static>, SerError> {
        i32::try_from(v)
            .map(Value::Int32)
            .or_else(|_| Ok(Value::Uint64(v as u64)))
            .map_err(SerError)
    }

    fn serialize_u8(self, v: u8) -> Result<Value<'static>, SerError> {
        Ok(Value::Uint16(v as u16))
    }

    fn serialize_u16(self, v: u16) -> Result<Value<'static>, SerError> {
        Ok(Value::Uint16(v))
    }

    fn serialize_u32(self, v: u32) -> Result<Value<'static>, SerError> {
        Ok(Value::Uint32(v))
    }

    fn serialize_u64(self, v: u64) -> Result<Value<'static>, SerError> {
        Ok(Value::Uint64(v))
    }

    fn serialize_u128(self, v: u128) -> Result<Value<'static>, SerError> {
        Ok(Value::Uint128(v))
    }

    fn serialize_f32(self, v: f32) -> Result<Value<'static>, SerError> {
        Ok(Value::Float32(v))
    }

    fn serialize_f64(self, v: f64) -> Result<Value<'static>, SerError> {
        Ok(Value::Float64(v))
    }

    fn serialize_char(self, v: char) -> Result<Value<'static>, SerError> {
        Ok(Value::String(Cow::Owned(v.to_string())))
    }

    fn serialize_str(self, v: &str) -> Result<Value<'static>, SerError> {
        Ok(Value::String(Cow::Owned(v.to_string())))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Value<'static>, SerError> {
        Ok(Value::Bytes(Cow::Owned(v.to_vec())))
    }

    fn serialize_none(self) -> Result<Value<'static>, SerError> {
        Err(SerError("MaxMind DB has no null type".into()))
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<Value<'static>, SerError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Value<'static>, SerError> {
        Err(SerError("MaxMind DB has no null type".into()))
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Value<'static>, SerError> {
        Err(SerError("MaxMind DB has no null type".into()))
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<Value<'static>, SerError> {
        Ok(Value::String(Cow::Borrowed(variant)))
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Value<'static>, SerError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Value<'static>, SerError> {
        value.serialize(self)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<MapOrSlice<'static>, SerError> {
        Ok(MapOrSlice::slice())
    }

    fn serialize_tuple(self, len: usize) -> Result<MapOrSlice<'static>, SerError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<MapOrSlice<'static>, SerError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<MapOrSlice<'static>, SerError> {
        Ok(MapOrSlice::map())
    }

    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<MapOrSlice<'static>, SerError> {
        self.serialize_map(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, SerError> {
        Err(SerError("tuple variants not supported".into()))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, SerError> {
        Err(SerError("struct variants not supported".into()))
    }
}

pub struct MapOrSlice<'a> {
    pending_key: Option<Cow<'a, str>>,
    inner: MapOrSliceInner<'a>,
}

enum MapOrSliceInner<'a> {
    Map(BTreeMap<Cow<'a, str>, Value<'a>>),
    Slice(Vec<Value<'a>>),
}

impl<'a> MapOrSlice<'a> {
    fn map() -> Self {
        MapOrSlice {
            pending_key: None,
            inner: MapOrSliceInner::Map(BTreeMap::new()),
        }
    }
    fn slice() -> Self {
        MapOrSlice {
            pending_key: None,
            inner: MapOrSliceInner::Slice(Vec::new()),
        }
    }
}

impl SerializeSeq for MapOrSlice<'static> {
    type Ok = Value<'static>;
    type Error = SerError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        match self.inner {
            MapOrSliceInner::Slice(ref mut v) => {
                v.push(value.serialize(&ValueSerializer)?);
                Ok(())
            }
            MapOrSliceInner::Map(_) => Err(SerError("expected map entry, got element".into())),
        }
    }

    fn end(self) -> Result<Value<'static>, SerError> {
        match self.inner {
            MapOrSliceInner::Slice(v) => Ok(Value::Slice(v)),
            MapOrSliceInner::Map(m) => Ok(Value::Map(m)),
        }
    }
}

impl ser::SerializeTuple for MapOrSlice<'static> {
    type Ok = Value<'static>;
    type Error = SerError;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value<'static>, SerError> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleStruct for MapOrSlice<'static> {
    type Ok = Value<'static>;
    type Error = SerError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<Value<'static>, SerError> {
        SerializeSeq::end(self)
    }
}

impl SerializeMap for MapOrSlice<'static> {
    type Ok = Value<'static>;
    type Error = SerError;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), SerError> {
        match self.inner {
            MapOrSliceInner::Slice(_) => Err(SerError("expected element, got map key".into())),
            MapOrSliceInner::Map(_) => {
                let k = key.serialize(&ValueSerializer)?;
                match k {
                    Value::String(cow) => {
                        self.pending_key = Some(cow);
                        Ok(())
                    }
                    _ => Err(SerError("map key must be a string".into())),
                }
            }
        }
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), SerError> {
        match self.inner {
            MapOrSliceInner::Slice(_) => Err(SerError("expected element, got map value".into())),
            MapOrSliceInner::Map(ref mut m) => {
                let key = self
                    .pending_key
                    .take()
                    .ok_or_else(|| SerError("missing map key".into()))?;
                let v = value.serialize(&ValueSerializer)?;
                m.insert(key, v);
                Ok(())
            }
        }
    }

    fn end(self) -> Result<Value<'static>, SerError> {
        match self.inner {
            MapOrSliceInner::Map(m) => Ok(Value::Map(m)),
            MapOrSliceInner::Slice(_) => Err(SerError("expected map, got slice".into())),
        }
    }
}

impl SerializeStruct for MapOrSlice<'static> {
    type Ok = Value<'static>;
    type Error = SerError;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, key: &'static str, value: &T) -> Result<(), SerError> {
        match self.inner {
            MapOrSliceInner::Map(ref mut m) => {
                let v = value.serialize(&ValueSerializer)?;
                m.insert(Cow::Borrowed(key), v);
                Ok(())
            }
            MapOrSliceInner::Slice(_) => Err(SerError("expected map, got struct".into())),
        }
    }

    fn end(self) -> Result<Value<'static>, SerError> {
        match self.inner {
            MapOrSliceInner::Map(m) => Ok(Value::Map(m)),
            MapOrSliceInner::Slice(_) => Err(SerError("expected map, got slice".into())),
        }
    }
}

fn type_number(v: &Value<'_>) -> u8 {
    match v {
        Value::Pointer(_) => 1,
        Value::String(_) => 2,
        Value::Float64(_) => 3,
        Value::Bytes(_) => 4,
        Value::Uint16(_) => 5,
        Value::Uint32(_) => 6,
        Value::Int32(_) => 8,
        Value::Map(_) => 7,
        Value::Uint64(_) => 9,
        Value::Uint128(_) => 10,
        Value::Slice(_) => 11,
        Value::Bool(_) => 14,
        Value::Float32(_) => 15,
    }
}

fn payload_size(v: &Value<'_>) -> usize {
    match v {
        Value::Pointer(p) => match *p {
            p if p < 2048 => 0,
            p if p < 526336 => 1,
            p if p < 134744064 => 2,
            _ => 3,
        },
        Value::String(s) => s.len(),
        Value::Float64(_) => 8,
        Value::Bytes(b) => b.len(),
        Value::Uint16(n) => 2 - (n.leading_zeros() as usize / 8),
        Value::Uint32(n) => 4 - (n.leading_zeros() as usize / 8),
        Value::Int32(n) => {
            let u = *n as u32;
            4 - (u.leading_zeros() as usize / 8)
        }
        Value::Uint64(n) => 8 - (n.leading_zeros() as usize / 8),
        Value::Uint128(n) => 16 - (n.leading_zeros() as usize / 8),
        Value::Map(m) => m.len(),
        Value::Slice(s) => s.len(),
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        Value::Float32(_) => 4,
    }
}

fn write_size_bytes(w: &mut Vec<u8>, size: usize) -> EncodeResult<()> {
    match size {
        s if s < FIRST_SIZE => {}
        s if s < SECOND_SIZE => {
            w.push((s - FIRST_SIZE) as u8);
        }
        s if s < THIRD_SIZE => {
            let v = s - SECOND_SIZE;
            w.push((v >> 8) as u8);
            w.push((v & 0xFF) as u8);
        }
        s => {
            let v = s - THIRD_SIZE;
            w.push((v >> 16) as u8);
            w.push((v >> 8) as u8);
            w.push((v & 0xFF) as u8);
        }
    }
    Ok(())
}

fn size_extra_bytes(size: usize) -> usize {
    match size {
        s if s < FIRST_SIZE => 0,
        s if s < SECOND_SIZE => 1,
        s if s < THIRD_SIZE => 2,
        _ => 3,
    }
}

fn write_ctrl_byte(w: &mut Vec<u8>, v: &Value<'_>) -> EncodeResult<()> {
    let type_num = type_number(v);
    let size = payload_size(v);

    let first_byte: u8;
    let second_byte: u8;

    if type_num < 8 {
        first_byte = type_num << 5;
        second_byte = 0;
    } else {
        first_byte = 0;
        second_byte = type_num - 7;
    }

    let size_val = match size {
        s if s < FIRST_SIZE => s as u8,
        s if s < SECOND_SIZE => 29u8,
        s if s < THIRD_SIZE => 30u8,
        _ => 31u8,
    };
    let first_byte = first_byte | size_val;
    w.push(first_byte);

    if second_byte != 0 {
        w.push(second_byte);
    }

    write_size_bytes(w, size)
}

pub fn encode_value(v: &Value<'_>) -> EncodeResult<Vec<u8>> {
    let mut buf = Vec::new();
    encode_value_to(&mut buf, v)?;
    Ok(buf)
}

pub fn encode_value_to(w: &mut Vec<u8>, v: &Value<'_>) -> EncodeResult<()> {
    match v {
        Value::Pointer(p) => encode_pointer(w, *p)?,
        Value::String(s) => {
            write_ctrl_byte(w, v)?;
            w.extend_from_slice(s.as_bytes());
        }
        Value::Float64(f) => {
            write_ctrl_byte(w, v)?;
            w.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        Value::Bytes(b) => {
            write_ctrl_byte(w, v)?;
            w.extend_from_slice(b);
        }
        Value::Uint16(n) => {
            write_ctrl_byte(w, v)?;
            let size = payload_size(v);
            for i in (0..size).rev() {
                w.push((n >> (8 * i)) as u8);
            }
        }
        Value::Uint32(n) => {
            write_ctrl_byte(w, v)?;
            let size = payload_size(v);
            for i in (0..size).rev() {
                w.push((n >> (8 * i)) as u8);
            }
        }
        Value::Int32(n) => {
            write_ctrl_byte(w, v)?;
            let size = payload_size(v);
            for i in (0..size).rev() {
                w.push(((*n as u32) >> (8 * i)) as u8);
            }
        }
        Value::Uint64(n) => {
            write_ctrl_byte(w, v)?;
            let size = payload_size(v);
            for i in (0..size).rev() {
                w.push((n >> (8 * i)) as u8);
            }
        }
        Value::Uint128(n) => {
            write_ctrl_byte(w, v)?;
            let size = payload_size(v);
            for i in (0..size).rev() {
                w.push((n >> (8 * i)) as u8);
            }
        }
        Value::Map(m) => {
            write_ctrl_byte(w, v)?;
            for (k, val) in m.iter() {
                let key = Value::String(Cow::Borrowed(k.as_ref()));
                encode_value_to(w, &key)?;
                encode_value_to(w, val)?;
            }
        }
        Value::Slice(s) => {
            write_ctrl_byte(w, v)?;
            for val in s {
                encode_value_to(w, val)?;
            }
        }
        Value::Bool(_b) => {
            write_ctrl_byte(w, v)?;
        }
        Value::Float32(f) => {
            write_ctrl_byte(w, v)?;
            w.extend_from_slice(&f.to_bits().to_be_bytes());
        }
    }
    Ok(())
}

fn encode_pointer(w: &mut Vec<u8>, pointer: u32) -> EncodeResult<()> {
    match pointer {
        p if p < 2048 => {
            w.push(0b00100000 | ((p >> 8) as u8 & 0x07));
            w.push((p & 0xFF) as u8);
        }
        p if p < 526336 => {
            let v = p - 2048;
            w.push(0b00101000 | ((v >> 16) as u8 & 0x07));
            w.push((v >> 8) as u8);
            w.push((v & 0xFF) as u8);
        }
        p if p < 134744064 => {
            let v = p - 526336;
            w.push(0b00110000 | ((v >> 24) as u8 & 0x07));
            w.push((v >> 16) as u8);
            w.push((v >> 8) as u8);
            w.push((v & 0xFF) as u8);
        }
        p => {
            w.push(0b00111000);
            w.push((p >> 24) as u8);
            w.push((p >> 16) as u8);
            w.push((p >> 8) as u8);
            w.push((p & 0xFF) as u8);
        }
    }
    Ok(())
}

pub fn encoded_size(v: &Value<'_>) -> usize {
    let type_num = type_number(v);
    let size = payload_size(v);

    let mut total = 1;
    if type_num >= 8 {
        total += 1;
    }
    total += size_extra_bytes(size);

    match v {
        Value::Pointer(p) => {
            total += match *p {
                p if p < 2048 => 1,
                p if p < 526336 => 2,
                p if p < 134744064 => 3,
                _ => 4,
            };
            total
        }
        Value::String(s) => total + s.len(),
        Value::Float64(_) => total + 8,
        Value::Bytes(b) => total + b.len(),
        Value::Uint16(_) => total + size,
        Value::Uint32(_) => total + size,
        Value::Int32(_) => total + size,
        Value::Uint64(_) => total + size,
        Value::Uint128(_) => total + size,
        Value::Map(m) => {
            let mut s = total;
            for (k, val) in m.iter() {
                s += encoded_size(&Value::String(Cow::Borrowed(k.as_ref())));
                s += encoded_size(val);
            }
            s
        }
        Value::Slice(sl) => {
            let mut s = total;
            for val in sl {
                s += encoded_size(val);
            }
            s
        }
        Value::Bool(_) => total,
        Value::Float32(_) => total + 4,
    }
}
