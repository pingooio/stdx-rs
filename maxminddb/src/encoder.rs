use std::collections::BTreeMap;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

pub type EncodeResult<T> = Result<T, String>;

const FIRST_SIZE: usize = 29;
const SECOND_SIZE: usize = FIRST_SIZE + 256;
const THIRD_SIZE: usize = SECOND_SIZE + (1 << 16);

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Pointer(u32),
    String(String),
    Float64(f64),
    Bytes(Vec<u8>),
    Uint16(u16),
    Uint32(u32),
    Int32(i32),
    Map(BTreeMap<String, Value>),
    Uint64(u64),
    Uint128(u128),
    Slice(Vec<Value>),
    Bool(bool),
    Float32(f32),
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<u16> for Value {
    fn from(v: u16) -> Self {
        Value::Uint16(v)
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Uint32(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Int32(v)
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Uint64(v)
    }
}

impl From<u128> for Value {
    fn from(v: u128) -> Self {
        Value::Uint128(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float64(v)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Value::Float32(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}

/// Construct a `Value::Map` from key-value pairs.
///
/// Keys are converted with `.to_string()`. Values are converted via
/// `Into<Value>`, so string literals, numbers, bools, and `Value` variants
/// all work directly.
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
/// assert!(matches!(v, maxminddb::encoder::Value::Map(_)));
/// ```
#[macro_export]
macro_rules! map {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let mut __map = ::std::collections::BTreeMap::new();
        $(
            __map.insert(
                ($key).to_string(),
                ::std::convert::Into::<$crate::encoder::Value>::into($val),
            );
        )*
        $crate::encoder::Value::Map(__map)
    }};
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a MaxMind DB value")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
                if let Ok(v) = i32::try_from(v) {
                    Ok(Value::Int32(v))
                } else {
                    Ok(Value::Uint64(v as u64))
                }
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
                Ok(Value::Uint64(v))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
                Ok(Value::Float64(v))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
                Ok(Value::String(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
                Ok(Value::String(v))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Value, E> {
                Ok(Value::Bytes(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Value, E> {
                Ok(Value::Bytes(v))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(elem) = seq.next_element::<Value>()? {
                    items.push(elem);
                }
                Ok(Value::Slice(items))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut entries = BTreeMap::new();
                while let Some((key, val)) = map.next_entry::<String, Value>()? {
                    entries.insert(key, val);
                }
                Ok(Value::Map(entries))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

fn type_number(v: &Value) -> u8 {
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

fn payload_size(v: &Value) -> usize {
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

fn write_ctrl_byte(w: &mut Vec<u8>, v: &Value) -> EncodeResult<()> {
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

pub fn encode_value(v: &Value) -> EncodeResult<Vec<u8>> {
    let mut buf = Vec::new();
    encode_value_to(&mut buf, v)?;
    Ok(buf)
}

pub fn encode_value_to(w: &mut Vec<u8>, v: &Value) -> EncodeResult<()> {
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
                let key = Value::String(k.clone());
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
            // size=3: next 4 bytes are the full 32-bit pointer value
            // the last 3 bits of the control byte are ignored per spec
            w.push(0b00111000);
            w.push((p >> 24) as u8);
            w.push((p >> 16) as u8);
            w.push((p >> 8) as u8);
            w.push((p & 0xFF) as u8);
        }
    }
    Ok(())
}

pub fn encoded_size(v: &Value) -> usize {
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
                s += encoded_size(&Value::String(k.clone()));
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
