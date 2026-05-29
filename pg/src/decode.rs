use crate::error::{PgError, Result};

pub trait FromSql: Sized {
    fn from_sql(type_oid: u32, buf: &[u8]) -> Result<Self>;
}

impl FromSql for i16 {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 2 {
            return Err(PgError::Decode("i16: buffer too short".into()));
        }
        Ok(i16::from_be_bytes([buf[0], buf[1]]))
    }
}

impl FromSql for i32 {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(PgError::Decode("i32: buffer too short".into()));
        }
        Ok(i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }
}

impl FromSql for i64 {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(PgError::Decode("i64: buffer too short".into()));
        }
        let arr: [u8; 8] = buf[..8].try_into().unwrap();
        Ok(i64::from_be_bytes(arr))
    }
}

impl FromSql for f32 {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(PgError::Decode("f32: buffer too short".into()));
        }
        let arr: [u8; 4] = buf[..4].try_into().unwrap();
        Ok(f32::from_be_bytes(arr))
    }
}

impl FromSql for f64 {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(PgError::Decode("f64: buffer too short".into()));
        }
        let arr: [u8; 8] = buf[..8].try_into().unwrap();
        Ok(f64::from_be_bytes(arr))
    }
}

impl FromSql for bool {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(PgError::Decode("bool: empty buffer".into()));
        }
        Ok(buf[0] != 0)
    }
}

impl FromSql for String {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        String::from_utf8(buf.to_vec()).map_err(|e| PgError::Decode(format!("string: invalid utf-8: {}", e)))
    }
}

impl FromSql for Vec<u8> {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        Ok(buf.to_vec())
    }
}

impl FromSql for uuid::Uuid {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        uuid::Uuid::from_slice(buf).map_err(|e| PgError::Decode(format!("uuid: {}", e)))
    }
}

impl FromSql for chrono::DateTime<chrono::Utc> {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(PgError::Decode("timestamptz: buffer too short".into()));
        }
        let arr: [u8; 8] = buf[..8].try_into().unwrap();
        let micros = i64::from_be_bytes(arr);
        let pg_epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|d| d.and_utc())
            .unwrap();
        let duration = chrono::TimeDelta::microseconds(micros);
        Ok(pg_epoch + duration)
    }
}

impl<T: FromSql> FromSql for Option<T> {
    fn from_sql(type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Ok(None);
        }
        T::from_sql(type_oid, buf).map(Some)
    }
}

impl<T: FromSql> FromSql for Vec<T> {
    fn from_sql(_type_oid: u32, buf: &[u8]) -> Result<Self> {
        if buf.len() < 12 {
            return Err(PgError::Decode("array: buffer too short".into()));
        }
        let _num_dims = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let _has_nulls = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let _elem_oid = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let dim_count = i32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let _dim_lbound = i32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);

        let mut offset = 20usize;
        let mut result = Vec::with_capacity(dim_count as usize);

        for _ in 0..dim_count {
            if offset + 4 > buf.len() {
                return Err(PgError::Decode("array: invalid element offset".into()));
            }
            let elem_len = i32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
            offset += 4;
            if elem_len == -1 {
                continue;
            }
            if offset + elem_len as usize > buf.len() {
                return Err(PgError::Decode("array: element length exceeds buffer".into()));
            }
            let elem = T::from_sql(_elem_oid, &buf[offset..offset + elem_len as usize])?;
            result.push(elem);
            offset += elem_len as usize;
        }

        Ok(result)
    }
}
