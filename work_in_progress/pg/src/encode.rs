use crate::{
    error::{PgError, Result},
    types::PgType,
};

pub trait ToSql: Send + Sync {
    fn to_sql(&self) -> Result<Vec<u8>>;
    fn pg_type(&self) -> &'static PgType;
}

impl ToSql for i16 {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::INT2
    }
}

impl ToSql for i32 {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::INT4
    }
}

impl ToSql for i64 {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::INT8
    }
}

impl ToSql for f32 {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::FLOAT4
    }
}

impl ToSql for f64 {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::FLOAT8
    }
}

impl ToSql for bool {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(vec![if *self { 1 } else { 0 }])
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::BOOL
    }
}

impl ToSql for String {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::TEXT
    }
}

impl ToSql for &str {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::TEXT
    }
}

impl ToSql for uuid::Uuid {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::UUID
    }
}

impl ToSql for chrono::DateTime<chrono::Utc> {
    fn to_sql(&self) -> Result<Vec<u8>> {
        let pg_epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|d| d.and_utc())
            .unwrap();
        let diff = *self - pg_epoch;
        let micros = diff.num_microseconds().ok_or_else(|| {
            PgError::Encode("timestamptz value out of range for PostgreSQL microsecond encoding".into())
        })?;
        Ok(micros.to_be_bytes().to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::TIMESTAMPTZ
    }
}

impl<T: ToSql> ToSql for Option<T> {
    fn to_sql(&self) -> Result<Vec<u8>> {
        match self {
            Some(val) => val.to_sql(),
            None => Ok(Vec::new()),
        }
    }
    fn pg_type(&self) -> &'static PgType {
        self.as_ref()
            .and_then(|v| Some(v.pg_type()))
            .unwrap_or(&crate::types::TEXT)
    }
}

impl<T: ToSql> ToSql for Vec<T> {
    fn to_sql(&self) -> Result<Vec<u8>> {
        let elem_type = self.first().map(|e| e.pg_type()).unwrap_or(&crate::types::INT4);
        let elem_oid = elem_type.oid;
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&elem_oid.to_be_bytes());
        buf.extend_from_slice(&(self.len() as i32).to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        for elem in self {
            let data = elem.to_sql()?;
            buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
            buf.extend_from_slice(&data);
        }
        Ok(buf)
    }
    fn pg_type(&self) -> &'static PgType {
        self.first()
            .map(|e| crate::types::element_to_array(e.pg_type()))
            .unwrap_or(&crate::types::INT4_ARRAY)
    }
}

impl ToSql for Vec<u8> {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.clone())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::BYTEA
    }
}

impl ToSql for &[u8] {
    fn to_sql(&self) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }
    fn pg_type(&self) -> &'static PgType {
        &crate::types::BYTEA
    }
}

impl<T: ToSql> ToSql for &[T] {
    fn to_sql(&self) -> Result<Vec<u8>> {
        let elem_type = self.first().map(|e| e.pg_type()).unwrap_or(&crate::types::INT4);
        let elem_oid = elem_type.oid;
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&elem_oid.to_be_bytes());
        buf.extend_from_slice(&(self.len() as i32).to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());
        for elem in *self {
            let data = elem.to_sql()?;
            buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
            buf.extend_from_slice(&data);
        }
        Ok(buf)
    }
    fn pg_type(&self) -> &'static PgType {
        self.first()
            .map(|e| crate::types::element_to_array(e.pg_type()))
            .unwrap_or(&crate::types::INT4_ARRAY)
    }
}

/// Wraps an iterator to produce a PG array without allocating an intermediate `Vec`.
/// Uses `size_hint` from the iterator for pre-allocation when available.
///
/// # Example
/// ```ignore
/// use pg::{BindIter, ToSql, types::UUID};
/// let ids: Vec<uuid::Uuid> = vec![/* ... */];
/// let param = BindIter::new(ids.iter().copied(), &UUID);
/// conn.execute_raw("SELECT * FROM unnest($1::uuid[])", &[&param]).await?;
/// ```
pub struct BindIter<I> {
    inner: std::sync::Mutex<Option<I>>,
    elem_type: &'static PgType,
}

impl<I> BindIter<I> {
    pub fn new(iter: I, elem_type: &'static PgType) -> Self {
        BindIter {
            inner: std::sync::Mutex::new(Some(iter)),
            elem_type,
        }
    }
}

impl<I, T> ToSql for BindIter<I>
where
    I: Iterator<Item = T> + Send,
    T: ToSql,
{
    fn to_sql(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&self.elem_type.oid.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes());

        let per_elem_guess = match self.elem_type.oid {
            crate::types::INT2OID => 4 + 2,
            crate::types::INT4OID | crate::types::FLOAT4OID => 4 + 4,
            crate::types::INT8OID | crate::types::FLOAT8OID | crate::types::TIMESTAMPTZOID => 4 + 8,
            crate::types::UUIDOID => 4 + 16,
            crate::types::BOOLOID => 4 + 1,
            _ => 4 + 64,
        };
        if let Some(ref iter) = *self.inner.lock().unwrap() {
            let (lower, _) = iter.size_hint();
            if lower > 0 {
                buf.reserve(20 + lower * per_elem_guess);
            }
        }

        let mut count = 0i32;
        let mut iter_guard = self.inner.lock().unwrap();
        if let Some(ref mut iter) = *iter_guard {
            while let Some(item) = iter.next() {
                let data = item.to_sql()?;
                buf.extend_from_slice(&(data.len() as i32).to_be_bytes());
                buf.extend_from_slice(&data);
                count += 1;
            }
        }

        buf[12..16].copy_from_slice(&count.to_be_bytes());
        Ok(buf)
    }

    fn pg_type(&self) -> &'static PgType {
        crate::types::element_to_array(self.elem_type)
    }
}
