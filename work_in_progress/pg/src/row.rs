use std::collections::HashMap;

use crate::{
    decode::FromSql,
    error::{PgError, Result},
    protocol::FieldDescription,
};

#[derive(Debug, Clone)]
pub struct Row {
    columns: Vec<FieldDescription>,
    values: Vec<Option<Vec<u8>>>,
    name_to_index: HashMap<String, usize>,
}

impl Row {
    pub fn new(fields: &[FieldDescription], values: &[Option<Vec<u8>>]) -> Self {
        let name_to_index = fields.iter().enumerate().map(|(i, f)| (f.name.clone(), i)).collect();

        Row {
            columns: fields.to_vec(),
            values: values.to_vec(),
            name_to_index,
        }
    }

    pub fn len(&self) -> usize {
        self.columns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    pub fn columns(&self) -> &[FieldDescription] {
        &self.columns
    }

    pub fn try_get<T: FromSql>(&self, name: &str) -> Result<T> {
        let idx = self
            .name_to_index
            .get(name)
            .ok_or_else(|| PgError::ColumnNotFound(name.to_string()))?;

        let field = &self.columns[*idx];
        let type_oid = field.type_oid;

        match &self.values[*idx] {
            None => T::from_sql(type_oid, &[]),
            Some(data) => T::from_sql(type_oid, data),
        }
    }

    pub fn try_get_by_index<T: FromSql>(&self, idx: usize) -> Result<T> {
        if idx >= self.columns.len() {
            return Err(PgError::ColumnNotFound(format!("column index {}", idx)));
        }

        let field = &self.columns[idx];
        let type_oid = field.type_oid;

        match &self.values[idx] {
            None => T::from_sql(type_oid, &[]),
            Some(data) => T::from_sql(type_oid, data),
        }
    }
}
