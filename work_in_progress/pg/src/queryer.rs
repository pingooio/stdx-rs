use std::{
    pin::Pin,
    task::{Context, Poll},
};

use tokio_stream::Stream;

use crate::{connection::Connection, decode::FromSql, encode::ToSql, error::Result, row::Row};

/// Trait for anything that can execute SQL queries.
/// Implemented for Connection, Pool, Transaction.
/// All methods take &self thanks to interior mutability.
pub trait Queryer: Send + Sync {
    async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>>;

    async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64>;

    async fn query<T: FromSql>(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Vec<T>>> {
        let rows = self.query_raw(sql, params).await?;
        let mut result: Vec<Vec<T>> = Vec::new();
        for row in &rows {
            let val: T = row.try_get_by_index(0)?;
            match result.last_mut() {
                Some(last) => last.push(val),
                None => {
                    result.push(vec![val]);
                }
            }
        }
        Ok(result)
    }

    async fn query_as<T: FromRow>(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<T>> {
        let rows = self.query_raw(sql, params).await?;
        let mut result = Vec::with_capacity(rows.len());
        for row in &rows {
            result.push(T::from_row(row)?);
        }
        Ok(result)
    }

    async fn query_one_as<T: FromRow>(&self, sql: &str, params: &[&dyn ToSql]) -> Result<T> {
        let rows = self.query_raw(sql, params).await?;
        match rows.first() {
            Some(row) => T::from_row(row),
            None => Err(crate::error::PgError::RowNotFound),
        }
    }

    async fn query_first_as<T: FromRow>(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Option<T>> {
        let rows = self.query_raw(sql, params).await?;
        match rows.into_iter().next() {
            Some(row) => T::from_row(&row).map(Some),
            None => Ok(None),
        }
    }

    async fn query_first<T: FromSql>(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Option<T>> {
        let mut rows = self.query_raw(sql, params).await?;
        match rows.first_mut() {
            Some(row) => row.try_get_by_index(0).map(Some),
            None => Ok(None),
        }
    }
}

impl Queryer for Connection {
    async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        Connection::query_raw(self, sql, params).await
    }

    async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64> {
        Connection::execute_raw(self, sql, params).await
    }
}

impl<T: Queryer + Send + Sync + ?Sized> Queryer for &T {
    async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        (**self).query_raw(sql, params).await
    }

    async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64> {
        (**self).execute_raw(sql, params).await
    }
}

/// Trait for types that can be constructed from a database Row.
/// Used by query_as, query_one_as, query_first_as.
/// Typically derived with #[derive(FromRow)].
pub trait FromRow: Sized {
    fn from_row(row: &Row) -> Result<Self>;
}

pub struct RowStream {
    inner: tokio::sync::mpsc::Receiver<Result<Row>>,
}

impl Stream for RowStream {
    type Item = Result<Row>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_recv(cx)
    }
}
