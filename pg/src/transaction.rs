use std::sync::Arc;

use crate::{config::PoolInner, connection::Connection, encode::ToSql, error::Result, queryer::Queryer, row::Row};

pub struct Transaction {
    conn: Option<Connection>,
    done: bool,
    /// If set, return the connection to this pool on completion.
    pool: Option<PoolBacking>,
}

struct PoolBacking {
    inner: Arc<PoolInner>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Transaction {
    pub async fn begin(conn: Connection) -> Result<Self> {
        conn.execute_raw("BEGIN", &[]).await?;
        Ok(Transaction {
            conn: Some(conn),
            done: false,
            pool: None,
        })
    }

    pub(crate) async fn begin_pooled(
        conn: Connection,
        pool: Arc<PoolInner>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Self> {
        conn.execute_raw("BEGIN", &[]).await?;
        Ok(Transaction {
            conn: Some(conn),
            done: false,
            pool: Some(PoolBacking {
                inner: pool,
                _permit: permit,
            }),
        })
    }

    pub async fn commit(mut self) -> Result<()> {
        let conn = self.conn.as_ref().expect("Transaction already completed");
        conn.execute_raw("COMMIT", &[]).await?;
        self.done = true;
        Ok(())
    }

    pub async fn rollback(mut self) -> Result<()> {
        let conn = self.conn.as_ref().expect("Transaction already completed");
        conn.execute_raw("ROLLBACK", &[]).await?;
        self.done = true;
        Ok(())
    }

    pub async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        self.conn().query_raw(sql, params).await
    }

    pub async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64> {
        self.conn().execute_raw(sql, params).await
    }

    fn conn(&self) -> &Connection {
        self.conn.as_ref().expect("Transaction already completed")
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.done {
            if let Some(conn) = self.conn.take() {
                tokio::spawn(async move {
                    let _ = conn.execute_raw("ROLLBACK", &[]).await;
                });
            }
            return;
        }

        // Return connection to pool if applicable
        if let (Some(conn), Some(pool)) = (self.conn.take(), self.pool.take()) {
            pool.inner.idle_conns.blocking_lock().push(conn);
            pool.inner.idle.blocking_lock().push(std::time::Instant::now());
        }
    }
}

impl Queryer for Transaction {
    async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        self.conn().query_raw(sql, params).await
    }

    async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64> {
        self.conn().execute_raw(sql, params).await
    }
}
