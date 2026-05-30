use std::{sync::Arc, time::Instant};

use crate::{
    config::{IdleConn, PoolInner},
    connection::Connection,
    encode::ToSql,
    error::Result,
    queryer::Queryer,
    row::Row,
};

pub struct Transaction {
    conn: Option<Connection>,
    done: bool,
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
        match conn.execute_raw("BEGIN", &[]).await {
            Ok(_) => Ok(Transaction {
                conn: Some(conn),
                done: false,
                pool: Some(PoolBacking {
                    inner: pool,
                    _permit: permit,
                }),
            }),
            Err(e) => {
                pool.idle.lock().await.push(IdleConn {
                    conn,
                    since: Instant::now(),
                    created: Instant::now(),
                    _permit: permit,
                });
                Err(e)
            }
        }
    }

    pub async fn commit(mut self) -> Result<()> {
        let conn = self.conn.as_ref().expect("Transaction already completed");
        let result = conn.execute_raw("COMMIT", &[]).await.map(|_| ());
        self.done = true;
        result
    }

    pub async fn rollback(mut self) -> Result<()> {
        let conn = self.conn.as_ref().expect("Transaction already completed");
        let result = conn.execute_raw("ROLLBACK", &[]).await.map(|_| ());
        self.done = true;
        result
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
        let done = self.done;

        if let (Some(conn), Some(pool)) = (self.conn.take(), self.pool.take()) {
            tokio::spawn(async move {
                if !done {
                    let _ = conn.execute_raw("ROLLBACK", &[]).await;
                }
                pool.inner.idle.lock().await.push(IdleConn {
                    conn,
                    since: Instant::now(),
                    created: Instant::now(),
                    _permit: pool._permit,
                });
            });
        } else if let Some(conn) = self.conn.take() {
            if !done {
                tokio::spawn(async move {
                    let _ = conn.execute_raw("ROLLBACK", &[]).await;
                });
            }
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
