use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

use crate::{
    config::{ConnectParams, IdleConn, PoolConfig, PoolInner},
    connection::Connection,
    encode::ToSql,
    error::{PgError, Result},
    queryer::Queryer,
    row::Row,
    transaction::Transaction,
};

#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

impl Pool {
    pub async fn connect(params: ConnectParams) -> Result<Self> {
        Pool::connect_with_config(params, PoolConfig::default()).await
    }

    pub async fn connect_with_config(params: ConnectParams, config: PoolConfig) -> Result<Self> {
        let inner = PoolInner::new(params, config);
        let pool = Pool {
            inner,
        };

        for _ in 0..pool.inner.config.min_connections {
            let permit = match pool.inner.semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };
            match Connection::connect(&pool.inner.params).await {
                Ok(conn) => {
                    pool.inner.idle.lock().await.push(IdleConn {
                        conn,
                        since: Instant::now(),
                        created: Instant::now(),
                        _permit: permit,
                    });
                }
                Err(_) => {
                    permit.forget();
                    break;
                }
            }
        }

        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.reaper_loop().await;
        });

        Ok(pool)
    }

    pub async fn get(&self) -> Result<PooledConnection> {
        if self.is_closed() {
            return Err(PgError::PoolClosed);
        }

        {
            let mut idle = self.inner.idle.lock().await;
            if let Some(idle_conn) = idle.pop() {
                return Ok(PooledConnection {
                    conn: Some(idle_conn.conn),
                    pool: self.inner.clone(),
                    _permit: Some(idle_conn._permit),
                });
            }
        }

        let permit =
            tokio::time::timeout(self.inner.config.connect_timeout, self.inner.semaphore.clone().acquire_owned())
                .await
                .map_err(|_| PgError::PoolTimeout)?
                .map_err(|_| PgError::PoolClosed)?;

        match Connection::connect(&self.inner.params).await {
            Ok(conn) => Ok(PooledConnection {
                conn: Some(conn),
                pool: self.inner.clone(),
                _permit: Some(permit),
            }),
            Err(e) => {
                permit.forget();
                Err(e)
            }
        }
    }

    pub async fn begin(&self) -> Result<Transaction> {
        let mut pooled = self.get().await?;
        let conn = pooled.conn.take().expect("connection already taken");
        let permit = pooled._permit.take().expect("permit already taken");
        Transaction::begin_pooled(conn, self.inner.clone(), permit).await
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    pub async fn close(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.semaphore.close();
        self.inner.closed_notify.notify_waiters();
        let mut idle = self.inner.idle.lock().await;
        idle.clear();
    }

    async fn reaper_loop(&self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            if self.is_closed() {
                return;
            }

            let mut idle = self.inner.idle.lock().await;
            let now = Instant::now();

            let mut keep = Vec::new();
            for conn in idle.drain(..) {
                if now - conn.since < self.inner.config.idle_timeout
                    && now - conn.created < self.inner.config.max_lifetime
                {
                    keep.push(conn);
                }
            }

            while keep.len() > self.inner.config.min_connections as usize {
                keep.pop();
            }

            *idle = keep;
        }
    }
}

impl Queryer for Pool {
    async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        self.get().await?.query_raw(sql, params).await
    }

    async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64> {
        self.get().await?.execute_raw(sql, params).await
    }
}

pub struct PooledConnection {
    pub(crate) conn: Option<Connection>,
    pub(crate) pool: Arc<PoolInner>,
    pub(crate) _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl PooledConnection {
    pub async fn ping(&self) -> Result<()> {
        if let Some(ref conn) = self.conn {
            conn.ping().await
        } else {
            Err(PgError::PoolClosed)
        }
    }

    pub async fn begin(mut self) -> Result<Transaction> {
        let conn = self.conn.take().expect("connection already taken");
        let permit = self._permit.take().expect("permit already taken");
        let pool = self.pool.clone();
        Transaction::begin_pooled(conn, pool, permit).await
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("PooledConnection connection already taken")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("PooledConnection connection already taken")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let (Some(conn), Some(permit)) = (self.conn.take(), self._permit.take()) {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                pool.idle.lock().await.push(IdleConn {
                    conn,
                    since: Instant::now(),
                    created: Instant::now(),
                    _permit: permit,
                });
            });
        }
    }
}
