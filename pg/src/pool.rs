use std::{sync::Arc, time::Instant};

use tokio::sync::Semaphore;

use crate::{
    config::{ConnectParams, PoolConfig, PoolInner},
    connection::Connection,
    error::{PgError, Result},
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

        if pool.inner.config.min_connections > 0 {
            for _ in 0..pool.inner.config.min_connections {
                match Connection::connect(&pool.inner.params).await {
                    Ok(conn) => {
                        pool.inner.idle_conns.lock().await.push(conn);
                        pool.inner.idle.lock().await.push(Instant::now());
                        pool.inner.semaphore.add_permits(1);
                    }
                    Err(_) => break,
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
        let permit =
            tokio::time::timeout(self.inner.config.connect_timeout, self.inner.semaphore.clone().acquire_owned())
                .await
                .map_err(|_| PgError::PoolTimeout)?
                .map_err(|_| PgError::PoolClosed)?;

        {
            let mut idle = self.inner.idle_conns.lock().await;
            if let Some(conn) = idle.pop() {
                self.inner.idle.lock().await.remove(0);
                return Ok(PooledConnection {
                    conn: Some(conn),
                    pool: self.inner.clone(),
                    _permit: Some(permit),
                });
            }
        }

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

    /// Acquire a connection from the pool and start a transaction.
    /// The connection is returned to the pool on commit/rollback/drop.
    pub async fn begin(&self) -> Result<Transaction> {
        let mut pooled = self.get().await?;
        let conn = pooled.conn.take().expect("connection already taken");
        let permit = pooled._permit.take().expect("permit already taken");
        Transaction::begin_pooled(conn, pooled.pool.clone(), permit).await
    }

    pub fn is_closed(&self) -> bool {
        false
    }

    pub async fn close(&self) {
        self.inner.closed.notify_waiters();
    }

    async fn reaper_loop(&self) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            if self.is_closed() {
                return;
            }

            let mut idle = self.inner.idle_conns.lock().await;
            let mut idle_times = self.inner.idle.lock().await;
            let mut keep = Vec::new();
            let mut keep_times = Vec::new();

            while let Some(conn) = idle.pop() {
                let t = idle_times.remove(0);
                if t.elapsed() < self.inner.config.idle_timeout {
                    keep.push(conn);
                    keep_times.push(t);
                }
            }

            while idle.len() > self.inner.config.min_connections as usize {
                idle.pop();
                idle_times.pop();
            }

            *idle = keep;
            *idle_times = keep_times;
        }
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

    /// Start a transaction on this pooled connection.
    /// The connection is returned to the pool on commit/rollback/drop.
    pub async fn begin(mut self) -> Result<Transaction> {
        let conn = self.conn.take().expect("connection already taken");
        let permit = self._permit.take();
        let pool = self.pool.clone();
        Transaction::begin_pooled(conn, pool, permit.unwrap()).await
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("PooledConnection dropped")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("PooledConnection dropped")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.idle_conns.blocking_lock().push(conn);
            self.pool.idle.blocking_lock().push(Instant::now());
        }
    }
}
