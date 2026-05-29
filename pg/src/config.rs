use tokio::sync::Semaphore;

use crate::{PgError, error::Result as PgResult};

#[derive(Debug, Clone)]
pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub dbname: Option<String>,
    pub user: String,
    pub password: Option<String>,
    pub connect_timeout: std::time::Duration,
}

impl ConnectParams {
    pub fn parse(conn_string: &str) -> PgResult<Self> {
        let mut host = String::from("localhost");
        let mut port: u16 = 5432;
        let mut dbname = None;
        let mut user = String::new();
        let mut password = None;
        let mut connect_timeout = std::time::Duration::from_secs(10);

        for part in conn_string.split_whitespace() {
            let (key, value) = match part.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match key {
                "host" => host = value.to_string(),
                "port" => port = value.parse().unwrap_or(5432),
                "dbname" => dbname = Some(value.to_string()),
                "user" => user = value.to_string(),
                "password" => password = Some(value.to_string()),
                "connect_timeout" => {
                    let secs: u64 = value.parse().unwrap_or(10);
                    connect_timeout = std::time::Duration::from_secs(secs);
                }
                _ => {}
            }
        }

        if user.is_empty() {
            return Err(PgError::Config("user is required".into()));
        }

        Ok(ConnectParams {
            host,
            port,
            dbname,
            user,
            password,
            connect_timeout,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub min_connections: u32,
    pub max_connections: u32,
    pub idle_timeout: std::time::Duration,
    pub max_lifetime: std::time::Duration,
    pub connect_timeout: std::time::Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            min_connections: 0,
            max_connections: 10,
            idle_timeout: std::time::Duration::from_secs(600),
            max_lifetime: std::time::Duration::from_secs(1800),
            connect_timeout: std::time::Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PoolInner {
    pub(crate) params: ConnectParams,
    pub(crate) config: PoolConfig,
    pub(crate) idle: tokio::sync::Mutex<Vec<std::time::Instant>>,
    pub(crate) idle_conns: tokio::sync::Mutex<Vec<super::connection::Connection>>,
    pub(crate) semaphore: std::sync::Arc<Semaphore>,
    pub(crate) closed: tokio::sync::Notify,
}

impl PoolInner {
    pub(crate) fn new(params: ConnectParams, config: PoolConfig) -> std::sync::Arc<Self> {
        std::sync::Arc::new(PoolInner {
            semaphore: std::sync::Arc::new(Semaphore::new(config.max_connections as usize)),
            idle: tokio::sync::Mutex::new(Vec::new()),
            idle_conns: tokio::sync::Mutex::new(Vec::new()),
            params,
            config,
            closed: tokio::sync::Notify::new(),
        })
    }
}
