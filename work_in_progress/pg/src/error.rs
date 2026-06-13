use std::fmt;

pub type Result<T> = std::result::Result<T, PgError>;

#[derive(Debug)]
pub struct DbError {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub position: Option<i32>,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} (code: {})", self.severity, self.message, self.code)?;
        if let Some(detail) = &self.detail {
            write!(f, "\n  detail: {}", detail)?;
        }
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {}", hint)?;
        }
        Ok(())
    }
}

impl std::error::Error for DbError {}

#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(Box<dyn std::error::Error + Send + Sync>),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Server error: {0}")]
    Server(#[from] DbError),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Pool closed")]
    PoolClosed,

    #[error("Pool timeout")]
    PoolTimeout,

    #[error("Config error: {0}")]
    Config(String),

    #[error("Decode error: {0}")]
    Decode(String),

    #[error("Encode error: {0}")]
    Encode(String),

    #[error("Row not found")]
    RowNotFound,

    #[error("Column not found: {0}")]
    ColumnNotFound(String),
}

impl From<rustls::Error> for PgError {
    fn from(e: rustls::Error) -> Self {
        PgError::Tls(Box::new(e))
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for PgError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        PgError::Tls(e)
    }
}
