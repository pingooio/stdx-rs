use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::BytesMut;
use lru::LruCache;
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};
use tokio_rustls::TlsConnector;

use crate::{
    config::ConnectParams,
    encode::ToSql,
    error::{PgError, Result},
    protocol::{BackendDecoder, BackendMessage, FieldDescription, FrontendMessage, ScramClient},
    row::Row,
};

enum PgStream {
    Plain(tokio::net::TcpStream),
    Tls(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
}

impl AsyncRead for PgStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            PgStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PgStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            PgStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_flush(cx),
            PgStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            PgStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            PgStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

struct Inner {
    stream: PgStream,
    buf: BytesMut,
    _pid: i32,
    _secret_key: i32,
    _parameter_status: HashMap<String, String>,
    statement_cache: LruCache<String, (String, Vec<FieldDescription>)>,
}

#[derive(Clone)]
pub struct Connection {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

fn sql_statement_name(sql: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    sql.hash(&mut hasher);
    format!("s{:x}", hasher.finish())
}

impl Connection {
    pub async fn connect(params: &ConnectParams) -> Result<Self> {
        let addr = format!("{}:{}", params.host, params.port);
        let tcp = tokio::time::timeout(params.connect_timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| PgError::Protocol(format!("connection timeout to {}", addr)))?
            .map_err(PgError::Io)?;

        tcp.set_nodelay(true).ok();

        let stream = tls_handshake(tcp, &params.host).await?;

        let mut inner = Inner {
            stream,
            buf: BytesMut::with_capacity(8192),
            _pid: 0,
            _secret_key: 0,
            _parameter_status: HashMap::new(),
            statement_cache: LruCache::new(NonZeroUsize::new(100).unwrap()),
        };

        do_startup(&mut inner, params).await?;

        Ok(Connection {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    pub async fn query_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Row>> {
        let mut guard = self.inner.lock().await;

        if params.is_empty() {
            return simple_query(&mut guard, sql).await;
        }

        let stmt_name = sql_statement_name(sql);
        let param_oids: Vec<u32> = params.iter().map(|p| p.pg_type().oid).collect();

        let cached_name = guard.statement_cache.get(sql).map(|(name, _)| name.clone());
        if let Some(ref old_name) = cached_name {
            if *old_name != stmt_name {
                send_close_statement(&mut guard, old_name).await?;
                guard.statement_cache.pop(sql);
            }
        }

        if !guard.statement_cache.contains(sql) {
            send_parse(&mut guard, &stmt_name, sql, &param_oids).await?;
            read_until_parse_complete(&mut guard).await?;

            send_describe_statement(&mut guard, &stmt_name).await?;
            let fields = match read_describe_response(&mut guard).await? {
                Some(fields) => fields,
                None => Vec::new(),
            };

            guard.statement_cache.put(sql.to_string(), (stmt_name.clone(), fields));
        }

        let (cached_stmt_name, fields) = guard.statement_cache.get(sql).expect("just cached").clone();

        let param_binary: Vec<Vec<u8>> = params.iter().map(|p| p.to_sql()).collect::<Result<Vec<Vec<u8>>>>()?;
        let param_formats: Vec<crate::types::Format> = params.iter().map(|_| crate::types::Format::Binary).collect();

        send_bind(
            &mut guard,
            "",
            &cached_stmt_name,
            &param_formats,
            &param_binary,
            crate::types::Format::Binary,
        )
        .await?;
        read_until_bind_complete(&mut guard).await?;

        send_describe_portal(&mut guard, "").await?;

        send_execute(&mut guard, "", 0).await?;
        let rows = read_rows_until_complete(&mut guard, &fields).await?;

        send_sync(&mut guard).await?;
        read_until_ready(&mut guard).await?;

        Ok(rows)
    }

    pub async fn execute_raw(&self, sql: &str, params: &[&dyn ToSql]) -> Result<u64> {
        let mut guard = self.inner.lock().await;

        if params.is_empty() {
            return simple_execute(&mut guard, sql).await;
        }

        let stmt_name = sql_statement_name(sql);
        let param_oids: Vec<u32> = params.iter().map(|p| p.pg_type().oid).collect();

        if let Some((old_name, _)) = guard.statement_cache.get(sql) {
            if *old_name != stmt_name {
                let old = old_name.clone();
                guard.statement_cache.pop(sql);
                send_close_statement(&mut guard, &old).await?;
            }
        }

        if !guard.statement_cache.contains(sql) {
            send_parse(&mut guard, &stmt_name, sql, &param_oids).await?;
            read_until_parse_complete(&mut guard).await?;
            guard
                .statement_cache
                .put(sql.to_string(), (stmt_name.clone(), Vec::new()));
        }

        let cached_stmt_name = guard
            .statement_cache
            .get(sql)
            .map(|(n, _)| n.clone())
            .expect("just cached");

        let param_binary: Vec<Vec<u8>> = params.iter().map(|p| p.to_sql()).collect::<Result<Vec<Vec<u8>>>>()?;
        let param_formats: Vec<crate::types::Format> = params.iter().map(|_| crate::types::Format::Binary).collect();

        send_bind(
            &mut guard,
            "",
            &cached_stmt_name,
            &param_formats,
            &param_binary,
            crate::types::Format::Binary,
        )
        .await?;
        read_until_bind_complete(&mut guard).await?;

        send_execute(&mut guard, "", 0).await?;
        let rows_affected = read_command_complete(&mut guard).await?;

        send_sync(&mut guard).await?;
        read_until_ready(&mut guard).await?;

        Ok(rows_affected)
    }

    pub(crate) async fn ping(&self) -> Result<()> {
        self.query_raw("SELECT 1", &[]).await?;
        Ok(())
    }
}

async fn tls_handshake(tcp: tokio::net::TcpStream, host: &str) -> Result<PgStream> {
    let msg = FrontendMessage::SslRequest;
    let encoded = msg.encode();
    let (mut reader, mut writer) = tokio::io::split(tcp);

    writer.write_all(&encoded).await?;

    let mut response = [0u8; 1];
    reader.read_exact(&mut response).await?;

    if response[0] == b'S' {
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| PgError::Config(format!("invalid hostname: {}", host)))?;

        let tls_stream = connector
            .connect(server_name, reader.unsplit(writer))
            .await
            .map_err(|e| PgError::Tls(Box::new(e)))?;
        Ok(PgStream::Tls(tls_stream))
    } else {
        let tcp = reader.unsplit(writer);
        Ok(PgStream::Plain(tcp))
    }
}

async fn do_startup(inner: &mut Inner, params: &ConnectParams) -> Result<()> {
    let mut kv = vec![
        ("client_encoding".to_string(), "UTF8".to_string()),
        ("user".to_string(), params.user.clone()),
    ];
    if let Some(ref db) = params.dbname {
        kv.push(("database".to_string(), db.clone()));
    }

    let msg = FrontendMessage::Startup(kv);
    inner.write_all(&msg.encode()).await?;

    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::AuthenticationOk => {
                read_until_ready(inner).await?;
                return Ok(());
            }
            BackendMessage::AuthenticationCleartextPassword => {
                let password = params.password.as_deref().unwrap_or("");
                let msg = FrontendMessage::Password(password.to_string());
                inner.write_all(&msg.encode()).await?;
            }
            BackendMessage::AuthenticationSasl(mechanisms) => {
                if !mechanisms.iter().any(|m| m == "SCRAM-SHA-256") {
                    return Err(PgError::Auth("server does not support SCRAM-SHA-256".into()));
                }
                let mut scram = ScramClient::new(&params.user, params.password.as_deref().unwrap_or(""));

                let initial = scram.client_first_message().as_bytes().to_vec();
                let msg = FrontendMessage::SaslInitialResponse("SCRAM-SHA-256".to_string(), initial);
                inner.write_all(&msg.encode()).await?;

                let continue_msg = read_message(inner).await?;
                match continue_msg {
                    BackendMessage::AuthenticationSaslContinue(data) => {
                        scram.parse_server_first_message(&data)?;
                        let final_msg = scram.build_client_final_message();
                        let msg = FrontendMessage::SaslResponse(final_msg);
                        inner.write_all(&msg.encode()).await?;
                    }
                    _ => return Err(PgError::Protocol("expected SASL continue".into())),
                }

                let final_msg = read_message(inner).await?;
                match final_msg {
                    BackendMessage::AuthenticationSaslFinal(data) => {
                        scram.parse_server_final_message(&data)?;
                    }
                    _ => return Err(PgError::Protocol("expected SASL final".into())),
                }
            }
            BackendMessage::ParameterStatus(_, _) => {}
            BackendMessage::BackendKeyData(pid, key) => {
                inner._pid = pid;
                inner._secret_key = key;
            }
            BackendMessage::ReadyForQuery(_) => {
                return Ok(());
            }
            _ => return Err(PgError::Protocol("unexpected message during startup".into())),
        }
    }
}

async fn simple_query(inner: &mut Inner, sql: &str) -> Result<Vec<Row>> {
    let msg = FrontendMessage::Query(sql.to_string());
    inner.write_all(&msg.encode()).await?;

    let mut rows = Vec::new();
    let mut fields = Vec::new();

    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::RowDescription(fds) => {
                fields = fds;
            }
            BackendMessage::DataRow(cols) => {
                let row = Row::new(&fields, &cols);
                rows.push(row);
            }
            BackendMessage::CommandComplete(_) => {}
            BackendMessage::ReadyForQuery(_) => {
                return Ok(rows);
            }
            BackendMessage::EmptyQueryResponse => {}
            BackendMessage::NoticeResponse(_) => {}
            _ => {
                return Err(PgError::Protocol("unexpected message in simple query".into()));
            }
        }
    }
}

async fn simple_execute(inner: &mut Inner, sql: &str) -> Result<u64> {
    let msg = FrontendMessage::Query(sql.to_string());
    inner.write_all(&msg.encode()).await?;

    let mut rows_affected = 0u64;

    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::RowDescription(_) => {}
            BackendMessage::DataRow(_) => {}
            BackendMessage::CommandComplete(tag) => {
                parse_command_tag(&tag, &mut rows_affected);
            }
            BackendMessage::ReadyForQuery(_) => {
                return Ok(rows_affected);
            }
            BackendMessage::EmptyQueryResponse => {}
            BackendMessage::NoticeResponse(_) => {}
            _ => {
                return Err(PgError::Protocol("unexpected message in simple execute".into()));
            }
        }
    }
}

fn parse_command_tag(tag: &str, affected: &mut u64) -> u64 {
    if let Some(n) = tag.rsplit(' ').next().and_then(|s| s.parse::<u64>().ok()) {
        *affected = n;
        n
    } else {
        0
    }
}

async fn send_parse(inner: &mut Inner, stmt_name: &str, sql: &str, param_oids: &[u32]) -> Result<()> {
    let msg = FrontendMessage::Parse(stmt_name.to_string(), sql.to_string(), param_oids.to_vec());
    inner.write_all(&msg.encode()).await?;
    Ok(())
}

async fn read_until_parse_complete(inner: &mut Inner) -> Result<()> {
    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::ParseComplete => return Ok(()),
            BackendMessage::NoticeResponse(_) => {}
            _ => return Err(PgError::Protocol("expected ParseComplete".into())),
        }
    }
}

async fn send_bind(
    inner: &mut Inner,
    portal: &str,
    stmt: &str,
    formats: &[crate::types::Format],
    params: &[Vec<u8>],
    result_format: crate::types::Format,
) -> Result<()> {
    let msg = FrontendMessage::Bind(
        portal.to_string(),
        stmt.to_string(),
        formats.to_vec(),
        params.to_vec(),
        result_format,
    );
    inner.write_all(&msg.encode()).await?;
    Ok(())
}

async fn read_until_bind_complete(inner: &mut Inner) -> Result<()> {
    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::BindComplete => return Ok(()),
            BackendMessage::NoticeResponse(_) => {}
            _ => return Err(PgError::Protocol("expected BindComplete".into())),
        }
    }
}

async fn send_describe_statement(inner: &mut Inner, stmt: &str) -> Result<()> {
    let msg = FrontendMessage::Describe(b'S', stmt.to_string());
    inner.write_all(&msg.encode()).await?;
    Ok(())
}

async fn send_describe_portal(inner: &mut Inner, portal: &str) -> Result<()> {
    let msg = FrontendMessage::Describe(b'P', portal.to_string());
    inner.write_all(&msg.encode()).await?;
    Ok(())
}

async fn read_describe_response(inner: &mut Inner) -> Result<Option<Vec<FieldDescription>>> {
    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::RowDescription(fields) => return Ok(Some(fields)),
            BackendMessage::NoData => return Ok(None),
            BackendMessage::NoticeResponse(_) => {}
            _ => return Err(PgError::Protocol("expected RowDescription or NoData".into())),
        }
    }
}

async fn send_execute(inner: &mut Inner, portal: &str, max_rows: i32) -> Result<()> {
    let msg = FrontendMessage::Execute(portal.to_string(), max_rows);
    inner.write_all(&msg.encode()).await?;
    Ok(())
}

async fn read_rows_until_complete(inner: &mut Inner, fields: &[FieldDescription]) -> Result<Vec<Row>> {
    let mut rows = Vec::new();

    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::DataRow(cols) => {
                let row = Row::new(fields, &cols);
                rows.push(row);
            }
            BackendMessage::CommandComplete(_) => {
                return Ok(rows);
            }
            BackendMessage::PortalSuspended => {
                return Ok(rows);
            }
            BackendMessage::NoticeResponse(_) => {}
            _ => return Err(PgError::Protocol("expected DataRow or CommandComplete".into())),
        }
    }
}

async fn read_command_complete(inner: &mut Inner) -> Result<u64> {
    let mut affected = 0u64;
    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::CommandComplete(tag) => {
                parse_command_tag(&tag, &mut affected);
                return Ok(affected);
            }
            BackendMessage::NoticeResponse(_) => {}
            _ => return Err(PgError::Protocol("expected CommandComplete".into())),
        }
    }
}

async fn send_sync(inner: &mut Inner) -> Result<()> {
    let msg = FrontendMessage::Sync;
    inner.write_all(&msg.encode()).await?;
    Ok(())
}

async fn send_close_statement(inner: &mut Inner, stmt: &str) -> Result<()> {
    let msg = FrontendMessage::Close(b'S', stmt.to_string());
    inner.write_all(&msg.encode()).await?;
    read_until_close_complete(inner).await
}

async fn read_until_close_complete(inner: &mut Inner) -> Result<()> {
    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::CloseComplete => return Ok(()),
            BackendMessage::NoticeResponse(_) => {}
            _ => return Err(PgError::Protocol("expected CloseComplete".into())),
        }
    }
}

async fn read_until_ready(inner: &mut Inner) -> Result<u8> {
    loop {
        let backend = read_message(inner).await?;
        match backend {
            BackendMessage::ReadyForQuery(status) => return Ok(status),
            BackendMessage::NoticeResponse(_) => {}
            BackendMessage::ParameterStatus(_, _) => {}
            BackendMessage::CommandComplete(_) => {}
            _ => {
                return Err(PgError::Protocol("expected ReadyForQuery".into()));
            }
        }
    }
}

async fn read_message(inner: &mut Inner) -> Result<BackendMessage> {
    loop {
        if let Some(msg) = BackendDecoder::decode(&mut inner.buf)? {
            return Ok(msg);
        }
        inner.buf.reserve(4096);
        let n = inner.stream.read_buf(&mut inner.buf).await.map_err(PgError::Io)?;
        if n == 0 {
            return Err(PgError::Protocol("connection closed by server".into()));
        }
    }
}

impl Inner {
    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        AsyncWriteExt::write_all(&mut self.stream, buf)
            .await
            .map_err(PgError::Io)
    }
}
