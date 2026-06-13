use bytes::{BufMut, Bytes, BytesMut};

use crate::types::Format;

fn startup_message(params: &[(&str, &str)]) -> Bytes {
    let mut buf = BytesMut::new();
    let body_len = 4 + 4 + params.iter().map(|(k, v)| k.len() + v.len() + 2).sum::<usize>() + 1;
    buf.put_i32(body_len as i32);
    buf.put_i32(196608);
    for (k, v) in params {
        buf.put_slice(k.as_bytes());
        buf.put_u8(0);
        buf.put_slice(v.as_bytes());
        buf.put_u8(0);
    }
    buf.put_u8(0);
    buf.freeze()
}

fn ssl_request() -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_i32(8);
    buf.put_i32(80877103);
    buf.freeze()
}

fn password_message(password: &str) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u8(b'p');
    let body = password.as_bytes();
    buf.put_i32((body.len() + 4 + 1) as i32);
    buf.put_slice(body);
    buf.put_u8(0);
    buf.freeze()
}

fn sasl_initial_response(mechanism: &str, initial_data: &[u8]) -> Bytes {
    let mechanism_c = mechanism.as_bytes();
    let initial_len = mechanism_c.len() + 1 + 4 + initial_data.len();
    let mut buf = BytesMut::new();
    buf.put_u8(b'p');
    buf.put_i32((initial_len + 4) as i32);
    buf.put_slice(mechanism_c);
    buf.put_u8(0);
    buf.put_i32(initial_data.len() as i32);
    buf.put_slice(initial_data);
    buf.freeze()
}

fn sasl_response(data: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u8(b'p');
    buf.put_i32((data.len() + 4) as i32);
    buf.put_slice(data);
    buf.freeze()
}

fn query(sql: &str) -> Bytes {
    let sql_bytes = sql.as_bytes();
    let mut buf = BytesMut::new();
    buf.put_u8(b'Q');
    buf.put_i32((sql_bytes.len() + 4 + 1) as i32);
    buf.put_slice(sql_bytes);
    buf.put_u8(0);
    buf.freeze()
}

fn parse(stmt_name: &str, sql: &str, param_oids: &[u32]) -> Bytes {
    let sql_bytes = sql.as_bytes();
    let name_bytes = stmt_name.as_bytes();
    let body_len = name_bytes.len() + 1 + sql_bytes.len() + 1 + 2 + param_oids.len() * 4;
    let mut buf = BytesMut::new();
    buf.put_u8(b'P');
    buf.put_i32((body_len + 4) as i32);
    buf.put_slice(name_bytes);
    buf.put_u8(0);
    buf.put_slice(sql_bytes);
    buf.put_u8(0);
    buf.put_i16(param_oids.len() as i16);
    for oid in param_oids {
        buf.put_i32(*oid as i32);
    }
    buf.freeze()
}

fn bind(portal: &str, stmt: &str, param_formats: &[Format], params: &[Vec<u8>], result_format: Format) -> Bytes {
    let portal_bytes = portal.as_bytes();
    let stmt_bytes = stmt.as_bytes();
    let params_len: usize = params.iter().map(|p| p.len() + 4).sum();
    let body_len = portal_bytes.len()
        + 1
        + stmt_bytes.len()
        + 1
        + 2
        + param_formats.len() * 2
        + 2
        + params.len() * 4
        + params_len
        + 2;
    let mut buf = BytesMut::new();
    buf.put_u8(b'B');
    buf.put_i32((body_len + 4) as i32);
    buf.put_slice(portal_bytes);
    buf.put_u8(0);
    buf.put_slice(stmt_bytes);
    buf.put_u8(0);
    buf.put_i16(param_formats.len() as i16);
    for fmt in param_formats {
        buf.put_i16(match fmt {
            Format::Text => 0,
            Format::Binary => 1,
        });
    }
    buf.put_i16(params.len() as i16);
    for p in params {
        if p.is_empty() {
            buf.put_i32(-1);
        } else {
            buf.put_i32(p.len() as i32);
            buf.put_slice(p);
        }
    }
    buf.put_i16(match result_format {
        Format::Text => 0,
        Format::Binary => 1,
    });
    buf.freeze()
}

fn execute(portal: &str, max_rows: i32) -> Bytes {
    let portal_bytes = portal.as_bytes();
    let mut buf = BytesMut::new();
    buf.put_u8(b'E');
    buf.put_i32((portal_bytes.len() + 1 + 4 + 4) as i32);
    buf.put_slice(portal_bytes);
    buf.put_u8(0);
    buf.put_i32(max_rows);
    buf.freeze()
}

fn describe(kind: u8, name: &str) -> Bytes {
    let name_bytes = name.as_bytes();
    let mut buf = BytesMut::new();
    buf.put_u8(b'D');
    buf.put_i32((4 + 1 + name_bytes.len() + 1) as i32);
    buf.put_u8(kind);
    buf.put_slice(name_bytes);
    buf.put_u8(0);
    buf.freeze()
}

fn sync() -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u8(b'S');
    buf.put_i32(4 + 4);
    buf.freeze()
}

fn close(kind: u8, name: &str) -> Bytes {
    let name_bytes = name.as_bytes();
    let mut buf = BytesMut::new();
    buf.put_u8(b'C');
    buf.put_i32((4 + 1 + name_bytes.len() + 1) as i32);
    buf.put_u8(kind);
    buf.put_slice(name_bytes);
    buf.put_u8(0);
    buf.freeze()
}

fn terminate() -> Bytes {
    let mut buf = BytesMut::new();
    buf.put_u8(b'X');
    buf.put_i32(4 + 4);
    buf.freeze()
}

pub enum FrontendMessage {
    Startup(Vec<(String, String)>),
    SslRequest,
    Password(String),
    SaslInitialResponse(String, Vec<u8>),
    SaslResponse(Vec<u8>),
    Query(String),
    Parse(String, String, Vec<u32>),
    Bind(String, String, Vec<Format>, Vec<Vec<u8>>, Format),
    Execute(String, i32),
    Describe(u8, String),
    Sync,
    Close(u8, String),
    Terminate,
}

impl FrontendMessage {
    pub fn encode(&self) -> Bytes {
        match self {
            FrontendMessage::Startup(params) => {
                let pairs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                startup_message(&pairs)
            }
            FrontendMessage::SslRequest => ssl_request(),
            FrontendMessage::Password(p) => password_message(p),
            FrontendMessage::SaslInitialResponse(mech, data) => sasl_initial_response(mech, data),
            FrontendMessage::SaslResponse(data) => sasl_response(data),
            FrontendMessage::Query(sql) => query(sql),
            FrontendMessage::Parse(name, sql, oids) => parse(name, sql, oids),
            FrontendMessage::Bind(portal, stmt, formats, params, result_fmt) => {
                bind(portal, stmt, formats, params, *result_fmt)
            }
            FrontendMessage::Execute(portal, rows) => execute(portal, *rows),
            FrontendMessage::Describe(kind, name) => describe(*kind, name),
            FrontendMessage::Sync => sync(),
            FrontendMessage::Close(kind, name) => close(*kind, name),
            FrontendMessage::Terminate => terminate(),
        }
    }
}
