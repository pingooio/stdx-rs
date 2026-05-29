use bytes::Buf;

use crate::error::{DbError, PgError};

#[derive(Debug)]
pub enum BackendMessage {
    AuthenticationOk,
    AuthenticationCleartextPassword,
    AuthenticationMD5Password([u8; 4]),
    AuthenticationSasl(Vec<String>),
    AuthenticationSaslContinue(Vec<u8>),
    AuthenticationSaslFinal(Vec<u8>),
    AuthenticationKerberosV5,
    AuthenticationScmCredential,
    AuthenticationGss,
    AuthenticationSspi,
    AuthenticationGssContinue(Vec<u8>),
    BackendKeyData(i32, i32),
    ParameterStatus(String, String),
    ReadyForQuery(u8),
    RowDescription(Vec<FieldDescription>),
    DataRow(Vec<Option<Vec<u8>>>),
    CommandComplete(String),
    ParseComplete,
    BindComplete,
    CloseComplete,
    PortalSuspended,
    ErrorResponse(DbError),
    NoticeResponse(DbError),
    NotificationResponse(i32, String, String),
    EmptyQueryResponse,
    NoData,
}

#[derive(Debug, Clone)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: u32,
    pub column_attr: i16,
    pub type_oid: u32,
    pub type_size: i16,
    pub type_mod: i32,
    pub format: i16,
}

pub struct BackendDecoder;

impl BackendDecoder {
    pub fn decode(buf: &mut bytes::BytesMut) -> Result<Option<BackendMessage>, PgError> {
        if buf.len() < 5 {
            return Ok(None);
        }

        let tag = buf[0];
        let len = (&buf[1..5]).get_i32() as usize;

        if buf.len() < 5 + len - 4 {
            return Ok(None);
        }

        buf.advance(5);
        let mut payload = buf.split_to(len - 4);

        let msg = match tag {
            b'R' => Self::decode_authentication(&mut payload)?,
            b'K' => Self::decode_backend_key_data(&mut payload),
            b'S' => Self::decode_parameter_status(&mut payload),
            b'Z' => Self::decode_ready_for_query(&mut payload),
            b'T' => Self::decode_row_description(&mut payload)?,
            b'D' => Self::decode_data_row(&mut payload),
            b'C' => Self::decode_command_complete(&mut payload),
            b'1' => BackendMessage::ParseComplete,
            b'2' => BackendMessage::BindComplete,
            b'3' => BackendMessage::CloseComplete,
            b's' => BackendMessage::PortalSuspended,
            b'E' => {
                let err = Self::decode_error(&mut payload);
                return Err(PgError::Server(err));
            }
            b'N' => {
                let err = Self::decode_error(&mut payload);
                BackendMessage::NoticeResponse(err)
            }
            b'A' => Self::decode_notification_response(&mut payload),
            b'I' => BackendMessage::EmptyQueryResponse,
            b'n' => BackendMessage::NoData,
            other => return Err(PgError::Protocol(format!("unknown message tag: {:?}", other as char))),
        };

        Ok(Some(msg))
    }

    fn decode_authentication(buf: &mut bytes::BytesMut) -> Result<BackendMessage, PgError> {
        let kind = buf.get_i32();

        match kind {
            0 => Ok(BackendMessage::AuthenticationOk),
            2 => Ok(BackendMessage::AuthenticationKerberosV5),
            3 => Ok(BackendMessage::AuthenticationCleartextPassword),
            5 => {
                let mut salt = [0u8; 4];
                buf.copy_to_slice(&mut salt);
                Ok(BackendMessage::AuthenticationMD5Password(salt))
            }
            6 => Ok(BackendMessage::AuthenticationScmCredential),
            7 => Ok(BackendMessage::AuthenticationGss),
            8 => Ok(BackendMessage::AuthenticationGssContinue(buf.to_vec())),
            9 => Ok(BackendMessage::AuthenticationSspi),
            10 => {
                let mut mechanisms = Vec::new();
                while buf.has_remaining() {
                    let b = buf.get_u8();
                    if b == 0 {
                        break;
                    }
                    let mut s = vec![b];
                    while buf.has_remaining() {
                        let b = buf.get_u8();
                        if b == 0 {
                            break;
                        }
                        s.push(b);
                    }
                    mechanisms.push(String::from_utf8_lossy(&s).to_string());
                }
                Ok(BackendMessage::AuthenticationSasl(mechanisms))
            }
            11 => Ok(BackendMessage::AuthenticationSaslContinue(buf.to_vec())),
            12 => Ok(BackendMessage::AuthenticationSaslFinal(buf.to_vec())),
            _ => Err(PgError::Auth(format!("unknown auth method: {}", kind))),
        }
    }

    fn decode_backend_key_data(buf: &mut bytes::BytesMut) -> BackendMessage {
        let pid = buf.get_i32();
        let key = buf.get_i32();
        BackendMessage::BackendKeyData(pid, key)
    }

    fn decode_parameter_status(buf: &mut bytes::BytesMut) -> BackendMessage {
        let key = read_cstring(buf);
        let value = read_cstring(buf);
        BackendMessage::ParameterStatus(key, value)
    }

    fn decode_ready_for_query(buf: &mut bytes::BytesMut) -> BackendMessage {
        let status = buf.get_u8();
        BackendMessage::ReadyForQuery(status)
    }

    fn decode_row_description(buf: &mut bytes::BytesMut) -> Result<BackendMessage, PgError> {
        let count = buf.get_i16();
        let mut fields = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let name = read_cstring(buf);
            let table_oid = buf.get_u32();
            let column_attr = buf.get_i16();
            let type_oid = buf.get_u32();
            let type_size = buf.get_i16();
            let type_mod = buf.get_i32();
            let format = buf.get_i16();
            fields.push(FieldDescription {
                name,
                table_oid,
                column_attr,
                type_oid,
                type_size,
                type_mod,
                format,
            });
        }
        Ok(BackendMessage::RowDescription(fields))
    }

    fn decode_data_row(buf: &mut bytes::BytesMut) -> BackendMessage {
        let count = buf.get_i16();
        let mut columns = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let len = buf.get_i32();
            if len == -1 {
                columns.push(None);
            } else {
                let mut data = vec![0u8; len as usize];
                buf.copy_to_slice(&mut data);
                columns.push(Some(data));
            }
        }
        BackendMessage::DataRow(columns)
    }

    fn decode_command_complete(buf: &mut bytes::BytesMut) -> BackendMessage {
        let tag = read_cstring(buf);
        BackendMessage::CommandComplete(tag)
    }

    fn decode_error(buf: &mut bytes::BytesMut) -> DbError {
        let mut severity = String::new();
        let mut code = String::new();
        let mut message = String::new();
        let mut detail = None;
        let mut hint = None;
        let mut position = None;

        while buf.has_remaining() {
            let field_type = buf.get_u8();
            if field_type == 0 {
                break;
            }
            let value = read_cstring(buf);
            match field_type {
                b'S' => severity = value,
                b'C' => code = value,
                b'M' => message = value,
                b'D' => detail = Some(value),
                b'H' => hint = Some(value),
                b'P' => position = value.parse().ok(),
                _ => {}
            }
        }

        DbError {
            severity,
            code,
            message,
            detail,
            hint,
            position,
        }
    }

    fn decode_notification_response(buf: &mut bytes::BytesMut) -> BackendMessage {
        let pid = buf.get_i32();
        let channel = read_cstring(buf);
        let payload = read_cstring(buf);
        BackendMessage::NotificationResponse(pid, channel, payload)
    }
}

fn read_cstring(buf: &mut bytes::BytesMut) -> String {
    let mut s = Vec::new();
    loop {
        let b = buf.get_u8();
        if b == 0 {
            break;
        }
        s.push(b);
    }
    String::from_utf8_lossy(&s).to_string()
}
