mod config;
mod connection;
mod decode;
mod encode;
mod error;
mod pool;
pub mod protocol;
mod queryer;
mod row;
mod transaction;
pub mod types;

pub use config::{ConnectParams, PoolConfig};
pub use connection::Connection;
pub use decode::FromSql;
pub use encode::{BindIter, ToSql};
pub use error::{DbError, PgError};
pub use pg_derive::FromRow;
pub use pool::{Pool, PooledConnection};
pub use queryer::{FromRow, Queryer, RowStream};
pub use row::Row;
pub use transaction::Transaction;

pub type Result<T> = std::result::Result<T, PgError>;

#[cfg(test)]
mod tests {
    use crate::{types::*, *};

    #[test]
    fn test_to_sql_i32() {
        let val: i32 = 42;
        let bytes = val.to_sql();
        assert_eq!(bytes, vec![0, 0, 0, 42]);
        assert_eq!(val.pg_type().oid, INT4OID);
    }

    #[test]
    fn test_to_sql_i64() {
        let val: i64 = 1234567890;
        let bytes = val.to_sql();
        assert_eq!(bytes, vec![0, 0, 0, 0, 73, 150, 2, 210]);
        assert_eq!(val.pg_type().oid, INT8OID);
    }

    #[test]
    fn test_to_sql_bool() {
        let t = true;
        let f = false;
        assert_eq!(t.to_sql(), vec![1]);
        assert_eq!(f.to_sql(), vec![0]);
        assert_eq!(t.pg_type().oid, BOOLOID);
    }

    #[test]
    fn test_to_sql_string() {
        let s = "hello".to_string();
        assert_eq!(s.to_sql(), b"hello");
        assert_eq!(s.pg_type().oid, TEXTOID);
    }

    #[test]
    fn test_to_sql_vec_i32() {
        let v = vec![1i32, 2, 3];
        let bytes = v.to_sql();
        assert!(bytes.len() > 20);
        assert_eq!(v.pg_type().oid, INT4_ARRAY_OID);
    }

    #[test]
    fn test_to_sql_vec_u8_bytea() {
        let v: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(v.to_sql(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(v.pg_type().oid, BYTEAOID);
    }

    #[test]
    fn test_to_sql_slice_u8_bytea() {
        let b: &[u8] = &[0xca, 0xfe, 0xba, 0xbe];
        assert_eq!(b.to_sql(), vec![0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(b.pg_type().oid, BYTEAOID);
    }

    #[test]
    fn test_to_sql_slice_i32_array() {
        let arr: &[i32] = &[10, 20];
        let bytes = arr.to_sql();
        assert!(bytes.len() > 20);
        assert_eq!(arr.pg_type().oid, INT4_ARRAY_OID);
    }

    #[test]
    fn test_to_sql_option_some() {
        let val: Option<i32> = Some(42);
        assert_eq!(val.to_sql(), vec![0, 0, 0, 42]);
    }

    #[test]
    fn test_bind_iter_i32() {
        let data = vec![1i32, 2, 3];
        let bi = BindIter::new(data.into_iter(), &INT4);
        let bytes = bi.to_sql();
        assert!(bytes.len() > 20);
        assert_eq!(bi.pg_type().oid, INT4_ARRAY_OID);

        let dim_count = i32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(dim_count, 3);
    }

    #[test]
    fn test_bind_iter_uuid() {
        let u1 = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let u2 = uuid::Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap();
        let bi = BindIter::new(vec![u1, u2].into_iter(), &UUID);
        let bytes = bi.to_sql();
        let dim_count = i32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(dim_count, 2);
        assert_eq!(bi.pg_type().oid, UUID_ARRAY_OID);
    }

    #[test]
    fn test_bind_iter_empty() {
        let empty: Vec<i32> = vec![];
        let bi = BindIter::new(empty.into_iter(), &INT4);
        let bytes = bi.to_sql();
        let dim_count = i32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        assert_eq!(dim_count, 0);
        assert_eq!(bytes.len(), 20); // header only
    }

    #[test]
    fn test_bind_iter_same_as_collected_vec() {
        let data = vec![10i32, 20, 30];
        let vec_encoded = data.to_sql();
        let bi_encoded = BindIter::new(data.clone().into_iter(), &INT4).to_sql();
        assert_eq!(vec_encoded, bi_encoded);
    }

    #[test]
    fn test_to_sql_option_none() {
        let val: Option<i32> = None;
        assert_eq!(val.to_sql(), Vec::<u8>::new());
    }

    #[test]
    fn test_from_sql_i32() {
        let val = i32::from_sql(INT4OID, &[0, 0, 0, 42]).unwrap();
        assert_eq!(val, 42);
    }

    #[test]
    fn test_from_sql_i64() {
        let val = i64::from_sql(INT8OID, &[0, 0, 0, 0, 73, 150, 2, 210]).unwrap();
        assert_eq!(val, 1234567890);
    }

    #[test]
    fn test_from_sql_bool() {
        let t = bool::from_sql(BOOLOID, &[1]).unwrap();
        let f = bool::from_sql(BOOLOID, &[0]).unwrap();
        assert!(t);
        assert!(!f);
    }

    #[test]
    fn test_from_sql_string() {
        let s = String::from_sql(TEXTOID, b"hello").unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn test_from_sql_option() {
        let some: Option<i32> = Option::from_sql(INT4OID, &[0, 0, 0, 42]).unwrap();
        assert_eq!(some, Some(42));

        let none: Option<i32> = Option::from_sql(INT4OID, &[]).unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn test_connect_params_parse() {
        let params = ConnectParams::parse("host=localhost port=5432 user=test dbname=mydb").unwrap();
        assert_eq!(params.host, "localhost");
        assert_eq!(params.port, 5432);
        assert_eq!(params.user, "test");
        assert_eq!(params.dbname, Some("mydb".to_string()));
    }

    #[test]
    fn test_connect_params_requires_user() {
        let result = ConnectParams::parse("host=localhost");
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_params_defaults() {
        let params = ConnectParams::parse("user=test").unwrap();
        assert_eq!(params.host, "localhost");
        assert_eq!(params.port, 5432);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"SCRAM test data \x00\x01\x02";
        let encoded = protocol::base64_encode(data);
        let decoded = protocol::base64_decode(&encoded).unwrap();
        assert_eq!(data, &decoded[..]);
    }

    #[test]
    fn test_pool_config_default() {
        let cfg = PoolConfig::default();
        assert_eq!(cfg.min_connections, 0);
        assert_eq!(cfg.max_connections, 10);
    }

    #[test]
    fn test_from_sql_timestamptz() {
        use chrono::{DateTime, Utc};
        let pg_epoch = DateTime::from_timestamp(946684800, 0).unwrap();
        let micros = 0i64.to_be_bytes();
        let dt = DateTime::<Utc>::from_sql(TIMESTAMPTZOID, &micros).unwrap();
        assert_eq!(dt, pg_epoch);

        let one_second: i64 = 1_000_000;
        let dt2 = DateTime::<Utc>::from_sql(TIMESTAMPTZOID, &one_second.to_be_bytes()).unwrap();
        assert_eq!(dt2, pg_epoch + chrono::TimeDelta::seconds(1));
    }
}
