pub type Oid = u32;

pub const INT2OID: Oid = 21;
pub const INT4OID: Oid = 23;
pub const INT8OID: Oid = 20;
pub const FLOAT4OID: Oid = 700;
pub const FLOAT8OID: Oid = 701;
pub const NUMERICOID: Oid = 1700;
pub const BOOLOID: Oid = 16;
pub const TEXTOID: Oid = 25;
pub const VARCHAROID: Oid = 1043;
pub const BYTEAOID: Oid = 17;
pub const UUIDOID: Oid = 2950;
pub const DATEOID: Oid = 1082;
pub const TIMEOID: Oid = 1083;
pub const TIMESTAMPOID: Oid = 1114;
pub const TIMESTAMPTZOID: Oid = 1184;
pub const JSONOID: Oid = 114;
pub const JSONBOID: Oid = 3802;
pub const INT2_ARRAY_OID: Oid = 1005;
pub const INT4_ARRAY_OID: Oid = 1007;
pub const INT8_ARRAY_OID: Oid = 1016;
pub const TEXT_ARRAY_OID: Oid = 1009;
pub const FLOAT8_ARRAY_OID: Oid = 1022;
pub const BOOL_ARRAY_OID: Oid = 1000;
pub const BYTEA_ARRAY_OID: Oid = 1001;
pub const UUID_ARRAY_OID: Oid = 2951;
pub const TIMESTAMPTZ_ARRAY_OID: Oid = 1185;
pub const OIDOID: Oid = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Binary,
}

#[derive(Debug, Clone)]
pub struct PgType {
    pub oid: Oid,
    pub name: &'static str,
}

impl PgType {
    pub const fn new(oid: Oid, name: &'static str) -> Self {
        PgType {
            oid,
            name,
        }
    }
}

pub static INT2: PgType = PgType::new(INT2OID, "int2");
pub static INT4: PgType = PgType::new(INT4OID, "int4");
pub static INT8: PgType = PgType::new(INT8OID, "int8");
pub static FLOAT4: PgType = PgType::new(FLOAT4OID, "float4");
pub static FLOAT8: PgType = PgType::new(FLOAT8OID, "float8");
pub static BOOL: PgType = PgType::new(BOOLOID, "bool");
pub static TEXT: PgType = PgType::new(TEXTOID, "text");
pub static BYTEA: PgType = PgType::new(BYTEAOID, "bytea");
pub static UUID: PgType = PgType::new(UUIDOID, "uuid");
pub static TIMESTAMPTZ: PgType = PgType::new(TIMESTAMPTZOID, "timestamptz");
pub static INT2_ARRAY: PgType = PgType::new(INT2_ARRAY_OID, "_int2");
pub static INT4_ARRAY: PgType = PgType::new(INT4_ARRAY_OID, "_int4");
pub static INT8_ARRAY: PgType = PgType::new(INT8_ARRAY_OID, "_int8");
pub static TEXT_ARRAY: PgType = PgType::new(TEXT_ARRAY_OID, "_text");
pub static FLOAT8_ARRAY: PgType = PgType::new(FLOAT8_ARRAY_OID, "_float8");
pub static BOOL_ARRAY: PgType = PgType::new(BOOL_ARRAY_OID, "_bool");
pub static UUID_ARRAY: PgType = PgType::new(UUID_ARRAY_OID, "_uuid");

pub fn element_to_array(elem: &PgType) -> &'static PgType {
    match elem.oid {
        INT2OID => &INT2_ARRAY,
        INT4OID => &INT4_ARRAY,
        INT8OID => &INT8_ARRAY,
        FLOAT8OID => &FLOAT8_ARRAY,
        BOOLOID => &BOOL_ARRAY,
        UUIDOID => &UUID_ARRAY,
        TEXTOID | VARCHAROID => &TEXT_ARRAY,
        _ => &INT4_ARRAY,
    }
}

impl PgType {
    pub fn array_of(elem: &PgType) -> Self {
        let oid = match elem.oid {
            INT2OID => INT2_ARRAY_OID,
            INT4OID => INT4_ARRAY_OID,
            INT8OID => INT8_ARRAY_OID,
            FLOAT8OID => FLOAT8_ARRAY_OID,
            BOOLOID => BOOL_ARRAY_OID,
            TEXTOID | VARCHAROID => TEXT_ARRAY_OID,
            BYTEAOID => BYTEA_ARRAY_OID,
            UUIDOID => UUID_ARRAY_OID,
            TIMESTAMPTZOID => TIMESTAMPTZ_ARRAY_OID,
            _ => INT4_ARRAY_OID,
        };
        PgType {
            oid,
            name: "", // array name not preserved
        }
    }
}
