//! Integration with [`sqlx`] for PostgreSQL UUID support.
//!
//! Enabled via the `sqlx` feature flag (requires the `postgres` database feature on `sqlx`).
//!
//! # Supported traits
//!
//! | Trait | Purpose |
//! |---|---|
//! | [`sqlx::Type`] | Declares the PostgreSQL type mapping as `uuid`. |
//! | [`sqlx::postgres::PgHasArrayType`] | Declares the PostgreSQL array type mapping as `_uuid`. |
//! | [`sqlx::Encode`] | Encodes a [`Uuid`] as 16 binary bytes for query arguments. |
//! | [`sqlx::Decode`] | Decodes a [`Uuid`] from both binary and text wire formats. |

use sqlx::{
    Postgres,
    decode::Decode,
    encode::{Encode, IsNull},
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueFormat, PgValueRef},
    types::Type,
};

use crate::Uuid;

impl Type<Postgres> for Uuid {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("uuid")
    }
}

impl PgHasArrayType for Uuid {
    fn array_type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("_uuid")
    }
}

impl Encode<'_, Postgres> for Uuid {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        buf.extend_from_slice(&self.0);
        Ok(IsNull::No)
    }
}

impl Decode<'_, Postgres> for Uuid {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        match value.format() {
            PgValueFormat::Binary => Uuid::from_slice(value.as_bytes()?).map_err(Into::into),
            PgValueFormat::Text => Uuid::parse(value.as_str()?).map_err(Into::into),
        }
    }
}
