# pg — PostgreSQL client library for Rust

Async PostgreSQL client with connection pooling, type-safe row mapping, and iterator-based array binding.

## Features

- **Connection pooling** — configurable min/max connections, idle timeout, background reaper
- **FromRow derive** — auto-decode rows to structs via `#[derive(pg::FromRow)]`
- **Iterator array binding** — bind iterators directly (no intermediate `Vec`) for `UNNEST` / `ANY`
- **SCRAM-SHA-256 auth** — no MD5, no cleartext passwords without TLS
- **Async/tokio** — all I/O via tokio with interior mutability (`&self` methods)
- **Connection, Pool, Transaction** all implement `Queryer` — write generic functions

## Quick Start

```rust
use pg::{Connection, ConnectParams, Pool, Transaction, FromRow};

#[derive(FromRow, Debug)]
struct User {
    id: i32,
    name: String,
    email: Option<String>,
}

#[tokio::main]
async fn main() -> pg::Result<()> {
    // Single connection
    let params = ConnectParams::parse("user=postgres dbname=test")?;
    let conn = Connection::connect(&params).await?;
    let rows: Vec<User> = conn.query_as("SELECT id, name, email FROM users", &[]).await?;

    // Or with a pool
    let pool = Pool::connect(params).await?;
    let conn = pool.get().await?;
    let user: User = conn.query_one_as("SELECT * FROM users WHERE id = $1", &[&42i32]).await?;

    Ok(())
}
```

## Connection

```rust
let params = ConnectParams::parse("host=localhost port=5432 user=postgres dbname=mydb password=secret")?;
let conn = Connection::connect(&params).await?;

// Simple query (no parameters)
let rows = conn.query_raw("SELECT 1 AS num, 'hello' AS text", &[]).await?;
let num: i32 = rows[0].try_get("num")?;

// Parameterized query (binary format)
conn.execute_raw("INSERT INTO users (name, age) VALUES ($1, $2)", &[&"Alice".to_string(), &30i32]).await?;
```

## Connection Pooling

```rust
use pg::{Pool, PoolConfig};

let pool = Pool::connect_with_config(params, PoolConfig {
    min_connections: 2,
    max_connections: 10,
    idle_timeout: std::time::Duration::from_secs(300),
    ..PoolConfig::default()
}).await?;

// PooledConnection auto-returns to pool on drop
let conn = pool.get().await?;
conn.query_raw("SELECT 1", &[]).await?;
```

## Transactions

```rust
// Standalone transaction
let txn = Transaction::begin(conn.clone()).await?;
txn.execute_raw("UPDATE accounts SET balance = balance - 100 WHERE id = $1", &[&1i32]).await?;
txn.commit().await?;

// Pool-level transaction (acquires connection, returns on commit/rollback)
let txn = pool.begin().await?;
txn.execute_raw("INSERT INTO logs (msg) VALUES ($1)", &[&"done".to_string()]).await?;
txn.commit().await?;

// Auto-rollback on drop
{
    let txn = pool.begin().await?;
    txn.execute_raw("DELETE FROM users WHERE id = $1", &[&99i32]).await?;
    // txn drops → ROLLBACK, connection returned to pool
}
```

## Generic Queryer trait

Write functions that accept `Connection`, `Pool`, or `Transaction`:

```rust
async fn count_users<Q: pg::Queryer>(db: Q, min_age: i32) -> pg::Result<i64> {
    let row = db.query_one_as::<(i64,)>("SELECT COUNT(*) FROM users WHERE age >= $1", &[&min_age]).await?;
    Ok(row.0)
}

// All work:
count_users(&conn, 18).await?;
count_users(&pool, 18).await?;
count_users(&txn, 18).await?;
```

## FromRow Derive

```rust
#[derive(pg::FromRow)]
#[pg(rename_all = "camelCase")]
struct Staff {
    id: i32,
    #[pg(column = "full_name")]
    name: String,
    #[pg(default)]
    email: Option<String>,
}

let rows: Vec<Staff> = conn.query_as("SELECT id, full_name, email FROM staff", &[]).await?;
```

## Iterator Array Binding (UNNEST / ANY)

Bind iterators directly as PG arrays — no intermediate `Vec` for each column:

```rust
use pg::{BindIter, types::*};

let invitations: Vec<StaffInvitation> = get_invitations().await;

const QUERY: &str = "INSERT INTO staff_invitations
    (id, created_at, updated_at, role, invitee_id, inviter_id, organization_id)
    SELECT * FROM UNNEST(
        $1::UUID[], $2::TIMESTAMPTZ[], $3::TIMESTAMPTZ[],
        $4::TEXT[], $5::UUID[], $6::UUID[], $7::UUID[]
    )";

let params: &[&dyn pg::ToSql] = &[
    &BindIter::new(invitations.iter().map(|i| i.id), &UUID),
    &BindIter::new(invitations.iter().map(|i| i.created_at), &TIMESTAMPTZ),
    &BindIter::new(invitations.iter().map(|i| i.updated_at), &TIMESTAMPTZ),
    &BindIter::new(invitations.iter().map(|i| &*i.role), &TEXT),
    &BindIter::new(invitations.iter().map(|i| i.invitee_id), &UUID),
    &BindIter::new(invitations.iter().map(|i| i.inviter_id), &UUID),
    &BindIter::new(invitations.iter().map(|i| i.organization_id), &UUID),
];

db.execute_raw(QUERY, params).await?;
// No Vec allocation per column — iterator writes directly to wire format
```

Uses `Iterator::size_hint()` for pre-allocation when available. The encoded output matches `Vec<T>::to_sql()` exactly, so the same `UNNEST(...)` pattern works interchangeably.

## Supported Types

| Rust type | PG type |
|-----------|---------|
| `i16` | `INT2` |
| `i32` | `INT4` |
| `i64` | `INT8` |
| `f32` | `FLOAT4` |
| `f64` | `FLOAT8` |
| `bool` | `BOOL` |
| `String` / `&str` | `TEXT` |
| `Vec<u8>` / `&[u8]` | `BYTEA` |
| `uuid::Uuid` | `UUID` |
| `chrono::DateTime<Utc>` | `TIMESTAMPTZ` |
| `Vec<T: ToSql>` | PG array |
| `&[T: ToSql]` | PG array |
| `Option<T: ToSql>` | NULL if `None` |
| `BindIter<I>` | PG array (zero-copy iterator) |

## Connection String

Supports a simple key=value format:

```
host=localhost port=5432 user=postgres dbname=mydb password=secret connect_timeout=10
```

Fields: `host` (default localhost), `port` (default 5432), `user` (required), `dbname`, `password`, `connect_timeout` (seconds, default 10).

## Auth

- **SCRAM-SHA-256** — modern, secure (uses the workspace `crypto` crate)
- **Cleartext password** — only with TLS enabled
- **MD5** — explicitly not supported (returns error with guidance)
