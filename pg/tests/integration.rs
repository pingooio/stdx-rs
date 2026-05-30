use std::{
    process::{Command, Stdio},
    time::Duration,
};

use pg::*;

const PG_IMAGE: &str = "postgres:16-alpine";

fn start_postgres() -> (String, u16) {
    let container_id = Command::new("docker")
        .args([
            "run",
            "-d",
            "-e",
            "POSTGRES_USER=testuser",
            "-e",
            "POSTGRES_PASSWORD=testpass",
            "-e",
            "POSTGRES_DB=testdb",
            "-P",
            PG_IMAGE,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("failed to start PostgreSQL container")
        .stdout;
    let cid = String::from_utf8_lossy(&container_id).trim().to_string();

    let port_output = Command::new("docker")
        .args(["port", &cid, "5432"])
        .stdout(Stdio::piped())
        .output()
        .expect("failed to get port")
        .stdout;
    let port_str = String::from_utf8_lossy(&port_output);
    let port: u16 = port_str
        .trim()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .expect("invalid port");

    std::thread::sleep(Duration::from_secs(3));

    (cid, port)
}

fn stop_postgres(cid: &str) {
    let _ = Command::new("docker")
        .args(["kill", cid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let _ = Command::new("docker")
        .args(["rm", "-f", cid])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output();
}

async fn wait_for_ready(params: &ConnectParams) -> pg::Connection {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match pg::Connection::connect(params).await {
            Ok(conn) => return conn,
            Err(_) => {
                if std::time::Instant::now() > deadline {
                    panic!("timed out waiting for PostgreSQL");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

fn make_params(port: u16) -> ConnectParams {
    ConnectParams {
        host: "localhost".to_string(),
        port,
        user: "testuser".to_string(),
        password: Some("testpass".to_string()),
        dbname: Some("testdb".to_string()),
        connect_timeout: Duration::from_secs(10),
    }
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_basic_query() {
    let (cid, port) = start_postgres();
    let params = make_params(port);
    let conn = wait_for_ready(&params).await;

    let rows = conn.query_raw("SELECT 1 AS num, 'hello' AS text", &[]).await.unwrap();
    assert_eq!(rows.len(), 1);
    let num: i32 = rows[0].try_get("num").unwrap();
    assert_eq!(num, 1);
    let text: String = rows[0].try_get("text").unwrap();
    assert_eq!(text, "hello");

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_parameterized_query() {
    let (cid, port) = start_postgres();
    let params = make_params(port);
    let conn = wait_for_ready(&params).await;

    conn.execute_raw(
        "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, age INT NOT NULL)",
        &[],
    )
    .await
    .unwrap();

    conn.execute_raw("INSERT INTO users (name, age) VALUES ($1, $2)", &[&"Alice".to_string(), &30i32])
        .await
        .unwrap();
    conn.execute_raw("INSERT INTO users (name, age) VALUES ($1, $2)", &[&"Bob".to_string(), &25i32])
        .await
        .unwrap();

    let rows = conn
        .query_raw("SELECT name, age FROM users ORDER BY id", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let name1: String = rows[0].try_get("name").unwrap();
    assert_eq!(name1, "Alice");
    let age1: i32 = rows[0].try_get("age").unwrap();
    assert_eq!(age1, 30);

    let rows = conn
        .query_raw("SELECT age FROM users WHERE name = $1", &[&"Bob".to_string()])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let age: i32 = rows[0].try_get("age").unwrap();
    assert_eq!(age, 25);

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_pool() {
    let (cid, port) = start_postgres();
    let params = make_params(port);

    let pool = Pool::connect_with_config(
        params,
        PoolConfig {
            min_connections: 1,
            max_connections: 5,
            ..PoolConfig::default()
        },
    )
    .await
    .unwrap();

    let conn = pool.get().await.unwrap();
    let rows = conn.query_raw("SELECT 42 AS val", &[]).await.unwrap();
    let val: i32 = rows[0].try_get("val").unwrap();
    assert_eq!(val, 42);

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_transaction() {
    let (cid, port) = start_postgres();
    let params = make_params(port);
    let conn = wait_for_ready(&params).await;

    conn.execute_raw("CREATE TABLE IF NOT EXISTS txn_test (id INT PRIMARY KEY, val TEXT)", &[])
        .await
        .unwrap();

    let txn = Transaction::begin(conn.clone()).await.unwrap();
    txn.execute_raw("INSERT INTO txn_test (id, val) VALUES ($1, $2)", &[&1i32, &"hello".to_string()])
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let rows = conn
        .query_raw("SELECT val FROM txn_test WHERE id = $1", &[&1i32])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let val: String = rows[0].try_get("val").unwrap();
    assert_eq!(val, "hello");

    let txn = Transaction::begin(conn.clone()).await.unwrap();
    txn.execute_raw("INSERT INTO txn_test (id, val) VALUES ($1, $2)", &[&2i32, &"world".to_string()])
        .await
        .unwrap();
    txn.rollback().await.unwrap();

    let rows = conn
        .query_raw("SELECT val FROM txn_test WHERE id = $1", &[&2i32])
        .await
        .unwrap();
    assert_eq!(rows.len(), 0);

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_from_row() {
    let (cid, port) = start_postgres();
    let params = make_params(port);
    let conn = wait_for_ready(&params).await;

    conn.execute_raw(
        "CREATE TABLE IF NOT EXISTS staff (id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT)",
        &[],
    )
    .await
    .unwrap();
    conn.execute_raw(
        "INSERT INTO staff (name, email) VALUES ($1, $2)",
        &[&"Alice".to_string(), &"alice@example.com".to_string()],
    )
    .await
    .unwrap();
    conn.execute_raw(
        "INSERT INTO staff (name, email) VALUES ($1, $2)",
        &[&"Bob".to_string(), &Option::<String>::None],
    )
    .await
    .unwrap();

    #[derive(Debug, PartialEq, pg::FromRow)]
    struct Staff {
        id: i32,
        name: String,
        email: Option<String>,
    }

    let staff_list: Vec<Staff> = conn
        .query_as::<Staff>("SELECT id, name, email FROM staff ORDER BY id", &[])
        .await
        .unwrap();

    assert_eq!(staff_list.len(), 2);
    assert_eq!(staff_list[0].id, 1);
    assert_eq!(staff_list[0].name, "Alice");
    assert_eq!(staff_list[0].email, Some("alice@example.com".to_string()));
    assert_eq!(staff_list[1].id, 2);
    assert_eq!(staff_list[1].name, "Bob");
    assert_eq!(staff_list[1].email, None);

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_vec_binding() {
    let (cid, port) = start_postgres();
    let params = make_params(port);
    let conn = wait_for_ready(&params).await;

    conn.execute_raw("CREATE TABLE IF NOT EXISTS vec_test (id INT PRIMARY KEY, val INT)", &[])
        .await
        .unwrap();
    conn.execute_raw("INSERT INTO vec_test VALUES (1, 10), (2, 20), (3, 30)", &[])
        .await
        .unwrap();

    let ids = vec![1i32, 3];
    let rows = conn
        .query_raw("SELECT id, val FROM vec_test WHERE id = ANY($1::int[]) ORDER BY id", &[&ids])
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let id1: i32 = rows[0].try_get("id").unwrap();
    assert_eq!(id1, 1);
    let id2: i32 = rows[1].try_get("id").unwrap();
    assert_eq!(id2, 3);

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_pool_begin_transaction() {
    let (cid, port) = start_postgres();
    let params = make_params(port);

    let pool = Pool::connect_with_config(
        params,
        PoolConfig {
            min_connections: 1,
            max_connections: 5,
            ..PoolConfig::default()
        },
    )
    .await
    .unwrap();

    pool.execute_raw("CREATE TABLE IF NOT EXISTS pool_txn (id INT PRIMARY KEY, val TEXT)", &[])
        .await
        .unwrap();

    let txn = pool.begin().await.unwrap();
    txn.execute_raw(
        "INSERT INTO pool_txn (id, val) VALUES ($1, $2)",
        &[&1i32, &"pooled".to_string()],
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let rows = pool
        .query_raw("SELECT val FROM pool_txn WHERE id = $1", &[&1i32])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let val: String = rows[0].try_get("val").unwrap();
    assert_eq!(val, "pooled");

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_pool_queryer_trait() {
    let (cid, port) = start_postgres();
    let params = make_params(port);

    let pool = Pool::connect_with_config(
        params,
        PoolConfig {
            min_connections: 1,
            max_connections: 5,
            ..PoolConfig::default()
        },
    )
    .await
    .unwrap();

    let val: Option<i32> = pool.query_first("SELECT 99", &[]).await.unwrap();
    assert_eq!(val, Some(99));

    stop_postgres(&cid);
}

#[tokio::test]
#[ignore = "requires docker"]
async fn integration_test_connection_acquire_after_close() {
    let (cid, port) = start_postgres();
    let params = make_params(port);

    let pool = Pool::connect_with_config(
        params,
        PoolConfig {
            min_connections: 0,
            max_connections: 3,
            ..PoolConfig::default()
        },
    )
    .await
    .unwrap();

    let conn = pool.get().await.unwrap();
    let rows = conn.query_raw("SELECT 1 AS ok", &[]).await.unwrap();
    let val: i32 = rows[0].try_get("ok").unwrap();
    assert_eq!(val, 1);
    drop(conn);

    pool.close().await;
    let result = pool.get().await;
    assert!(result.is_err());
    match result {
        Err(PgError::PoolClosed) => {}
        _ => panic!("expected PoolClosed error"),
    }

    stop_postgres(&cid);
}
