# jsonrpc

JSON-RPC 2.0 types and async server. Transport-agnostic, no I/O — the caller drives the wire.

## Features

- Zero-copy deferred parsing via `serde_json::value::RawValue`
- Generic `Server<C>` with typed async handler registration and automatic serde
- Spec-compliant batch request/response handling (including invalid batch entries)
- Notification support
- Owned context — `C` is cloned once per handler invocation (wrap in `Arc` for cheap clones)

## Examples

### Defining types

```rust
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct AddParams {
    a: i64,
    b: i64,
}

#[derive(Serialize)]
struct AddResult {
    sum: i64,
}
```

### Creating a server

```rust
use jsonrpc::{Error, Server};

// Context can be any Clone type your handlers need — DB pool, config, etc.
// Wrap expensive state in Arc for cheap clones.
#[derive(Clone)]
struct AppState {
    prefix: String,
}

let mut server: Server<AppState> = Server::new();

server.register("add", |ctx: AppState, params: AddParams| async move {
    Ok::<_, Error>(AddResult {
        sum: params.a + params.b,
    })
});
```

### Handling a single request

```rust
use jsonrpc::{Request, ResponseMessage};

// Parse a request from JSON received over a transport:
let json = r#"{"jsonrpc":"2.0","method":"add","params":{"a":3,"b":4},"id":1}"#;
let request: Request = serde_json::from_str(json).unwrap();
let message = jsonrpc::RequestMessage::Single(request);

let state = AppState { prefix: String::new() };
let response = server.handle(state, message).await;

// Serialize the response back to JSON for the transport:
if let Some(json) = response.to_json().unwrap() {
    println!("{}", json);
    // => {"jsonrpc":"2.0","result":{"sum":7},"id":1}
}
```

### Handling a notification

```rust
server.register("log", |_: AppState, msg: String| async move {
    println!("notification: {msg}");
    Ok::<_, Error>(())
});

// Notification has no "id" — server returns ResponseMessage::Empty
let json = r#"{"jsonrpc":"2.0","method":"log","params":"hello"}"#;
let request: Request = serde_json::from_str(json).unwrap();
let response = server.handle(&state, jsonrpc::RequestMessage::Single(request)).await;
assert!(matches!(response, ResponseMessage::Empty));
```

### Handling a batch

```rust
let json = r#"[
    {"jsonrpc":"2.0","method":"add","params":{"a":1,"b":2},"id":"1"},
    {"jsonrpc":"2.0","method":"add","params":{"a":3,"b":4},"id":"2"}
]"#;
let message: jsonrpc::RequestMessage = serde_json::from_str(json).unwrap();
let response = server.handle(state, message).await;
if let Some(json) = response.to_json().unwrap() {
    println!("{json}");
    // => [{"jsonrpc":"2.0","result":{"sum":3},"id":"1"},
    //     {"jsonrpc":"2.0","result":{"sum":7},"id":"2"}]
}
```

### Custom errors

```rust
use jsonrpc::Error;

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("division by zero")]
    DivisionByZero,
    #[error("database error: {0}")]
    Db(String),
}

impl From<AppError> for Error {
    fn from(e: AppError) -> Self {
        match &e {
            AppError::DivisionByZero => Error::new(-32000, e.to_string()),
            AppError::Db(message) => Error::new(-32001, format!("internal: {message}")),
        }
    }
}

server.register("div", |_: AppState, (a, b): (i64, i64)| async move {
    if b == 0 {
        Err(AppError::DivisionByZero)
    } else {
        Ok(a / b)
    }
});

// AppError is automatically converted via Into<Error>
```

### Axum integration (HTTP)

```rust
use std::sync::Arc;

use axum::{
    extract::{Json, State},
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use jsonrpc::{Error, Id, RequestMessage, Response, ResponseMessage, Server};
use serde_json::Value;

#[derive(Clone)]
struct AppState { /* ... */ }

async fn rpc_handler(
    State(server): State<Arc<Server<AppState>>>,
    State(state): State<Arc<AppState>>,
    payload: Result<Json<RequestMessage>, JsonRejection>,
) -> impl IntoResponse {
    let message = match payload {
        Ok(Json(p)) => p,
        Err(_) => {
            let err = Response::error(Id::Null, Error::parse_error());
            let value = serde_json::to_value(err).unwrap();
            return (StatusCode::OK, Json(value)).into_response();
        }
    };

    let response = server.handle((*state).clone(), message).await;
    match response.to_json().unwrap() {
        Some(json) => {
            let value: Value = serde_json::from_str(&json).unwrap();
            (StatusCode::OK, Json(value)).into_response()
        }
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

#[tokio::main]
async fn main() {
    let mut server: Server<AppState> = Server::new();
    server.register("ping", |_: AppState, ()| async move {
        Ok::<_, Error>("pong".to_string())
    });

    let server = Arc::new(server);
    let state = Arc::new(AppState {});

    let app = Router::new()
        .route("/rpc", post(rpc_handler))
        .with_state((Arc::clone(&server), Arc::clone(&state)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### TCP server sketch (newline-delimited, using `tokio`)

```rust
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut server: Server<()> = Server::new();
    server.register("ping", |_: (), ()| async move {
        Ok::<_, Error>("pong".to_string())
    });

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let message: jsonrpc::RequestMessage = match serde_json::from_str(&line) {
                Ok(p) => p,
                Err(_) => {
                    let err = jsonrpc::Response::error(
                        jsonrpc::Id::Null,
                        jsonrpc::Error::parse_error(),
                    );
                    let _ = writer.write_all(serde_json::to_string(&err).unwrap().as_bytes()).await;
                    let _ = writer.write_all(b"\n").await;
                    continue;
                }
            };

            let response = server.handle((), message).await;
            if let Some(json) = response.to_json().unwrap() {
                writer.write_all(json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }
        }
    }
}
```

## License

Apache-2.0
