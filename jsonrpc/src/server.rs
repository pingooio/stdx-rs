use std::{collections::HashMap, future::Future, marker::PhantomData, pin::Pin, sync::Arc};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;

use crate::{Error, ErrorCode, Id, Request, RequestPacket, Response};

trait MethodHandler<C>: Send + Sync {
    fn call(&self, ctx: C, params: &RawValue) -> Pin<Box<dyn Future<Output = Result<Box<RawValue>, Error>> + Send>>;
}

struct MethodHandlerImpl<C, H, P, R, E, F> {
    handler: H,
    _phantom: PhantomData<fn(C, P) -> (R, E, F)>,
}

impl<C, P, R, E, F, H> MethodHandler<C> for MethodHandlerImpl<C, H, P, R, E, F>
where
    C: Send + 'static,
    P: DeserializeOwned + Send,
    R: Serialize + Send,
    E: Into<Error> + Send,
    F: Future<Output = Result<R, E>> + Send + 'static,
    H: Fn(C, P) -> F + Send + Sync,
{
    fn call(
        &self,
        ctx: C,
        raw_params: &RawValue,
    ) -> Pin<Box<dyn Future<Output = Result<Box<RawValue>, Error>> + Send>> {
        let params: P = match serde_json::from_str(raw_params.get()) {
            Ok(p) => p,
            Err(e) => {
                return Box::pin(async move { Err(Error::invalid_params(e.to_string())) });
            }
        };
        let fut = (self.handler)(ctx, params);
        Box::pin(async move {
            match fut.await {
                Ok(result) => serde_json::value::to_raw_value(&result)
                    .map_err(|e| Error::new(ErrorCode::INTERNAL_ERROR, e.to_string())),
                Err(e) => Err(e.into()),
            }
        })
    }
}

/// The output of [`Server::handle`].
///
/// An `Empty` variant means nothing should be sent back (e.g., all-notification batch).
#[derive(Clone, Debug)]
pub enum ResponsePacket {
    /// A single response.
    Single(Response),
    /// A batch of responses.
    Batch(Vec<Response>),
    /// No response to send (notification, or all-notification batch).
    Empty,
}

impl ResponsePacket {
    /// Serializes this packet into a JSON string suitable for writing to a transport.
    ///
    /// For `Empty` variants, returns `None`.
    /// For `Single`, returns the serialized `Response`.
    /// For `Batch`, returns the serialized array.
    pub fn to_json(&self) -> serde_json::Result<Option<String>> {
        match self {
            Self::Empty => Ok(None),
            Self::Single(resp) => serde_json::to_string(resp).map(Some),
            Self::Batch(resps) => {
                if resps.is_empty() {
                    Ok(None)
                } else {
                    serde_json::to_string(resps).map(Some)
                }
            }
        }
    }
}

/// A JSON-RPC 2.0 server.
///
/// Generic over a context type `C` that is cloned once per handler invocation.
///
/// # Example
///
/// ```rust
/// use jsonrpc::{Server, Error};
///
/// let mut server = Server::new();
/// server.register("add", |_: (), (a, b): (i64, i64)| async move {
///     Ok::<_, Error>(a + b)
/// });
/// ```
pub struct Server<C> {
    methods: HashMap<String, Arc<dyn MethodHandler<C>>>,
    empty_params: Box<RawValue>,
}

impl<C: Send + Sync + 'static> Server<C> {
    /// Creates a new server with no registered methods.
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
            empty_params: RawValue::from_string("{}".to_owned()).expect("{} is valid JSON"),
        }
    }

    /// Registers an async handler for the given method name.
    ///
    /// The handler receives an owned clone of the context and deserialized
    /// method parameters, and returns a future.
    pub fn register<P, R, E, F>(
        &mut self,
        method: impl Into<String>,
        handler: impl Fn(C, P) -> F + Send + Sync + 'static,
    ) where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + Send + 'static,
        E: Into<Error> + Send + 'static,
        F: Future<Output = Result<R, E>> + Send + 'static,
    {
        let entry = MethodHandlerImpl::<C, _, P, R, E, F> {
            handler,
            _phantom: PhantomData,
        };
        self.methods.insert(method.into(), Arc::new(entry));
    }

    /// Handles a request packet and returns the corresponding response packet.
    ///
    /// The context `ctx` is consumed and, for batches, cloned once per handler invocation.
    pub async fn handle(&self, ctx: C, packet: RequestPacket) -> ResponsePacket
    where
        C: Clone,
    {
        match packet {
            RequestPacket::Single(req) => self.handle_single(ctx, req).await,
            RequestPacket::Batch(entries) => self.handle_batch(ctx, entries).await,
        }
    }

    async fn handle_single(&self, ctx: C, req: Request) -> ResponsePacket {
        let Some(id) = req.id.into_id() else {
            let _ = self
                .dispatch(ctx, &req.method, req.params.as_deref().unwrap_or(&self.empty_params))
                .await;
            return ResponsePacket::Empty;
        };

        let params = req.params.as_deref().unwrap_or(&self.empty_params);
        match self.dispatch(ctx, &req.method, params).await {
            Ok(result) => ResponsePacket::Single(Response::Success {
                result,
                id,
            }),
            Err(error) => ResponsePacket::Single(Response::Error {
                error,
                id,
            }),
        }
    }

    async fn handle_batch(&self, ctx: C, entries: Vec<Box<RawValue>>) -> ResponsePacket
    where
        C: Clone,
    {
        if entries.is_empty() {
            return ResponsePacket::Single(Response::Error {
                error: Error::invalid_request("empty batch"),
                id: Id::Null,
            });
        }

        let mut responses: Vec<Response> = Vec::with_capacity(entries.len());

        for entry in entries {
            let req: Request = match serde_json::from_str(entry.get()) {
                Ok(req) => req,
                Err(_) => {
                    responses.push(Response::Error {
                        error: Error::invalid_request("invalid request in batch"),
                        id: Id::Null,
                    });
                    continue;
                }
            };

            let Some(id) = req.id.into_id() else {
                let _ = self
                    .dispatch(ctx.clone(), &req.method, req.params.as_deref().unwrap_or(&self.empty_params))
                    .await;
                continue;
            };

            let params = req.params.as_deref().unwrap_or(&self.empty_params);
            match self.dispatch(ctx.clone(), &req.method, params).await {
                Ok(result) => responses.push(Response::Success {
                    result,
                    id,
                }),
                Err(error) => responses.push(Response::Error {
                    error,
                    id,
                }),
            }
        }

        if responses.is_empty() {
            ResponsePacket::Empty
        } else {
            ResponsePacket::Batch(responses)
        }
    }

    async fn dispatch(&self, ctx: C, method: &str, params: &RawValue) -> Result<Box<RawValue>, Error> {
        let callback = self
            .methods
            .get(method)
            .ok_or_else(|| Error::method_not_found(method))?;
        callback.call(ctx, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorCode, RequestId};

    fn make_request(method: &str, params: Option<&str>, id: Option<i64>) -> Request {
        Request {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params: params.map(|s| RawValue::from_string(s.to_owned()).unwrap()),
            id: RequestId(id.map(Id::Number)),
        }
    }

    #[tokio::test]
    async fn test_simple_handler() {
        let mut server: Server<()> = Server::new();
        server.register("add", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a + b) });

        let req = make_request("add", Some("[3, 4]"), Some(1));
        let packet = server.handle((), RequestPacket::Single(req)).await;

        match packet {
            ResponsePacket::Single(Response::Success {
                result,
                id,
            }) => {
                assert_eq!(id, Id::Number(1));
                let v: i64 = serde_json::from_str(result.get()).unwrap();
                assert_eq!(v, 7);
            }
            other => panic!("expected success response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handler_with_error() {
        let mut server: Server<()> = Server::new();
        server.register("div", |_: (), (a, b): (i64, i64)| async move {
            if b == 0 {
                Err(Error::new(-32000, "division by zero"))
            } else {
                Ok(a / b)
            }
        });

        let req = make_request("div", Some("[4, 0]"), Some(1));
        let packet = server.handle((), RequestPacket::Single(req)).await;

        match packet {
            ResponsePacket::Single(Response::Error {
                error,
                id,
            }) => {
                assert_eq!(id, Id::Number(1));
                assert_eq!(error.code, -32000);
                assert_eq!(error.message, "division by zero");
            }
            other => panic!("expected error response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let server: Server<()> = Server::new();
        let req = make_request("unknown", None, Some(1));
        let packet = server.handle((), RequestPacket::Single(req)).await;

        match packet {
            ResponsePacket::Single(Response::Error {
                error,
                id,
            }) => {
                assert_eq!(id, Id::Number(1));
                assert_eq!(error.code, ErrorCode::METHOD_NOT_FOUND);
            }
            other => panic!("expected error response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_invalid_params() {
        let mut server: Server<()> = Server::new();
        server.register("add", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a + b) });

        let req = make_request("add", Some(r#""not_an_array""#), Some(1));
        let packet = server.handle((), RequestPacket::Single(req)).await;

        match packet {
            ResponsePacket::Single(Response::Error {
                error,
                id,
            }) => {
                assert_eq!(id, Id::Number(1));
                assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
            }
            other => panic!("expected error response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_notification_is_silent() {
        let mut server: Server<()> = Server::new();
        server.register("log", |_: (), _msg: (String,)| async move { Ok::<_, Error>(()) });

        let req = make_request("log", Some(r#"["hello"]"#), None);
        let packet = server.handle((), RequestPacket::Single(req)).await;

        assert!(matches!(packet, ResponsePacket::Empty));
    }

    #[tokio::test]
    async fn test_empty_batch() {
        let server: Server<()> = Server::new();
        let packet = server.handle((), RequestPacket::Batch(vec![])).await;

        match packet {
            ResponsePacket::Single(Response::Error {
                error,
                id,
            }) => {
                assert_eq!(id, Id::Null);
                assert_eq!(error.code, ErrorCode::INVALID_REQUEST);
            }
            other => panic!("expected single error for empty batch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_batch_mixed() {
        let mut server: Server<()> = Server::new();
        server.register("add", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a + b) });

        let entries = vec![
            RawValue::from_string(
                serde_json::json!({"jsonrpc":"2.0","method":"add","params":[1,2],"id":1}).to_string(),
            )
            .unwrap(),
            RawValue::from_string(serde_json::json!({"jsonrpc":"2.0","method":"add","params":[3,4]}).to_string())
                .unwrap(),
            RawValue::from_string(
                serde_json::json!({"jsonrpc":"2.0","method":"add","params":[5,6],"id":2}).to_string(),
            )
            .unwrap(),
        ];

        let packet = server.handle((), RequestPacket::Batch(entries)).await;

        match packet {
            ResponsePacket::Batch(responses) => {
                assert_eq!(responses.len(), 2);
            }
            other => panic!("expected batch response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_batch_with_invalid_entry() {
        let mut server: Server<()> = Server::new();
        server.register("add", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a + b) });

        let entries = vec![
            RawValue::from_string(
                serde_json::json!({"jsonrpc":"2.0","method":"add","params":[1,2],"id":1}).to_string(),
            )
            .unwrap(),
            RawValue::from_string("42".to_owned()).unwrap(),
            RawValue::from_string(
                serde_json::json!({"jsonrpc":"2.0","method":"add","params":[3,4],"id":2}).to_string(),
            )
            .unwrap(),
        ];

        let packet = server.handle((), RequestPacket::Batch(entries)).await;

        match packet {
            ResponsePacket::Batch(responses) => {
                assert_eq!(responses.len(), 3);
                assert!(responses[0].is_success());
                assert!(responses[1].is_error());
                assert_eq!(responses[1].error_ref().unwrap().code, ErrorCode::INVALID_REQUEST);
                assert_eq!(responses[1].id(), &Id::Null);
                assert!(responses[2].is_success());
            }
            other => panic!("expected batch response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_all_notification_batch_is_empty() {
        let mut server: Server<()> = Server::new();
        server.register("notify", |_: (), _msg: (String,)| async move { Ok::<_, Error>(()) });

        let entries = vec![
            RawValue::from_string(serde_json::json!({"jsonrpc":"2.0","method":"notify","params":["a"]}).to_string())
                .unwrap(),
            RawValue::from_string(serde_json::json!({"jsonrpc":"2.0","method":"notify","params":["b"]}).to_string())
                .unwrap(),
        ];

        let packet = server.handle((), RequestPacket::Batch(entries)).await;
        assert!(matches!(packet, ResponsePacket::Empty));
    }

    #[test]
    fn test_response_packet_to_json_single() {
        let resp = Response::success(Id::Number(1), 42).unwrap();
        let packet = ResponsePacket::Single(resp);
        let json = packet.to_json().unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["result"], serde_json::json!(42));
    }

    #[test]
    fn test_response_packet_to_json_empty() {
        let packet: ResponsePacket = ResponsePacket::Empty;
        assert!(packet.to_json().unwrap().is_none());
    }

    #[test]
    fn test_response_packet_to_json_batch() {
        let resps = vec![
            Response::success(Id::Number(1), 10).unwrap(),
            Response::success(Id::Number(2), 20).unwrap(),
        ];
        let packet = ResponsePacket::Batch(resps);
        let json = packet.to_json().unwrap().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_handler_with_context() {
        #[derive(Clone)]
        struct State {
            base: i64,
        }

        let mut server: Server<State> = Server::new();
        server.register("add", |ctx: State, (x,): (i64,)| async move { Ok::<_, Error>(ctx.base + x) });

        let state = State {
            base: 100,
        };
        let req = make_request("add", Some("[5]"), Some(1));
        let packet = server.handle(state, RequestPacket::Single(req)).await;

        match packet {
            ResponsePacket::Single(Response::Success {
                result, ..
            }) => {
                let v: i64 = serde_json::from_str(result.get()).unwrap();
                assert_eq!(v, 105);
            }
            other => panic!("expected success, got {other:?}"),
        }
    }
}
