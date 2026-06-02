use jsonrpc::{Error, RequestPacket, Server};

#[tokio::main]
async fn main() {
    let mut server: Server<()> = Server::new();

    server.register("add", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a + b) });

    server.register("subtract", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a - b) });

    server.register("multiply", |_: (), (a, b): (i64, i64)| async move { Ok::<_, Error>(a * b) });

    server.register("divide", |_: (), (a, b): (i64, i64)| async move {
        if b == 0 {
            Err(Error::new(-32000, "division by zero"))
        } else {
            Ok(a / b)
        }
    });

    // --- Single requests ---

    let call = |method, params| {
        serde_json::from_str(&serde_json::json!({"jsonrpc":"2.0","method":method,"params":params,"id":1}).to_string())
            .unwrap()
    };

    let resp = server.handle((), RequestPacket::Single(call("add", [3, 4]))).await;
    println!("add(3, 4)  => {}", json_from_resp(&resp));

    let resp = server
        .handle((), RequestPacket::Single(call("subtract", [10, 3])))
        .await;
    println!("sub(10, 3) => {}", json_from_resp(&resp));

    let resp = server.handle((), RequestPacket::Single(call("multiply", [6, 7]))).await;
    println!("mul(6, 7)  => {}", json_from_resp(&resp));

    let resp = server.handle((), RequestPacket::Single(call("divide", [42, 6]))).await;
    println!("div(42, 6) => {}", json_from_resp(&resp));

    let resp = server.handle((), RequestPacket::Single(call("divide", [1, 0]))).await;
    println!("div(1, 0)  => {}", json_from_resp(&resp));

    // --- Notification (no response expected) ---

    let notif = serde_json::from_str(r#"{"jsonrpc":"2.0","method":"add","params":[1,1]}"#).unwrap();
    let resp = server.handle((), RequestPacket::Single(notif)).await;
    println!("notif      => {:?}", resp); // Empty

    // --- Method not found ---

    let resp = server
        .handle(
            (),
            RequestPacket::Single(serde_json::from_str(r#"{"jsonrpc":"2.0","method":"unknown","id":1}"#).unwrap()),
        )
        .await;
    println!("unknown    => {}", json_from_resp(&resp));

    // --- Batch ---

    let batch_json = r#"[
        {"jsonrpc":"2.0","method":"add","params":[1,2],"id":"a"},
        {"jsonrpc":"2.0","method":"multiply","params":[3,4],"id":"b"},
        {"jsonrpc":"2.0","method":"subtract","params":[10,7],"id":"c"}
    ]"#;
    let packet: RequestPacket = serde_json::from_str(batch_json).unwrap();
    let resp = server.handle((), packet).await;
    println!("batch      => {}", json_from_resp(&resp));
}

fn json_from_resp(packet: &jsonrpc::ResponsePacket) -> String {
    packet.to_json().unwrap().unwrap_or_else(|| "nothing".to_string())
}
