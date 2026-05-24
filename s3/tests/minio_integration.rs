use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Read;

use s3::{Client, ClientConfig, Error, StaticCredentials};

fn integration_enabled() -> bool {
    std::env::var("S3_RUN_INTEGRATION").ok().as_deref() == Some("1")
}

fn env_or_default(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    nanos.to_string()
}

fn test_client() -> Client {
    let endpoint = env_or_default("S3_ENDPOINT", "http://127.0.0.1:9000");
    let region = env_or_default("S3_REGION", "us-east-1");
    let access_key_id = env_or_default("S3_ACCESS_KEY_ID", "minioadmin");
    let secret_access_key = env_or_default("S3_SECRET_ACCESS_KEY", "minioadmin");
    let session_token = std::env::var("S3_SESSION_TOKEN").unwrap_or_default();

    let cfg = ClientConfig {
        endpoint: &endpoint,
        credentials: StaticCredentials::new(&access_key_id, &secret_access_key, &session_token),
        region: &region,
    };

    Client::new(&cfg).expect("failed to build s3 client")
}

#[test]
fn minio_object_lifecycle() {
    if !integration_enabled() {
        eprintln!("skipping integration test (set S3_RUN_INTEGRATION=1)");
        return;
    }

    let client = test_client();
    let bucket = env_or_default("S3_TEST_BUCKET", "stdx-rs-s3-integration");

    match client.create_bucket(&bucket) {
        Ok(()) => {}
        Err(Error::Api { status: 409, .. }) => {}
        Err(err) => panic!("create_bucket failed: {err}"),
    }

    let key = format!("integration/{}/hello.txt", unique_suffix());
    let body = b"hello from stdx s3";

    client
        .put_object(&bucket, &key, body)
        .expect("put_object failed");

    let head = client
        .head_object(&bucket, &key)
        .expect("head_object failed");
    assert_eq!(head.content_length, Some(body.len() as u64));

    let mut got = client
        .get_object(&bucket, &key)
        .expect("get_object failed");
    let mut got_body = Vec::new();
    got.body
        .read_to_end(&mut got_body)
        .expect("failed reading object body stream");
    assert_eq!(got_body, body);

    let listed = client
        .list_objects(&bucket, Some("integration/"), None, Some(1000))
        .expect("list_objects failed");
    assert!(listed.contents.iter().any(|obj| obj.key == key));

    client
        .delete_object(&bucket, &key)
        .expect("delete_object failed");
}
