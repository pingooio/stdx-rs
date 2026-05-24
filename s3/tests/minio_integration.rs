#![cfg(feature = "reqwest")]

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::TryStreamExt;
use s3::{Client, ClientConfig, CompletedPart, Error, ReqwestHttpClient, StaticCredentials};

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

fn test_client() -> Client<ReqwestHttpClient> {
    let endpoint = env_or_default("S3_ENDPOINT", "http://127.0.0.1:9000");
    let region = env_or_default("S3_REGION", "auto");
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

async fn collect_stream(body: s3::ByteStream) -> Vec<u8> {
    let chunks: Vec<Bytes> = body.try_collect().await.expect("failed to collect body stream");
    chunks.into_iter().flat_map(|b| b.into_iter()).collect()
}

#[tokio::test]
async fn minio_object_lifecycle() {
    if !integration_enabled() {
        eprintln!("skipping integration test (set S3_RUN_INTEGRATION=1)");
        return;
    }

    let client = test_client();
    let bucket = env_or_default("S3_TEST_BUCKET", "stdx-rs-s3-integration");

    match client.create_bucket(&bucket).await {
        Ok(()) => {}
        Err(Error::Api { status: 409, .. }) => {}
        Err(err) => panic!("create_bucket failed: {err}"),
    }

    let key = format!("integration/{}/hello.txt", unique_suffix());
    let body = b"hello from stdx s3";

    client.put_object(&bucket, &key, body).await.expect("put_object failed");

    let head = client.head_object(&bucket, &key).await.expect("head_object failed");
    assert_eq!(head.content_length, Some(body.len() as u64));

    let got = client.get_object(&bucket, &key).await.expect("get_object failed");
    assert_eq!(collect_stream(got.body).await, body.as_ref());

    let listed = client
        .list_objects(&bucket, Some("integration/"), None, Some(1000))
        .await
        .expect("list_objects failed");
    assert!(listed.contents.iter().any(|obj| obj.key == key));

    client.delete_object(&bucket, &key).await.expect("delete_object failed");
}

#[tokio::test]
async fn minio_multipart_upload() {
    if !integration_enabled() {
        eprintln!("skipping integration test (set S3_RUN_INTEGRATION=1)");
        return;
    }

    let client = test_client();
    let bucket = env_or_default("S3_TEST_BUCKET", "stdx-rs-s3-integration");

    match client.create_bucket(&bucket).await {
        Ok(()) => {}
        Err(Error::Api { status: 409, .. }) => {}
        Err(err) => panic!("create_bucket failed: {err}"),
    }

    let key = format!("integration/{}/multipart.bin", unique_suffix());

    // S3 requires every part except the last to be at least 5 MiB.
    let part1: Vec<u8> = vec![b'A'; 5 * 1024 * 1024];
    let part2: Vec<u8> = vec![b'B'; 1024];

    let upload_id = client
        .create_multipart_upload(&bucket, &key)
        .await
        .expect("create_multipart_upload failed");

    let out1 = client
        .upload_part(&bucket, &key, &upload_id, 1, &part1)
        .await
        .expect("upload_part 1 failed");
    let out2 = client
        .upload_part(&bucket, &key, &upload_id, 2, &part2)
        .await
        .expect("upload_part 2 failed");

    let parts = vec![
        CompletedPart {
            part_number: 1,
            e_tag: out1.e_tag.expect("part 1 etag missing"),
        },
        CompletedPart {
            part_number: 2,
            e_tag: out2.e_tag.expect("part 2 etag missing"),
        },
    ];

    client
        .complete_multipart_upload(&bucket, &key, &upload_id, &parts)
        .await
        .expect("complete_multipart_upload failed");

    let head = client
        .head_object(&bucket, &key)
        .await
        .expect("head_object after multipart failed");
    let expected_len = (part1.len() + part2.len()) as u64;
    assert_eq!(head.content_length, Some(expected_len));

    let got = client
        .get_object(&bucket, &key)
        .await
        .expect("get_object after multipart failed");
    let mut expected = part1;
    expected.extend_from_slice(&part2);
    assert_eq!(collect_stream(got.body).await, expected);

    client
        .delete_object(&bucket, &key)
        .await
        .expect("delete_object after multipart failed");
}
