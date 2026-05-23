# s3

Minimal S3 client SDK for `stdx-rs`, focused on common actions:

- `CreateBucket`
- `PutObject`
- `GetObject`
- `HeadObject`
- `DeleteObject`
- `ListObjects` (ListObjectsV2)

## API

```rust
use s3::{Client, ClientConfig, StaticCredentials};

let cfg = ClientConfig {
    endpoint: "http://127.0.0.1:9000",
    credentials: StaticCredentials::new("minioadmin", "minioadmin", ""),
    region: "us-east-1",
};

let client = Client::new(&cfg)?;
```

## Integration tests (MinIO)

The Makefile sets default env vars but does **not** start MinIO.

```bash
make -C s3 integration-test
```

Example MinIO image: `minio/minio`.
