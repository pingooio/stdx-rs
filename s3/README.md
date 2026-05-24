# s3

Minimal S3 client SDK for `stdx-rs`, focused on common actions:

- `CreateBucket`
- `PutObject`
- `GetObject`
- `HeadObject`
- `DeleteObject`
- `ListObjects` (ListObjectsV2)
- `CreateMultipartUpload` / `UploadPart` / `CompleteMultipartUpload` / `AbortMultipartUpload`

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

### 1. Start MinIO

```bash
docker run -d --name minio \
  -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data
```

### 2. Run integration tests

```bash
make -C s3 integration-test
```

### 3. Stop and remove MinIO

```bash
docker stop minio && docker rm minio
```
