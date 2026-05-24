# s3

Minimal S3 client SDK for `stdx-rs`, focused on common actions.

Based on commonly used S3 request categories and API operations in AWS docs (pricing request classes and S3 API operations list), this crate supports these 20 operations:

1. `ListBuckets`
2. `CreateBucket`
3. `HeadBucket`
4. `DeleteBucket`
5. `GetBucketLocation`
6. `ListObjects` (ListObjectsV2)
7. `PutObject`
8. `GetObject`
9. `HeadObject`
10. `DeleteObject`
11. `DeleteObjects`
12. `CreateMultipartUpload`
13. `UploadPart`
14. `ListParts`
15. `CompleteMultipartUpload`
16. `AbortMultipartUpload`
17. `ListMultipartUploads`
18. `PutObjectTagging`
19. `GetObjectTagging`
20. `DeleteObjectTagging`

References:
- https://aws.amazon.com/s3/pricing/
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html

## API

```rust
use s3::{Client, ClientConfig, StaticCredentials};

let cfg = ClientConfig {
    endpoint: "http://127.0.0.1:9000",
    credentials: StaticCredentials::new("minioadmin", "minioadmin", ""),
    region: "auto",
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
