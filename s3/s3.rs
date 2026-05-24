pub mod buckets;
pub mod client;
pub mod objects;

pub use buckets::{Bucket, GetBucketLocationOutput, ListBucketsOutput, ListObject, ListObjectsOutput};
pub use client::{
    ByteStream, Client, ClientConfig, Error, HttpClient, HttpError, HttpMethod, HttpRequest, HttpResponseData,
    ReqwestHttpClient, StaticCredentials,
};
pub use objects::{
    CompleteMultipartUploadOutput, CompletedPart, DeleteObjectsError, DeleteObjectsOutput, DeletedObject,
    GetObjectOutput, GetObjectTaggingOutput, HeadObjectOutput, ListMultipartUploadsOutput, ListPartsOutput,
    MultipartUpload, Tag, UploadPartOutput, UploadedPart,
};
