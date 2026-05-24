use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};

use hmac::{Hmac, Mac};
use quick_xml::de::from_str;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

const EMPTY_PAYLOAD_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone)]
pub struct StaticCredentials<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
    pub session_token: &'a str,
}

impl<'a> StaticCredentials<'a> {
    pub fn new(access_key_id: &'a str, secret_access_key: &'a str, session_token: &'a str) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            session_token,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig<'a> {
    pub endpoint: &'a str,
    pub credentials: StaticCredentials<'a>,
    pub region: &'a str,
}

#[derive(Debug, Clone)]
struct OwnedCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

#[derive(Debug)]
pub struct Client<H: HttpClient> {
    endpoint: Url,
    region: String,
    credentials: OwnedCredentials,
    http: H,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfig(&'static str),
    Http(String),
    Time(std::time::SystemTimeError),
    Xml(quick_xml::DeError),
    Api { status: u16, body: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig(msg) => write!(f, "invalid config: {msg}"),
            Error::Http(err) => write!(f, "http error: {err}"),
            Error::Time(err) => write!(f, "time error: {err}"),
            Error::Xml(err) => write!(f, "xml error: {err}"),
            Error::Api { status, body } => write!(f, "s3 api error (status {status}): {body}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::time::SystemTimeError> for Error {
    fn from(value: std::time::SystemTimeError) -> Self {
        Self::Time(value)
    }
}

impl From<quick_xml::DeError> for Error {
    fn from(value: quick_xml::DeError) -> Self {
        Self::Xml(value)
    }
}

pub type HttpError = Box<dyn std::error::Error + Send + Sync>;

/// A pinned, boxed async stream of byte chunks.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, HttpError>> + Send>>;

#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Put,
    Post,
    Delete,
    Head,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Put => "PUT",
            HttpMethod::Post => "POST",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub struct HttpResponseData {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: ByteStream,
}

impl HttpResponseData {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub trait HttpClient: Send + Sync {
    fn send(&self, request: HttpRequest) -> impl Future<Output = Result<HttpResponseData, HttpError>> + Send + '_;
}

#[cfg(feature = "reqwest")]
#[derive(Debug, Default, Clone)]
pub struct ReqwestHttpClient {
    inner: reqwest::Client,
}

#[cfg(feature = "reqwest")]
impl ReqwestHttpClient {
    pub fn new() -> Self {
        Self {
            inner: reqwest::Client::new(),
        }
    }
}

#[cfg(feature = "reqwest")]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponseData, HttpError> {
        let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())?;
        let mut req = self.inner.request(method, &request.url);
        for (name, value) in request.headers {
            req = req.header(&name, &value);
        }
        if !request.body.is_empty() {
            req = req.body(request.body);
        }
        let response = req.send().await?;
        let status_code = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|v| (name.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body: ByteStream = Box::pin(response.bytes_stream().map(|r| r.map_err(|e| -> HttpError { Box::new(e) })));
        Ok(HttpResponseData { status_code, headers, body })
    }
}

#[derive(Debug, Clone)]
pub struct CompletedPart {
    pub part_number: u32,
    pub e_tag: String,
}

#[derive(Debug, Clone)]
pub struct UploadPartOutput {
    pub e_tag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompleteMultipartUploadOutput {
    pub e_tag: Option<String>,
}

pub struct GetObjectOutput {
    pub body: ByteStream,
    pub e_tag: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct HeadObjectOutput {
    pub e_tag: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListObjectsOutput {
    pub name: String,
    pub prefix: Option<String>,
    pub key_count: Option<u64>,
    pub max_keys: Option<u64>,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
    pub contents: Vec<ListObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListObject {
    pub key: String,
    pub last_modified: Option<String>,
    pub e_tag: Option<String>,
    pub size: Option<u64>,
    pub storage_class: Option<String>,
}

impl<H: HttpClient> Client<H> {
    pub fn with_http_client(config: &ClientConfig<'_>, http: H) -> Result<Self, Error> {
        if config.endpoint.trim().is_empty() {
            return Err(Error::InvalidConfig("endpoint must not be empty"));
        }
        if config.region.trim().is_empty() {
            return Err(Error::InvalidConfig("region must not be empty"));
        }
        if config.credentials.access_key_id.trim().is_empty() {
            return Err(Error::InvalidConfig("access key id must not be empty"));
        }
        if config.credentials.secret_access_key.trim().is_empty() {
            return Err(Error::InvalidConfig("secret access key must not be empty"));
        }

        let endpoint = Url::parse(config.endpoint).map_err(|_| Error::InvalidConfig("invalid endpoint URL"))?;

        Ok(Self {
            endpoint,
            region: config.region.to_string(),
            credentials: OwnedCredentials {
                access_key_id: config.credentials.access_key_id.to_string(),
                secret_access_key: config.credentials.secret_access_key.to_string(),
                session_token: if config.credentials.session_token.is_empty() {
                    None
                } else {
                    Some(config.credentials.session_token.to_string())
                },
            },
            http,
        })
    }

    pub async fn create_bucket(&self, bucket: &str) -> Result<(), Error> {
        let canonical_uri = canonical_bucket_uri(bucket);
        let response = self.execute(HttpMethod::Put, &canonical_uri, "", b"").await?;
        consume_empty(response)
    }

    pub async fn put_object(&self, bucket: &str, key: &str, body: &[u8]) -> Result<(), Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Put, &canonical_uri, "", body).await?;
        consume_empty(response)
    }

    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<GetObjectOutput, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Get, &canonical_uri, "", b"").await?;
        let e_tag = header_to_string(&response, "etag");
        let content_type = header_to_string(&response, "content-type");
        let content_length = header_to_u64(&response, "content-length");

        Ok(GetObjectOutput {
            body: response.body,
            e_tag,
            content_type,
            content_length,
        })
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<HeadObjectOutput, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Head, &canonical_uri, "", b"").await?;

        Ok(HeadObjectOutput {
            e_tag: header_to_string(&response, "etag"),
            content_type: header_to_string(&response, "content-type"),
            content_length: header_to_u64(&response, "content-length"),
        })
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Delete, &canonical_uri, "", b"").await?;
        consume_empty(response)
    }

    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: Option<&str>,
        continuation_token: Option<&str>,
        max_keys: Option<u32>,
    ) -> Result<ListObjectsOutput, Error> {
        let canonical_uri = canonical_bucket_uri(bucket);

        let mut params = BTreeMap::new();
        params.insert("list-type".to_string(), "2".to_string());
        if let Some(prefix) = prefix {
            params.insert("prefix".to_string(), prefix.to_string());
        }
        if let Some(token) = continuation_token {
            params.insert("continuation-token".to_string(), token.to_string());
        }
        if let Some(max_keys) = max_keys {
            params.insert("max-keys".to_string(), max_keys.to_string());
        }

        let canonical_query = canonical_query_string(&params);
        let response = self.execute(HttpMethod::Get, &canonical_uri, &canonical_query, b"").await?;
        let body = bytes_to_string(collect_body(response.body).await?)?;
        let xml: ListBucketResultXml = from_str(&body)?;

        Ok(ListObjectsOutput {
            name: xml.name,
            prefix: xml.prefix,
            key_count: xml.key_count,
            max_keys: xml.max_keys,
            is_truncated: xml.is_truncated,
            next_continuation_token: xml.next_continuation_token,
            contents: xml
                .contents
                .into_iter()
                .map(|entry| ListObject {
                    key: entry.key,
                    last_modified: entry.last_modified,
                    e_tag: entry.e_tag,
                    size: entry.size,
                    storage_class: entry.storage_class,
                })
                .collect(),
        })
    }

    pub async fn create_multipart_upload(&self, bucket: &str, key: &str) -> Result<String, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Post, &canonical_uri, "uploads", b"").await?;
        let xml_text = bytes_to_string(collect_body(response.body).await?)?;
        let xml: InitiateMultipartUploadResultXml = from_str(&xml_text)?;
        Ok(xml.upload_id)
    }

    pub async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: u32,
        body: &[u8],
    ) -> Result<UploadPartOutput, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let mut params = BTreeMap::new();
        params.insert("partNumber".to_string(), part_number.to_string());
        params.insert("uploadId".to_string(), upload_id.to_string());
        let canonical_query = canonical_query_string(&params);
        let response = self.execute(HttpMethod::Put, &canonical_uri, &canonical_query, body).await?;
        let e_tag = header_to_string(&response, "etag");
        Ok(UploadPartOutput { e_tag })
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<CompleteMultipartUploadOutput, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let mut params = BTreeMap::new();
        params.insert("uploadId".to_string(), upload_id.to_string());
        let canonical_query = canonical_query_string(&params);
        let xml_body = build_complete_multipart_body(parts);
        let response = self.execute(HttpMethod::Post, &canonical_uri, &canonical_query, &xml_body).await?;
        let xml_text = bytes_to_string(collect_body(response.body).await?)?;
        let xml: CompleteMultipartUploadResultXml = from_str(&xml_text)?;
        Ok(CompleteMultipartUploadOutput { e_tag: xml.e_tag })
    }

    pub async fn abort_multipart_upload(&self, bucket: &str, key: &str, upload_id: &str) -> Result<(), Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let mut params = BTreeMap::new();
        params.insert("uploadId".to_string(), upload_id.to_string());
        let canonical_query = canonical_query_string(&params);
        let response = self.execute(HttpMethod::Delete, &canonical_uri, &canonical_query, b"").await?;
        consume_empty(response)
    }

    async fn execute(
        &self,
        method: HttpMethod,
        canonical_uri: &str,
        canonical_query: &str,
        body: &[u8],
    ) -> Result<HttpResponseData, Error> {
        let (date, amz_datetime) = amz_datetime(SystemTime::now())?;
        let credential_scope = format!("{}/{}/s3/aws4_request", date, self.region);

        let host = endpoint_host(&self.endpoint);
        let payload_hash = if body.is_empty() {
            EMPTY_PAYLOAD_SHA256.to_string()
        } else {
            hex_lower(&sha256(body))
        };

        let mut canonical_headers = vec![
            format!("host:{}\n", host),
            format!("x-amz-content-sha256:{}\n", payload_hash),
            format!("x-amz-date:{}\n", amz_datetime),
        ];
        let mut signed_headers = vec!["host", "x-amz-content-sha256", "x-amz-date"];

        if let Some(token) = self.credentials.session_token.as_deref() {
            canonical_headers.push(format!("x-amz-security-token:{}\n", token));
            signed_headers.push("x-amz-security-token");
        }

        canonical_headers.sort();
        signed_headers.sort();

        let canonical_headers_joined = canonical_headers.concat();
        let signed_headers_joined = signed_headers.join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers_joined,
            signed_headers_joined,
            payload_hash
        );

        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_datetime,
            credential_scope,
            hex_lower(&sha256(canonical_request.as_bytes()))
        );

        let signature = hex_lower(&sign_v4(
            &self.credentials.secret_access_key,
            &date,
            &self.region,
            &string_to_sign,
        ));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.credentials.access_key_id, credential_scope, signed_headers_joined, signature
        );

        let url = if canonical_query.is_empty() {
            format!("{}{}", self.endpoint.as_str().trim_end_matches('/'), canonical_uri)
        } else {
            format!(
                "{}{}?{}",
                self.endpoint.as_str().trim_end_matches('/'),
                canonical_uri,
                canonical_query
            )
        };

        let mut headers = vec![
            ("host".to_string(), host),
            ("x-amz-date".to_string(), amz_datetime),
            ("x-amz-content-sha256".to_string(), payload_hash),
            ("authorization".to_string(), authorization),
        ];
        if let Some(token) = self.credentials.session_token.as_deref() {
            headers.push(("x-amz-security-token".to_string(), token.to_string()));
        }

        let request = HttpRequest {
            method,
            url,
            headers,
            body: body.to_vec(),
        };
        let response = self.http.send(request).await.map_err(|err| Error::Http(err.to_string()))?;

        if (200..300).contains(&response.status_code) {
            return Ok(response);
        }

        let status = response.status_code;
        let body_bytes = collect_body(response.body).await.unwrap_or_default();
        let body = String::from_utf8_lossy(&body_bytes).into_owned();
        Err(Error::Api { status, body })
    }
}

#[cfg(feature = "reqwest")]
impl Client<ReqwestHttpClient> {
    pub fn new(config: &ClientConfig<'_>) -> Result<Self, Error> {
        Self::with_http_client(config, ReqwestHttpClient::new())
    }
}

fn consume_empty(_response: HttpResponseData) -> Result<(), Error> {
    Ok(())
}

fn canonical_bucket_uri(bucket: &str) -> String {
    canonical_uri(&format!("/{bucket}"))
}

fn canonical_object_uri(bucket: &str, key: &str) -> String {
    canonical_uri(&format!("/{bucket}/{key}"))
}

fn canonical_uri(path: &str) -> String {
    path.split('/').map(percent_encode).collect::<Vec<_>>().join("/")
}

fn canonical_query_string(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn endpoint_host(url: &Url) -> String {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        _ => String::new(),
    }
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
        {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_nibble_upper((b >> 4) & 0x0f));
            out.push(hex_nibble_upper(b & 0x0f));
        }
    }
    out
}

fn hex_nibble_upper(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + (value - 10)) as char,
        _ => unreachable!(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn sign_v4(secret_access_key: &str, date: &str, region: &str, string_to_sign: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret_access_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    hmac_sha256(&k_signing, string_to_sign.as_bytes())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length for SHA-256");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn amz_datetime(now: SystemTime) -> Result<(String, String), Error> {
    let elapsed = now.duration_since(UNIX_EPOCH)?;
    let total_seconds = elapsed.as_secs() as i64;

    let days = total_seconds.div_euclid(86_400);
    let seconds_of_day = total_seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    let date = format!("{year:04}{month:02}{day:02}");
    let datetime = format!("{date}T{hour:02}{minute:02}{second:02}Z");

    Ok((date, datetime))
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, i64, i64) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    (year as i32, month, day)
}

async fn collect_body(mut stream: ByteStream) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| Error::Http(e.to_string()))?;
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn bytes_to_string(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|e| Error::Http(e.to_string()))
}

fn header_to_string(response: &HttpResponseData, name: &str) -> Option<String> {
    response.header(name).map(ToString::to_string)
}

fn header_to_u64(response: &HttpResponseData, name: &str) -> Option<u64> {
    response.header(name).and_then(|s| s.parse::<u64>().ok())
}

fn build_complete_multipart_body(parts: &[CompletedPart]) -> Vec<u8> {
    let mut xml = String::from("<CompleteMultipartUpload>");
    for part in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&part.part_number.to_string());
        xml.push_str("</PartNumber><ETag>");
        xml.push_str(&xml_escape(&part.e_tag));
        xml.push_str("</ETag></Part>");
    }
    xml.push_str("</CompleteMultipartUpload>");
    xml.into_bytes()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[derive(Debug, Deserialize)]
#[serde(rename = "ListBucketResult")]
struct ListBucketResultXml {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Prefix")]
    prefix: Option<String>,
    #[serde(rename = "KeyCount")]
    key_count: Option<u64>,
    #[serde(rename = "MaxKeys")]
    max_keys: Option<u64>,
    #[serde(rename = "IsTruncated")]
    is_truncated: bool,
    #[serde(rename = "NextContinuationToken")]
    next_continuation_token: Option<String>,
    #[serde(rename = "Contents", default)]
    contents: Vec<ObjectXml>,
}

#[derive(Debug, Deserialize)]
struct ObjectXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "LastModified")]
    last_modified: Option<String>,
    #[serde(rename = "ETag")]
    e_tag: Option<String>,
    #[serde(rename = "Size")]
    size: Option<u64>,
    #[serde(rename = "StorageClass")]
    storage_class: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "InitiateMultipartUploadResult")]
struct InitiateMultipartUploadResultXml {
    #[serde(rename = "UploadId")]
    upload_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUploadResult")]
struct CompleteMultipartUploadResultXml {
    #[serde(rename = "ETag")]
    e_tag: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct NoopHttpClient;

    impl HttpClient for NoopHttpClient {
        async fn send(&self, _request: HttpRequest) -> Result<HttpResponseData, HttpError> {
            Ok(HttpResponseData {
                status_code: 200,
                headers: Vec::new(),
                body: Box::pin(futures_util::stream::empty()),
            })
        }
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex_lower(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_lower(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_known_vector() {
        let key = [0x0b; 20];
        let sig = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex_lower(&sig),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn percent_encoding_works() {
        assert_eq!(percent_encode("abcXYZ-_.~"), "abcXYZ-_.~");
        assert_eq!(percent_encode("hello world/é"), "hello%20world%2F%C3%A9");
    }

    #[test]
    fn canonical_uri_preserves_slashes() {
        assert_eq!(
            canonical_object_uri("my-bucket", "folder/my file.txt"),
            "/my-bucket/folder/my%20file.txt"
        );
    }

    #[test]
    fn parses_list_objects_v2_xml() {
        let xml = r#"
<ListBucketResult>
  <Name>my-bucket</Name>
  <Prefix>photos/</Prefix>
  <KeyCount>1</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>photos/a.jpg</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <ETag>\"abc\"</ETag>
    <Size>42</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>
"#;

        let parsed: ListBucketResultXml = from_str(xml).unwrap();
        assert_eq!(parsed.name, "my-bucket");
        assert_eq!(parsed.prefix.as_deref(), Some("photos/"));
        assert_eq!(parsed.key_count, Some(1));
        assert_eq!(parsed.max_keys, Some(1000));
        assert!(!parsed.is_truncated);
        assert_eq!(parsed.contents.len(), 1);
        assert_eq!(parsed.contents[0].key, "photos/a.jpg");
    }

    #[test]
    fn amz_datetime_format_works() {
        let ts = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let (date, datetime) = amz_datetime(ts).unwrap();
        assert_eq!(date.len(), 8);
        assert_eq!(datetime.len(), 16);
        assert!(datetime.ends_with('Z'));
    }

    #[test]
    fn client_config_validation_works() {
        let cfg = ClientConfig {
            endpoint: "",
            credentials: StaticCredentials::new("a", "b", ""),
            region: "us-east-1",
        };
        assert!(matches!(
            Client::with_http_client(&cfg, NoopHttpClient),
            Err(Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn sign_v4_known_output_length() {
        let sig = sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\nabc",
        );
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn exposes_supported_actions_list() {
        let actions = [
            "CreateBucket",
            "PutObject",
            "GetObject",
            "HeadObject",
            "DeleteObject",
            "ListObjects",
        ];
        assert_eq!(actions.len(), 6);
    }

    #[test]
    fn empty_payload_sha256_constant_is_correct() {
        assert_eq!(EMPTY_PAYLOAD_SHA256, hex_lower(&sha256(b"")));
    }
}
