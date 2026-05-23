use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use quick_xml::de::from_str;
use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::{Method, Url};
use serde::Deserialize;

const EMPTY_PAYLOAD_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_BLOCK_SIZE: usize = 64;

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
pub struct Client {
    endpoint: Url,
    region: String,
    credentials: OwnedCredentials,
    http: HttpClient,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfig(&'static str),
    Http(reqwest::Error),
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

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Self::Http(value)
    }
}

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

#[derive(Debug, Clone)]
pub struct GetObjectOutput {
    pub body: Vec<u8>,
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

impl Client {
    pub fn new(config: &ClientConfig<'_>) -> Result<Self, Error> {
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
            http: HttpClient::new(),
        })
    }

    pub fn create_bucket(&self, bucket: &str) -> Result<(), Error> {
        let canonical_uri = canonical_bucket_uri(bucket);
        let response = self.execute(Method::PUT, &canonical_uri, "", b"")?;
        consume_empty(response)
    }

    pub fn put_object(&self, bucket: &str, key: &str, body: &[u8]) -> Result<(), Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(Method::PUT, &canonical_uri, "", body)?;
        consume_empty(response)
    }

    pub fn get_object(&self, bucket: &str, key: &str) -> Result<GetObjectOutput, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(Method::GET, &canonical_uri, "", b"")?;
        let headers = response.headers().clone();
        let body = response.bytes()?.to_vec();

        Ok(GetObjectOutput {
            body,
            e_tag: header_to_string(headers.get("etag")),
            content_type: header_to_string(headers.get("content-type")),
            content_length: header_to_u64(headers.get("content-length")),
        })
    }

    pub fn head_object(&self, bucket: &str, key: &str) -> Result<HeadObjectOutput, Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(Method::HEAD, &canonical_uri, "", b"")?;
        let headers = response.headers();

        Ok(HeadObjectOutput {
            e_tag: header_to_string(headers.get("etag")),
            content_type: header_to_string(headers.get("content-type")),
            content_length: header_to_u64(headers.get("content-length")),
        })
    }

    pub fn delete_object(&self, bucket: &str, key: &str) -> Result<(), Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(Method::DELETE, &canonical_uri, "", b"")?;
        consume_empty(response)
    }

    pub fn list_objects(
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
        let response = self.execute(Method::GET, &canonical_uri, &canonical_query, b"")?;
        let body = response.text()?;
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

    fn execute(
        &self,
        method: Method,
        canonical_uri: &str,
        canonical_query: &str,
        body: &[u8],
    ) -> Result<Response, Error> {
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

        let mut request = self
            .http
            .request(method, &url)
            .header("host", host)
            .header("x-amz-date", amz_datetime)
            .header("x-amz-content-sha256", payload_hash)
            .header("authorization", authorization);

        if let Some(token) = self.credentials.session_token.as_deref() {
            request = request.header("x-amz-security-token", token);
        }

        let response = if body.is_empty() {
            request.send()?
        } else {
            request.body(body.to_vec()).send()?
        };

        if response.status().is_success() {
            return Ok(response);
        }

        let status = response.status().as_u16();
        let body = response.text().unwrap_or_default();
        Err(Error::Api { status, body })
    }
}

fn consume_empty(response: Response) -> Result<(), Error> {
    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    Err(Error::Api { status, body })
}

fn canonical_bucket_uri(bucket: &str) -> String {
    canonical_uri(&format!("/{bucket}"))
}

fn canonical_object_uri(bucket: &str, key: &str) -> String {
    canonical_uri(&format!("/{bucket}/{key}"))
}

fn canonical_uri(path: &str) -> String {
    path.split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/")
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
    let mut key_block = [0u8; SHA256_BLOCK_SIZE];

    if key.len() > SHA256_BLOCK_SIZE {
        key_block.copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut i_key_pad = [0u8; SHA256_BLOCK_SIZE];
    let mut o_key_pad = [0u8; SHA256_BLOCK_SIZE];

    for i in 0..SHA256_BLOCK_SIZE {
        i_key_pad[i] = key_block[i] ^ 0x36;
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner = Vec::with_capacity(SHA256_BLOCK_SIZE + data.len());
    inner.extend_from_slice(&i_key_pad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(SHA256_BLOCK_SIZE + inner_hash.len());
    outer.extend_from_slice(&o_key_pad);
    outer.extend_from_slice(&inner_hash);

    sha256(&outer)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64) * 8;
    msg.push(0x80);

    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }

    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];

        for (i, word) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, value) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&value.to_be_bytes());
    }

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

fn header_to_string(value: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    value.and_then(|v| v.to_str().ok()).map(ToString::to_string)
}

fn header_to_u64(value: Option<&reqwest::header::HeaderValue>) -> Option<u64> {
    value
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(canonical_object_uri("my-bucket", "folder/my file.txt"), "/my-bucket/folder/my%20file.txt");
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
        assert!(matches!(Client::new(&cfg), Err(Error::InvalidConfig(_))));
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
