use std::collections::BTreeMap;

use quick_xml::de::from_str;
use serde::Deserialize;

use crate::client::{
    ByteStream, Client, HttpClient, HttpMethod, bytes_to_string, canonical_object_uri, canonical_query_string,
    collect_body, consume_empty, header_to_string, header_to_u64,
};

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

impl<H: HttpClient> Client<H> {
    pub async fn put_object(&self, bucket: &str, key: &str, body: &[u8]) -> Result<(), crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Put, &canonical_uri, "", body).await?;
        consume_empty(response)
    }

    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<GetObjectOutput, crate::client::Error> {
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

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<HeadObjectOutput, crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Head, &canonical_uri, "", b"").await?;

        Ok(HeadObjectOutput {
            e_tag: header_to_string(&response, "etag"),
            content_type: header_to_string(&response, "content-type"),
            content_length: header_to_u64(&response, "content-length"),
        })
    }

    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Delete, &canonical_uri, "", b"").await?;
        consume_empty(response)
    }

    pub async fn create_multipart_upload(&self, bucket: &str, key: &str) -> Result<String, crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let response = self.execute(HttpMethod::Post, &canonical_uri, "uploads=", b"").await?;
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
    ) -> Result<UploadPartOutput, crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let mut params = BTreeMap::new();
        params.insert("partNumber".to_string(), part_number.to_string());
        params.insert("uploadId".to_string(), upload_id.to_string());
        let canonical_query = canonical_query_string(&params);
        let response = self
            .execute(HttpMethod::Put, &canonical_uri, &canonical_query, body)
            .await?;
        let e_tag = header_to_string(&response, "etag");
        Ok(UploadPartOutput {
            e_tag,
        })
    }

    pub async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<CompleteMultipartUploadOutput, crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let mut params = BTreeMap::new();
        params.insert("uploadId".to_string(), upload_id.to_string());
        let canonical_query = canonical_query_string(&params);
        let xml_body = build_complete_multipart_body(parts);
        let response = self
            .execute(HttpMethod::Post, &canonical_uri, &canonical_query, &xml_body)
            .await?;
        let xml_text = bytes_to_string(collect_body(response.body).await?)?;
        let xml: CompleteMultipartUploadResultXml = from_str(&xml_text)?;
        Ok(CompleteMultipartUploadOutput {
            e_tag: xml.e_tag,
        })
    }

    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), crate::client::Error> {
        let canonical_uri = canonical_object_uri(bucket, key);
        let mut params = BTreeMap::new();
        params.insert("uploadId".to_string(), upload_id.to_string());
        let canonical_query = canonical_query_string(&params);
        let response = self
            .execute(HttpMethod::Delete, &canonical_uri, &canonical_query, b"")
            .await?;
        consume_empty(response)
    }
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
