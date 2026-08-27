use aws_config::retry::RetryConfig;
use aws_sdk_s3::types::{
    ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart, MultipartUpload,
};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::primitives::ByteStream;

use crate::config::Remote;
use crate::hash::ContentHash;
use crate::state::CompletedUploadPart;
use crate::store::{
    NONCE_SIZE, ObjectMeta, ObjectStore, PartRecord, PartSink, PartSource, get_chunk_size,
};
use crate::{Error, Result};

const MAX_UPLOAD_SIZE: usize = 8 * 1024 * 1024; // 8 MB max single shot upload
// const MULTIPART_CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5 MB minimum per part
// const S3_MAX_PARTS: usize = 10000;
// const MAX_FILE_SIZE_BYTES: usize = S3_MAX_PARTS * MULTIPART_CHUNK_SIZE;

pub struct S3Store {
    client: Client,
    bucket: String,
}

impl S3Store {
    pub async fn connect(remote: &Remote) -> Result<Self> {
        let retry_config = RetryConfig::standard()
            .with_max_attempts(5)
            .with_initial_backoff(Duration::from_millis(150))
            .with_max_backoff(Duration::from_secs(5));

        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(remote.region.clone()))
            .retry_config(retry_config)
            .load()
            .await;

        let mut builder =
            aws_sdk_s3::config::Builder::from(&shared).force_path_style(remote.path_style);

        if let Some(endpoint) = &remote.endpoint {
            builder = builder.endpoint_url(endpoint);
        }

        Ok(Self {
            client: Client::from_conf(builder.build()),
            bucket: remote.bucket.clone(),
        })
    }

    pub async fn check(&self) -> Result<()> {
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        Ok(())
    }

    pub async fn abort_multipart_upload(&self, key: &str, upload_id: &str) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        Ok(())
    }

    async fn multipart_put(&self, key: &str, path: &Path, file_len: u64) -> Result<()> {
        let create_multipart_upload_output = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        let upload_id = create_multipart_upload_output
            .upload_id()
            .ok_or(Error::Store("Failed to get upload id".to_string()))?;

        // read and upload parts
        let mut file = File::open(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut part_number = 1;
        let mut completed_parts = Vec::new();
        let chunk_size = get_chunk_size(file_len);

        loop {
            let mut buffer = vec![0; chunk_size];
            let bytes_read = file.read(&mut buffer).map_err(|source| Error::Io {
                path: path.to_path_buf(),
                source,
            })?;

            if bytes_read == 0 {
                break; // end of file
            }

            // resize buffer if the last part is smaller than the chunk size
            buffer.truncate(bytes_read);

            println!(
                "Uploading part {}, size: {} bytes...",
                part_number, bytes_read
            );

            let upload_part_output = self
                .client
                .upload_part()
                .bucket(&self.bucket)
                .key(key)
                .upload_id(upload_id)
                .part_number(part_number)
                .body(buffer.into())
                .send()
                .await
                .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

            // extract the ETag identifier for this part
            let etag = upload_part_output
                .e_tag()
                .ok_or(Error::Store("Missing ETag".to_string()))?;

            // track completed parts sequentially
            completed_parts.push(
                CompletedPart::builder()
                    .e_tag(etag)
                    .part_number(part_number)
                    .build(),
            );

            part_number += 1;
        }

        // finalize and assemble the upload
        let completed_multipart_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();

        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(completed_multipart_upload)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        println!("Successfully finalized multipart upload!");

        Ok(())
    }

    /// Every multipart upload currently open on the bucket, from any device —
    /// `list_multipart_uploads` doesn't have a generated paginator the way
    /// `list_objects_v2` does, so this walks `is_truncated`/the marker pair by
    /// hand rather than truncating silently after the first page.
    pub async fn list_multipart_uploads(&self) -> Result<Vec<MultipartUpload>> {
        let mut uploads = Vec::new();
        let mut key_marker = None;
        let mut upload_id_marker = None;

        loop {
            let mut request = self.client.list_multipart_uploads().bucket(&self.bucket);

            if let Some(marker) = &key_marker {
                request = request.key_marker(marker);
            }
            if let Some(marker) = &upload_id_marker {
                request = request.upload_id_marker(marker);
            }

            let output = request
                .send()
                .await
                .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

            uploads.extend(output.uploads.unwrap_or_default());

            if output.is_truncated != Some(true) {
                break;
            }

            key_marker = output.next_key_marker;
            upload_id_marker = output.next_upload_id_marker;
        }

        Ok(uploads)
    }
}

pub struct S3PartSink {
    client: Client,
    bucket: String,
    key: String,
    pub upload_id: String,
    pub part_number: i32,
    completed_parts: Vec<CompletedPart>,
    completed: bool,
}

impl Drop for S3PartSink {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key = self.key.clone();
        let upload_id = self.upload_id.clone();

        tokio::spawn(async move {
            let _ = client
                .abort_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(upload_id)
                .send()
                .await;
        });
    }
}

impl PartSink for S3PartSink {
    fn upload_id(&self) -> &str {
        &self.upload_id
    }

    async fn abort(mut self) -> Result<()> {
        self.client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        self.completed = true;

        Ok(())
    }

    fn get_part_number(&self) -> i32 {
        self.part_number
    }

    async fn write_part(&mut self, bytes: &[u8]) -> Result<PartRecord> {
        // checksum_algorithm asks the SDK to compute a SHA-256 of the part body and
        // send it alongside — S3 verifies it server-side on receipt and rejects the
        // part outright (this call returns an Err) if the bytes that arrived don't
        // match, catching corruption in transit instead of only at decrypt time.
        let upload_part_output = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .part_number(self.part_number)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .body(bytes.to_vec().into())
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        let etag = upload_part_output
            .e_tag()
            .ok_or(Error::Store("Missing Etag".to_string()))?;

        // Carried forward into `finish`'s CompletedPart list — supplying it there is
        // what lets S3 verify the *assembled* object (order, no dropped/duplicated
        // parts) on completion, not just each part individually as it arrives.
        let checksum_sha256 = upload_part_output.checksum_sha256().ok_or(Error::Store(
            "Missing checksum for uploaded part".to_string(),
        ))?;

        self.completed_parts.push(
            CompletedPart::builder()
                .e_tag(etag)
                .checksum_sha256(checksum_sha256)
                .part_number(self.part_number)
                .build(),
        );

        self.part_number += 1;

        Ok(PartRecord {
            part_number: self.part_number - 1,
            etag: etag.to_string(),
            checksum_sha256: checksum_sha256.to_string(),
        })
    }

    async fn finish(mut self) -> Result<()> {
        let complete_multipart_upload = CompletedMultipartUpload::builder()
            .set_parts(Some(std::mem::take(&mut self.completed_parts)))
            .build();

        // Real AWS S3 returns a composite checksum here once it's verified every
        // part's checksum against what was supplied above and confirmed the
        // assembled object matches — but S3-compatible backends vary in whether they
        // implement that (confirmed against a live MinIO instance: it accepts and
        // verifies each part's checksum in write_part, but leaves this field empty on
        // completion). So its absence isn't an error, just unverifiable on this
        // backend — the per-part check in write_part is the guarantee that holds
        // everywhere.
        let output = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(&self.key)
            .upload_id(&self.upload_id)
            .multipart_upload(complete_multipart_upload)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        if output.checksum_sha256().is_none() {
            tracing::debug!(
                key = %self.key,
                "backend did not return a composite checksum on multipart completion"
            );
        }

        self.completed = true;

        Ok(())
    }
}

impl From<&CompletedUploadPart> for CompletedPart {
    fn from(part: &CompletedUploadPart) -> Self {
        CompletedPart::builder()
            .e_tag(&part.etag)
            .checksum_sha256(&part.checksum_sha256)
            .part_number(part.part_number)
            .build()
    }
}

pub struct S3PartSource {
    stream: ByteStream,
    nonce: [u8; NONCE_SIZE],
}

impl PartSource for S3PartSource {
    async fn next(&mut self) -> Result<Option<Vec<u8>>> {
        let bytes = self
            .stream
            .try_next()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        if let Some(b) = bytes {
            Ok(Some(b.to_vec()))
        } else {
            Ok(None)
        }
    }

    fn get_nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce
    }
}

impl ObjectStore for S3Store {
    type PartSink = S3PartSink;
    type PartSource = S3PartSource;

    async fn begin_download(&self, key: &str) -> Result<Self::PartSource> {
        let header = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(format!("bytes=0-{}", NONCE_SIZE - 1))
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        let header_bytes = header
            .body
            .collect()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?
            .into_bytes();

        let nonce: [u8; NONCE_SIZE] =
            header_bytes.to_vec().try_into().map_err(|bytes: Vec<u8>| {
                Error::Store(format!(
                    "object {key} is too short to hold a {NONCE_SIZE}-byte nonce (got {} bytes)",
                    bytes.len()
                ))
            })?;

        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(format!("bytes={NONCE_SIZE}-"))
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        Ok(S3PartSource {
            stream: response.body,
            nonce,
        })
    }

    async fn begin_put(&self, key: &str) -> Result<Self::PartSink> {
        let create_multipart_upload_output = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        let upload_id = create_multipart_upload_output
            .upload_id()
            .ok_or(Error::Store("Failed to get upload id".to_string()))?
            .to_string();

        Ok(S3PartSink {
            client: self.client.clone(), // aws_sdk_s3::Client is cheap to clone — Arc-backed internally
            bucket: self.bucket.clone(),
            key: key.to_string(),
            upload_id,
            part_number: 1,
            completed_parts: Vec::new(),
            completed: false,
        })
    }

    async fn resume_put(
        &self,
        key: &str,
        upload_id: &str,
        part_number: i32,
        completed_parts: Vec<CompletedUploadPart>,
    ) -> Result<Self::PartSink> {
        Ok(S3PartSink {
            client: self.client.clone(),
            bucket: self.bucket.clone(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
            part_number,
            completed_parts: completed_parts.iter().map(CompletedPart::from).collect(),
            completed: false,
        })
    }

    async fn put(&self, key: &str, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;

        if metadata.len() > MAX_UPLOAD_SIZE as u64 {
            self.multipart_put(key, path, metadata.len()).await?;
        } else {
            let body = ByteStream::from_path(path)
                .await
                .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .body(body)
                .send()
                .await
                .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;
        }

        Ok(())
    }

    async fn put_bytes(&self, key: &str, bytes: &[u8]) -> Result<()> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(bytes.to_vec()))
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?
            .to_vec();

        Ok(bytes)
    }

    async fn head(&self, key: &str) -> Result<Option<super::ObjectMeta>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                let content_hash = output
                    .metadata()
                    .and_then(|m| m.get("blake3hash"))
                    .map(|hex| ContentHash::from_hex(hex))
                    .transpose()?;

                Ok(Some(ObjectMeta {
                    key: key.to_string(),
                    size: output.content_length.map_or(0, |v| v.cast_unsigned()),
                    content_hash,
                }))
            }
            Err(err) if err.as_service_error().is_some_and(|e| e.is_not_found()) => Ok(None),
            Err(err) => Err(Error::Store(format!("{}", DisplayErrorContext(err)))),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(e))))?;

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<super::ObjectMeta>> {
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();

        let mut objects = Vec::new();

        while let Some(page) = pages.next().await {
            let page = page.map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

            let metas: Vec<ObjectMeta> = page
                .contents()
                .iter()
                .map(|entry| -> Result<ObjectMeta> {
                    Ok(ObjectMeta {
                        key: entry
                            .key()
                            .ok_or(Error::Store(
                                "listing returned an object with no key".into(),
                            ))?
                            .to_string(),
                        size: entry.size.map_or(0, |v| v.cast_unsigned()),
                        content_hash: None,
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            objects.extend(metas);
        }

        Ok(objects)
    }
}
