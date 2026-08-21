use aws_config::retry::RetryConfig;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
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
use crate::store::{ObjectMeta, ObjectStore};
use crate::{Error, Result};

const MAX_UPLOAD_SIZE: usize = 8 * 1024 * 1024; // 8 MB max single shot upload
const MULTIPART_CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5 MB minimum per part

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

    async fn multipart_put(&self, key: &str, path: &Path) -> Result<()> {
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

        loop {
            let mut buffer = vec![0; MULTIPART_CHUNK_SIZE];
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
}

impl ObjectStore for S3Store {
    async fn put(&self, key: &str, path: &Path) -> Result<()> {
        let metadata = fs::metadata(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;

        if metadata.len() > MAX_UPLOAD_SIZE as u64 {
            self.multipart_put(key, path).await?;
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

// async fn process_download(
//     stream: mut impl AsyncRead + Unpin, // Returned from your ObjectStore
//     tmp_path: &Path
// ) -> Result<blake3::Hash, Error> {
//     let mut file = tokio::fs::File::create(tmp_path).await?;
//     let mut hasher = blake3::Hasher::new();
//     let mut buffer = vec![0u8; 64 * 1024]; // Fixed 64 KiB buffer overhead

//     loop {
//         let n = stream.read(&mut buffer).await?;
//         if n == 0 { break; } // End of stream

//         let chunk = &buffer[..n];

//         // 1. Update hash on-the-fly
//         hasher.update(chunk);

//         // 2. Write straight to temporary disk location
//         file.write_all(chunk).await?;
//     }

//     file.flush().await?;
//     Ok(hasher.finalize())
// }
