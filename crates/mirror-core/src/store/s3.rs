use std::path::Path;
use tokio::io::{AsyncRead, AsyncReadExt};

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::primitives::ByteStream;

use crate::config::Remote;
use crate::store::ObjectStore;
use crate::{Error, Result};

pub struct S3Store {
    client: Client,
    bucket: String,
}

impl S3Store {
    pub async fn connect(remote: &Remote) -> Result<Self> {
        let shared = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(remote.region.clone()))
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
}

impl ObjectStore for S3Store {
    async fn put(&self, key: &str, path: &Path) -> Result<()> {
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

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

        let bytes = response.body
          .collect()
          .await
          .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?
          .to_vec();

        Ok(bytes)
    }

    async fn head(&self, key: &str) -> Result<Option<super::ObjectMeta>> {
      let response = self.client
        .head_object()
        .bucket(&self.bucket)
        .key(key)
        .send()
        .await
        .map_or_else(default, f);


    }

    async fn delete(&self, key: &str) -> Result<()> {
        todo!()
    }

    async fn list(&self, prefix: &str) -> Result<Vec<super::ObjectMeta>> {
        todo!()
    }
}

// impl ObjectStore for S3Store {
//     pub async fn connect(remote: &Remote) -> Result<Self> {
//         let shared = aws_config::defaults(BehaviorVersion::latest())
//             .region(Region::new(remote.region.clone()))
//             .load()
//             .await;

//         let mut builder =
//             aws_sdk_s3::config::Builder::from(&shared).force_path_style(remote.path_style);

//         if let Some(endpoint) = &remote.endpoint {
//             builder = builder.endpoint_url(endpoint);
//         }

//         Ok(Self {
//             client: Client::from_conf(builder.build()),
//             bucket: remote.bucket.clone(),
//         })
//     }

//     pub async fn check(&self) -> Result<()> {
//         self.client
//             .head_bucket()
//             .bucket(&self.bucket)
//             .send()
//             .await
//             .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

//         Ok(())
//     }

//     pub async fn put(&self, path: &Path, key: &str) -> Result<()> {
//         let body = ByteStream::from_path(path)
//             .await
//             .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

//         self.client
//             .put_object()
//             .bucket(&self.bucket)
//             .key(key)
//             .body(body)
//             .send()
//             .await
//             .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

//         Ok(())
//     }

//     pub async fn get(&self, key: &str) -> Result<ByteStream> {
//         let response = self.client
//             .get_object()
//             .bucket(&self.bucket)
//             .key(key)
//             .send()
//             .await
//             .map_err(|e| Error::Store(format!("{}", DisplayErrorContext(&e))))?;

//         Ok(response.body)
//     }
// }

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
