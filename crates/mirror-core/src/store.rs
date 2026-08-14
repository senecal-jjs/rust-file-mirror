use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::DisplayErrorContext;

use crate::config::Remote;
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
