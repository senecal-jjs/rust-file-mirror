use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error at {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("object store error: {0}")]
    Store(String),

    #[error("scan error: {0}")]
    Scan(String),

    #[error("state error: {0}")]
    State(String),

    #[error("invalid hash: {0}")]
    Hash(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}
