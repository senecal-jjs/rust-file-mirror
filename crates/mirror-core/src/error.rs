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

    /// A multipart upload's remote session is gone (`NoSuchUpload`) or its parts no
    /// longer match (`InvalidPart`) — the pending upload must be cleared and restarted.
    #[error("multipart upload no longer valid: {0}")]
    UploadGone(String),

    #[error("scan error: {0}")]
    Scan(String),

    #[error("state error: {0}")]
    State(String),

    #[error("invalid hash: {0}")]
    Hash(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("format error: {0}")]
    Format(String),

    /// Nothing is listening on the control socket at this path.
    #[error("no daemon running (nothing listening on {0}); start one with `rfm watch`")]
    DaemonNotRunning(String),

    /// The daemon took the connection but didn't answer in time.
    #[error("the daemon at {0} didn't answer; it may be shutting down")]
    DaemonUnresponsive(String),

    /// The daemon answered, but not in a way this build understands.
    #[error("the running daemon is older than this rfm (it replied {0:?}); restart it")]
    DaemonIncompatible(String),

    #[error("not enough free space: {0}")]
    NoSpace(String),
}
