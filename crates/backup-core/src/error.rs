pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Anything the shared mirror layers (object store, AEAD helpers) report.
    #[error(transparent)]
    Mirror(#[from] mirror_core::Error),

    /// An object failed authentication: wrong key, corruption, or tampering. These
    /// are deliberately not told apart.
    #[error(
        "decryption failed for {0}: wrong key, or the data is corrupt or has been tampered with"
    )]
    Decryption(String),

    /// An object decrypted but its contents don't parse, or contradict themselves.
    #[error("malformed {0}")]
    Format(String),

    /// Content whose recomputed ID doesn't match the one it's stored under.
    #[error("{0} does not match its ID; the repository is corrupt")]
    Corrupt(String),

    #[error("a backup repository already exists at {0}")]
    AlreadyInitialized(String),

    #[error("no backup repository at {0}")]
    NotInitialized(String),

    /// A write failed earlier in this run, so it can no longer produce a trustworthy
    /// snapshot. Sticky: every later write reports it too.
    #[error("refusing to continue because an earlier write failed: {0}")]
    RunFailed(String),

    #[error("blob {0} is not in the index")]
    UnknownBlob(String),

    #[error("invalid chunker configuration: {0}")]
    ChunkerConfig(String),

    #[error("reading input: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Invalid(String),
}
