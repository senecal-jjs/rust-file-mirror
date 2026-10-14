//! Encrypted, deduplicating, incremental backups into the same bucket (and under the
//! same vault passphrase) as the mirror. See `docs/backup-plan.md` for the design.

pub mod archiver;
pub mod cache;
pub mod chunker;
pub mod compress;
pub mod crypto;
pub mod error;
pub mod filter;
pub mod index;
pub mod pack;
pub mod repo;
pub mod restorer;
pub mod snapshot;
pub mod verify;

pub use error::{Error, Result};
