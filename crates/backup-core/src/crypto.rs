//! Backup keys, identifiers, and object sealing.
//!
//! Everything derives from the vault's `backup_key` (see `mirror_core::crypto::key`),
//! so backups need no key material of their own:
//!
//! ```text
//! backup_key ─┬─ id key    keyed BLAKE3 over a blob's plaintext → its BlobId
//!             ├─ data key  seals file content blobs
//!             └─ meta key  seals trees, pack headers, indexes, snapshots, config
//! ```
//!
//! Blob IDs are keyed rather than plain hashes. Deduplication still works, since
//! identical plaintext gives an identical ID under the same key, but someone who can
//! read the bucket can't test whether a file they already have is in a backup.
//!
//! Sealing reuses the mirror's XChaCha20-Poly1305 helper. Its 192-bit random nonce
//! means there's no per-key message ceiling to manage, which is what pushed gobackup
//! to derive a fresh AES-GCM key per object. Every seal carries associated data that
//! names the object, so a valid ciphertext can't be replayed as a different one.

use std::fmt;
use std::str::FromStr;

use data_encoding::HEXLOWER;
use mirror_core::crypto::content::{decrypt_bytes, encrypt_bytes};
use rand::Rng;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

pub const ID_SIZE: usize = 32;

/// BLAKE3 `derive_key` contexts. Part of the repository format: changing one makes
/// every existing backup unreadable.
const CONTEXT_ID: &str = "rfm backup v1 blob id key";
const CONTEXT_DATA: &str = "rfm backup v1 data key";
const CONTEXT_META: &str = "rfm backup v1 metadata key";

/// Identifies a blob (keyed hash of its plaintext) or a pack, index, or snapshot
/// (random). Serializes as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Id(pub [u8; ID_SIZE]);

impl Id {
    pub fn random() -> Self {
        let mut bytes = [0u8; ID_SIZE];
        rand::rng().fill(&mut bytes);
        Self(bytes)
    }

    /// A short, human-friendly prefix for messages.
    pub fn short(&self) -> String {
        HEXLOWER.encode(&self.0[..4])
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        bytes.try_into().map(Self).map_err(|_| {
            Error::Invalid(format!(
                "an ID must be {ID_SIZE} bytes, got {}",
                bytes.len()
            ))
        })
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&HEXLOWER.encode(&self.0))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.short())
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != ID_SIZE * 2 {
            return Err(Error::Invalid(format!(
                "invalid ID {s:?}: want {} hex characters, got {}",
                ID_SIZE * 2,
                s.len()
            )));
        }
        let bytes = HEXLOWER
            .decode(s.as_bytes())
            .map_err(|e| Error::Invalid(format!("invalid ID {s:?}: {e}")))?;
        Self::from_slice(&bytes)
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Which subkey seals an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Data,
    Meta,
}

pub struct Keys {
    id: [u8; 32],
    data: SecretBox<[u8; 32]>,
    meta: SecretBox<[u8; 32]>,
}

impl Keys {
    pub fn derive(backup_key: &SecretBox<[u8; 32]>) -> Self {
        let root = backup_key.expose_secret();
        Self {
            id: blake3::derive_key(CONTEXT_ID, root),
            data: SecretBox::new(Box::new(blake3::derive_key(CONTEXT_DATA, root))),
            meta: SecretBox::new(Box::new(blake3::derive_key(CONTEXT_META, root))),
        }
    }

    /// The keyed ID for a blob's plaintext.
    pub fn blob_id(&self, plaintext: &[u8]) -> Id {
        Id(*blake3::keyed_hash(&self.id, plaintext).as_bytes())
    }

    /// Whether `plaintext` is really the content `id` names. `blake3::Hash`
    /// compares in constant time.
    pub fn verify_blob_id(&self, id: &Id, plaintext: &[u8]) -> bool {
        blake3::keyed_hash(&self.id, plaintext) == blake3::Hash::from_bytes(id.0)
    }

    pub fn seal(&self, kind: KeyKind, plaintext: &[u8], aad: &str) -> Result<Vec<u8>> {
        Ok(encrypt_bytes(self.key(kind), plaintext, aad)?)
    }

    /// `what` names the object in the error message only.
    pub fn open(&self, kind: KeyKind, sealed: &[u8], aad: &str, what: &str) -> Result<Vec<u8>> {
        decrypt_bytes(self.key(kind), sealed, aad).map_err(|_| Error::Decryption(what.to_string()))
    }

    fn key(&self, kind: KeyKind) -> &SecretBox<[u8; 32]> {
        match kind {
            KeyKind::Data => &self.data,
            KeyKind::Meta => &self.meta,
        }
    }
}

#[cfg(test)]
pub(crate) fn test_keys() -> Keys {
    let mut root = [0u8; 32];
    rand::rng().fill(&mut root);
    Keys::derive(&SecretBox::new(Box::new(root)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let keys = test_keys();
        for kind in [KeyKind::Data, KeyKind::Meta] {
            for plaintext in [&b""[..], b"hello", &vec![7u8; 200_000]] {
                let sealed = keys.seal(kind, plaintext, "aad").unwrap();
                assert_eq!(keys.open(kind, &sealed, "aad", "test").unwrap(), plaintext);
            }
        }
    }

    #[test]
    fn seal_is_randomized() {
        let keys = test_keys();
        let a = keys.seal(KeyKind::Data, b"same", "aad").unwrap();
        let b = keys.seal(KeyKind::Data, b"same", "aad").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn open_rejects_tampering_truncation_and_wrong_aad() {
        let keys = test_keys();
        let sealed = keys.seal(KeyKind::Data, b"some plaintext", "aad").unwrap();

        for i in [0, sealed.len() / 2, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[i] ^= 1;
            assert!(keys.open(KeyKind::Data, &tampered, "aad", "t").is_err());
        }
        for len in [0, 5, sealed.len() - 1] {
            assert!(
                keys.open(KeyKind::Data, &sealed[..len], "aad", "t")
                    .is_err()
            );
        }
        assert!(keys.open(KeyKind::Data, &sealed, "other", "t").is_err());
    }

    #[test]
    fn open_rejects_wrong_key_and_wrong_subkey() {
        let keys = test_keys();
        let sealed = keys.seal(KeyKind::Data, b"secret", "aad").unwrap();
        assert!(
            test_keys()
                .open(KeyKind::Data, &sealed, "aad", "t")
                .is_err()
        );
        assert!(keys.open(KeyKind::Meta, &sealed, "aad", "t").is_err());
    }

    #[test]
    fn subkeys_are_distinct() {
        let keys = test_keys();
        assert_ne!(keys.data.expose_secret(), keys.meta.expose_secret());
        assert_ne!(&keys.id, keys.data.expose_secret());
        assert_ne!(&keys.id, keys.meta.expose_secret());
    }

    #[test]
    fn derivation_is_deterministic() {
        let root = SecretBox::new(Box::new([9u8; 32]));
        let a = Keys::derive(&root);
        let b = Keys::derive(&SecretBox::new(Box::new([9u8; 32])));
        assert_eq!(a.blob_id(b"x"), b.blob_id(b"x"));
        let sealed = a.seal(KeyKind::Meta, b"x", "aad").unwrap();
        assert_eq!(b.open(KeyKind::Meta, &sealed, "aad", "t").unwrap(), b"x");
    }

    #[test]
    fn blob_id_is_stable_content_dependent_and_keyed() {
        let keys = test_keys();
        assert_eq!(keys.blob_id(b"abc"), keys.blob_id(b"abc"));
        assert_ne!(keys.blob_id(b"abc"), keys.blob_id(b"abd"));
        assert_ne!(keys.blob_id(b"abc"), test_keys().blob_id(b"abc"));
        // Not a plain hash: anyone without the key can't compute it.
        assert_ne!(keys.blob_id(b"abc").0, *blake3::hash(b"abc").as_bytes());
    }

    #[test]
    fn verify_blob_id() {
        let keys = test_keys();
        let id = keys.blob_id(b"content");
        assert!(keys.verify_blob_id(&id, b"content"));
        assert!(!keys.verify_blob_id(&id, b"Content"));
    }

    #[test]
    fn id_encoding_round_trips() {
        let id = Id::random();
        let hex = id.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex.parse::<Id>().unwrap(), id);
        assert_eq!(id.short(), hex[..8]);

        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{hex}\""));
        assert_eq!(serde_json::from_str::<Id>(&json).unwrap(), id);
    }

    #[test]
    fn id_parsing_rejects_invalid_input() {
        for bad in [
            "",
            "abc",
            &"g".repeat(64),
            &"a".repeat(63),
            &"a".repeat(66),
            &"A".repeat(64),
        ] {
            assert!(bad.parse::<Id>().is_err(), "{bad:?} parsed");
        }
        assert!(Id::from_slice(&[0u8; 31]).is_err());
        assert_eq!(Id::from_slice(&[1u8; 32]).unwrap(), Id([1u8; 32]));
    }
}
