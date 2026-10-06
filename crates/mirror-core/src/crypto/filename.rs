use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

use crate::hash::ContentHash;
use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Content objects live under this sub-prefix, apart from `log/`, `snapshot/` and the vault.
pub const DATA_PREFIX: &str = "data/";

const OBJECT_KEY_DOMAIN: &[u8] = b"rfm:v2:obj\0";

fn hmac(name_enc_key: &SecretBox<[u8; 32]>, path: &str, hash: &ContentHash) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(name_enc_key.expose_secret())
        .map_err(|source| Error::Crypto(format!("failed to instantiate mac {}", source)))?;

    mac.update(OBJECT_KEY_DOMAIN);
    mac.update(path.as_bytes());
    mac.update(b"\0");
    mac.update(hash.as_bytes());

    let result = mac.finalize().into_bytes();

    Ok(result.into())
}

fn base32(bytes: &[u8]) -> Result<String> {
    Ok(BASE32_NOPAD.encode(bytes)[..26].to_string())
}

fn shard(name: &str) -> String {
    let mut result = String::new();

    for (index, ch) in name.chars().enumerate() {
        if index == 2 || index == 4 {
            result.push('/');
        }
        result.push(ch);
    }

    result
}

/// One key per (path, content) version, so an upload never overwrites another version's bytes.
pub fn object_key(
    name_enc_key: &SecretBox<[u8; 32]>,
    canonical_path: &str,
    content_hash: &ContentHash,
) -> Result<String> {
    let hash_bytes = hmac(name_enc_key, canonical_path, content_hash)?;
    let encoded_bytes = base32(&hash_bytes)?;
    Ok(format!("{DATA_PREFIX}{}", shard(encoded_bytes.as_str())))
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};

    use super::*;
    use crate::hash::hash_bytes;

    fn h() -> ContentHash {
        hash_bytes(b"contents")
    }

    #[test]
    fn same_path_same_key() {
        let canonical_path = "s3/test/file1.txt";
        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let key1 = object_key(&name_enc_key, canonical_path, &h()).unwrap();
        let key2 = object_key(&name_enc_key, canonical_path, &h()).unwrap();

        assert_eq!(key1, key2);
        assert!(key1.starts_with(DATA_PREFIX));
    }

    #[test]
    fn same_path_diff_content_diff_key() {
        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let key1 = object_key(&name_enc_key, "a.txt", &hash_bytes(b"v1")).unwrap();
        let key2 = object_key(&name_enc_key, "a.txt", &hash_bytes(b"v2")).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn diff_path_diff_key() {
        let canonical_path1 = "s3/test/file1.txt";
        let canonical_path2 = "s3/test/file2.txt";

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let key1 = object_key(&name_enc_key, canonical_path1, &h()).unwrap();
        let key2 = object_key(&name_enc_key, canonical_path2, &h()).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn diff_key_same_path() {
        let canonical_path = "s3/test/file1.txt";

        let mut name_enc_key1 = [0u8; 32];
        rng().fill(&mut name_enc_key1);
        let name_enc_key1 = SecretBox::new(Box::new(name_enc_key1));

        let mut name_enc_key2 = [0u8; 32];
        rng().fill(&mut name_enc_key2);
        let name_enc_key2 = SecretBox::new(Box::new(name_enc_key2));

        let key1 = object_key(&name_enc_key1, canonical_path, &h()).unwrap();
        let key2 = object_key(&name_enc_key2, canonical_path, &h()).unwrap();

        assert_ne!(key1, key2);
    }
}
