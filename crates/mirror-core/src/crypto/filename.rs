use data_encoding::BASE32;
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;

use crate::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

fn hmac(name_enc_key: &SecretBox<[u8; 32]>, name: &str) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(name_enc_key.expose_secret())
        .map_err(|source| Error::Crypto(format!("failed to instantiate mac {}", source)))?;

    mac.update(name.as_bytes());

    let result = mac.finalize().into_bytes();

    Ok(result.into())
}

fn base32(bytes: &[u8]) -> Result<String> {
    Ok(BASE32.encode(bytes))
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

pub fn object_key(name_enc_key: &SecretBox<[u8; 32]>, canonical_path: &str) -> Result<String> {
    let hash_bytes = hmac(name_enc_key, canonical_path)?;
    let encoded_bytes = base32(&hash_bytes)?;
    Ok(shard(encoded_bytes.as_str()))
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};

    use super::*;

    #[test]
    fn same_path_same_key() {
        let canonical_path = "s3/test/file1.txt";
        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let key1 = object_key(&name_enc_key, canonical_path).unwrap();
        let key2 = object_key(&name_enc_key, canonical_path).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn diff_path_diff_key() {
        let canonical_path1 = "s3/test/file1.txt";
        let canonical_path2 = "s3/test/file2.txt";

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let key1 = object_key(&name_enc_key, canonical_path1).unwrap();
        let key2 = object_key(&name_enc_key, canonical_path2).unwrap();

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

        let key1 = object_key(&name_enc_key1, canonical_path).unwrap();
        let key2 = object_key(&name_enc_key2, canonical_path).unwrap();

        assert_ne!(key1, key2);
    }
}
