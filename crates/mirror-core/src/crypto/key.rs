use argon2::{Algorithm::Argon2id, Argon2, Params, Version};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sha2::Sha256;

use crate::Error;
use crate::error::Result;

fn kdf(passphrase: SecretString, salt: &[u8], params: Params) -> Result<SecretBox<[u8; 32]>> {
    let argon2_custom = Argon2::new(Argon2id, Version::V0x13, params);

    let mut hash_buf = [0u8; 32];

    argon2_custom
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut hash_buf)
        .map_err(|e| Error::Crypto(format!("failed to hash passphrase {}", e)))?;

    let master_key = SecretBox::new(Box::new(hash_buf));

    Ok(master_key)
}

#[derive(Debug)]
pub struct DerivedSubKeys {
    // Secret prevents casual printing, logging, or leakage
    pub content_key: SecretBox<[u8; 32]>,
    pub name_key: SecretBox<[u8; 32]>,
    pub manifest_key: SecretBox<[u8; 32]>,
    pub keycheck_bytes: SecretBox<[u8; 32]>,
}

pub fn derive_application_keys(
    passphrase: SecretString,
    salt: &[u8],
    argon2_params: Params,
) -> Result<DerivedSubKeys> {
    let master_key = kdf(passphrase, salt, argon2_params)?;

    let hkdf_ctx = Hkdf::<Sha256>::new(Some(salt), master_key.expose_secret());

    let content_key = SecretBox::init_with_mut(|buf: &mut [u8; 32]| {
        hkdf_ctx
            .expand_multi_info(&[b"rfm:v1:", b"content"], buf)
            .unwrap();
    });
    let name_key = SecretBox::init_with_mut(|buf: &mut [u8; 32]| {
        hkdf_ctx
            .expand_multi_info(&[b"rfm:v1:", b"name"], buf)
            .unwrap();
    });
    let manifest_key = SecretBox::init_with_mut(|buf: &mut [u8; 32]| {
        hkdf_ctx
            .expand_multi_info(&[b"rfm:v1:", b"manifest"], buf)
            .unwrap();
    });
    let keycheck_bytes = SecretBox::init_with_mut(|buf: &mut [u8; 32]| {
        hkdf_ctx
            .expand_multi_info(&[b"rfm:v1:", b"keycheck"], buf)
            .unwrap();
    });

    let subkeys = DerivedSubKeys {
        content_key,
        name_key,
        manifest_key,
        keycheck_bytes,
    };

    Ok(subkeys)
}
