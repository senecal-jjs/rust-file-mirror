use keyring::Entry;
use secrecy::{ExposeSecret, SecretBox};

use crate::{Error, Result};

pub fn store_to_keyring(secret: SecretBox<[u8; 32]>, name: &str) -> Result<()> {
    let entry = Entry::new("com.bitcli.file.mirror", name)
        .map_err(|source| Error::Crypto(format!("Failed to create keyring entry {}", source)))?;

    entry.set_secret(secret.expose_secret()).map_err(|source| {
        Error::Crypto(format!(
            "Failed to store secret to keyring entry {}",
            source
        ))
    })?;

    Ok(())
}

pub fn load_from_keyring(name: &str) -> Result<SecretBox<[u8; 32]>> {
    let entry = Entry::new("com.bitcli.file.mirror", name)
        .map_err(|source| Error::Crypto(format!("Failed to create keyring entry {}", source)))?;

    // 1. Fetch the raw vector from the keyring safely
    let raw_vec = entry.get_secret().map_err(|source| {
        Error::Crypto(format!("Failed to fetch secret from keyring: {}", source))
    })?;

    // 2. Coerce the vector into the fixed array seamlessly
    let secret_bytes: [u8; 32] = raw_vec
        .try_into()
        .map_err(|_| Error::Crypto("Stored secret was not exactly 32 bytes long".to_string()))?;

    Ok(SecretBox::new(Box::new(secret_bytes)))
}
