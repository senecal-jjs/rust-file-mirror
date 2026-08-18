use serde::{Deserialize, Serialize};

use crate::Error;
use crate::error::Result;
use crate::store::ObjectStore;

#[derive(Serialize, Deserialize, Debug)]
pub struct VaultHeader {
    pub format_version: u32,
    pub kdf: String, // "argon2id" — a tag, not an enum, so a future KDF doesn't need a breaking format change
    pub m_cost: u32, // Argon2 memory cost, KiB
    pub t_cost: u32, // iterations
    pub p_cost: u32, // parallelism
    pub salt: Vec<u8>,
    pub key_check_nonce: [u8; 12], // ChaCha20Poly1305 Nonce
    pub key_check: Vec<u8>,        // ciphertext — filled in once 2.2/2.3 exist
}

pub async fn load(store: &impl ObjectStore, prefix: &str) -> Result<Option<VaultHeader>> {
    let key = format!("{prefix}vault.json");
    let head = store.head(&key).await?;

    match head {
        Some(_) => {
            let vault_bytes = store.get(&key).await?;
            let vault: VaultHeader = serde_json::from_slice(&vault_bytes)
                .map_err(|_| Error::Store(format!("failed to deserialize vault from {}", key)))?;

            Ok(Some(vault))
        }
        None => Ok(None),
    }
}

pub async fn create(store: &impl ObjectStore, prefix: &str, header: VaultHeader) -> Result<()> {
    let vault_bytes = serde_json::to_vec(&header)
        .map_err(|_| Error::Crypto("failed to serialize vault header to json".to_string()))?;

    let key = format!("{prefix}vault.json");

    store.put_bytes(&key, &vault_bytes).await?;

    Ok(())
}
