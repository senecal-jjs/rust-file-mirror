use std::{collections::BTreeMap, fs::File, os::raw, path::Path};

use serde::{Deserialize, Serialize};

use crate::{Error, Result, hash::ContentHash, state::State, store::ObjectStore};

#[derive(Serialize, Deserialize, Debug)]
pub struct DeltaEntry {
    pub path: String,
    pub object_key: String,
    pub plaintext_hash: ContentHash,
    pub size: u64,
    pub mtime_utc: u64,
    pub deleted: bool,
    pub deleted_at: u64,
    pub lamport: i64,
    pub device_id: String,
    pub base_hash: ContentHash,
}

pub type DeltaLog = BTreeMap<String, DeltaEntry>;

fn to_json_bytes(delta_log: &DeltaLog) -> Result<Vec<u8>> {
    serde_json::to_vec(delta_log).map_err(|e| {
        Error::Store(format!(
            "Failed to serialize Delta Log. Error: {}, Delta Log {:?}",
            e, delta_log
        ))
    })
}

fn from_json_bytes(bytes_path: &Path) -> Result<DeltaLog> {
    let input = File::open(bytes_path).map_err(|source| Error::Io {
        path: bytes_path.to_path_buf(),
        source,
    })?;

    let buf_reader = std::io::BufReader::new(input);

    let manifest = serde_json::from_reader(buf_reader).map_err(|source| {
        Error::Store(format!(
            "Failed to deserialize manifest from file. Error: {}",
            source
        ))
    })?;

    Ok(manifest)
}

pub async fn log_delta(store: &impl ObjectStore, state: &mut State, log: &DeltaLog) -> Result<()> {
    let log_bytes = to_json_bytes(log)?;
    let device_id = state.device_id()?;
    let raw_lamport = state.get_latest_lamport()?;
    // 20 is max number of digits a u64 an hold
    let formatted_lamport = format!("lamport:{:020}", raw_lamport);
    let store_key = format!("log/{}-{}.delta", formatted_lamport, device_id);

    store.put_bytes(&store_key, &log_bytes).await?;

    Ok(())
}
