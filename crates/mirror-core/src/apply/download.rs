use std::io::Write;
use std::path::Path;

use secrecy::SecretBox;
use tempfile::NamedTempFile;

use crate::{
    Error,
    apply::{MAX_SINGLE_SHOT_PUT_SIZE, safe_join},
    crypto::content::StreamingDecryptor,
    engine::Action,
    error::Result,
    hash,
    manifest::ManifestEntry,
    state::State,
    store::{NONCE_SIZE, ObjectStore, PartSource},
    util::file::file_stat,
};

pub(crate) async fn download<S: ObjectStore>(
    store: &S,
    root: &Path,
    state: &mut State,
    prefix: &str,
    manifest_entry: &ManifestEntry,
    action: &Action,
    content_enc_key: &SecretBox<[u8; 32]>,
) -> Result<()> {
    let tmp_dir = root.join(".mirror/tmp");

    std::fs::create_dir_all(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let mut tmp_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let store_key = format!("{prefix}{}", manifest_entry.object_key);
    let file_meta = store
        .head(&store_key)
        .await?
        .ok_or(Error::Store(format!("download not found {store_key}")))?;

    let mut write_chunk = |bytes: &[u8]| -> Result<()> {
        tmp_file.write_all(bytes).map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })
    };

    if file_meta.size <= MAX_SINGLE_SHOT_PUT_SIZE as u64 {
        let data = store.get(&store_key).await?;

        if data.len() < NONCE_SIZE {
            return Err(Error::Store(format!(
                "object {store_key} is too short to hold a {NONCE_SIZE}-byte nonce (got {} bytes)",
                data.len()
            )));
        }

        let (nonce, cipher_text) = data.split_at(NONCE_SIZE);
        let nonce_bytes: [u8; NONCE_SIZE] = nonce.try_into().expect("checked length above");
        let mut decryptor = StreamingDecryptor::new(content_enc_key, nonce_bytes, &action.path)?;
        let mut plain_text = decryptor.feed(cipher_text)?;

        plain_text.extend(decryptor.finish()?);

        write_chunk(&plain_text)?;
    } else {
        let mut part_source = store.begin_download(&store_key).await?;
        let nonce = part_source.get_nonce();
        let mut decryptor = StreamingDecryptor::new(content_enc_key, nonce, &action.path)?;

        while let Some(part) = part_source.next().await? {
            write_chunk(&decryptor.feed(&part)?)?;
        }

        write_chunk(&decryptor.finish()?)?;
    }

    let blake3_hash = hash::hash_file(tmp_file.path())?;

    if blake3_hash != manifest_entry.content_hash {
        return Err(Error::Store(format!(
            "Manifest hash {} does not match tmp file hash {}",
            manifest_entry.content_hash, blake3_hash
        )));
    }

    tmp_file.as_file().sync_all().map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let durable_path = safe_join(root, &manifest_entry.path)?;

    tmp_file
        .persist(&durable_path)
        .map_err(|source| Error::Io {
            path: durable_path.clone(),
            source: source.error,
        })?;

    // After the rename succeeds, stat the file (same as the scanner does) and write that (size, mtime_ns, content_hash)
    // into State as the new baseline, with last_synced_hash set — this is the "preserve mtime" concern: record whatever
    // mtime the filesystem actually assigned after your write, not a guess, so the next scan's stat matches what you just
    // recorded and doesn't look like a spurious local change.
    let file_stats = file_stat(&durable_path)?;

    state.confirm_sync(
        &manifest_entry.path,
        file_stats.size,
        file_stats.mtime_ns,
        blake3_hash,
    )?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}
