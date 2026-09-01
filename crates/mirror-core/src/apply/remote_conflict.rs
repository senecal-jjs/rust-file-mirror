use std::{io::Write, path::Path};

use secrecy::SecretBox;
use tempfile::NamedTempFile;

use crate::{
    Error, Result,
    apply::MAX_SINGLE_SHOT_PUT_SIZE,
    crypto::{
        content::{StreamingDecryptor, StreamingEncryptor},
        filename,
    },
    hash,
    manifest::{DeltaEntry, RemoteConflict},
    state::State,
    store::{NONCE_SIZE, ObjectStore, PartSink, PartSource, get_chunk_size},
    util::{
        file::conflict_name,
        time::{unix_timestamp, utc_timestamp},
    },
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_remote_conflict(
    store: &impl ObjectStore,
    conflict: &RemoteConflict,
    content_key: &SecretBox<[u8; 32]>,
    name_key: &SecretBox<[u8; 32]>,
    root: &Path,
    prefix: &str,
    state: &State,
    lamport: &u64,
) -> Result<DeltaEntry> {
    let tmp_dir = root.join(".mirror/tmp");

    std::fs::create_dir_all(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let mut tmp_file = NamedTempFile::new_in(&tmp_dir).map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let mut write_chunk = |bytes: &[u8]| -> Result<()> {
        tmp_file.write_all(bytes).map_err(|source| Error::Io {
            path: tmp_dir.clone(),
            source,
        })?;

        Ok(())
    };

    let new_name = conflict_name(
        &conflict.loser.path,
        &utc_timestamp(),
        &state.device_name()?,
    )?;
    let loser_object_key = filename::object_key(name_key, &new_name)?;
    let loser_store_key = format!("{prefix}{}", conflict.loser.object_key);
    let file_meta = store
        .head(&loser_store_key)
        .await?
        .ok_or(Error::Store(format!(
            "download not found {loser_store_key}"
        )))?;

    if file_meta.size <= MAX_SINGLE_SHOT_PUT_SIZE as u64 {
        let data = store.get(&loser_store_key).await?;

        if data.len() < NONCE_SIZE {
            return Err(Error::Store(format!(
                "object {loser_store_key} is too short to hold a {NONCE_SIZE}-byte nonce (got {} bytes)",
                data.len()
            )));
        }

        let (nonce, cipher_text) = data.split_at(NONCE_SIZE);
        let nonce_bytes: [u8; NONCE_SIZE] = nonce.try_into().expect("checked length above");
        let mut decryptor =
            StreamingDecryptor::new(content_key, nonce_bytes, &conflict.loser.path)?;
        let mut plain_text = decryptor.feed(cipher_text)?;

        plain_text.extend(decryptor.finish()?);

        write_chunk(&plain_text)?;
    } else {
        let mut part_source = store.begin_download(&loser_store_key).await?;
        let nonce = part_source.get_nonce();
        let mut decryptor = StreamingDecryptor::new(content_key, nonce, &conflict.loser.path)?;

        while let Some(part) = part_source.next().await? {
            write_chunk(&decryptor.feed(&part)?)?;
        }

        write_chunk(&decryptor.finish()?)?;
    }

    let blake3_hash = hash::hash_file(tmp_file.path())?;

    if blake3_hash != conflict.loser.plaintext_hash {
        return Err(Error::Store(format!(
            "conflict loser hash {} does not match tmp file hash {}",
            conflict.loser.plaintext_hash, blake3_hash
        )));
    }

    tmp_file.as_file().sync_all().map_err(|source| Error::Io {
        path: tmp_dir.clone(),
        source,
    })?;

    let new_store_key = format!("{prefix}{loser_object_key}");

    // Re-encrypt under a fresh nonce (StreamingEncryptor generates one when
    // passed None) with the *new* conflicted-copy path as AAD — this object's
    // identity is the new path, not the loser's original one, so that's what
    // has to authenticate it. Source is tmp_file — the already-downloaded,
    // already hash-verified plaintext — not the loser's original object.
    let mut encryptor = StreamingEncryptor::new(content_key, tmp_file.path(), &new_name, None)?;

    // Same as StreamingEncryptor elsewhere: it hands the nonce back separately
    // rather than writing it anywhere itself, so it has to be prepended here,
    // ahead of whichever chunk ends up being sent first.
    let mut nonce_prefix = Some(encryptor.get_nonce().to_vec());

    if conflict.loser.size <= MAX_SINGLE_SHOT_PUT_SIZE as u64 {
        if let Some(encrypted) = encryptor.encrypt_next_part(conflict.loser.size as usize)? {
            let mut payload = nonce_prefix.take().unwrap_or_default();
            payload.extend(encrypted.ciphertext);
            store.put_bytes(&new_store_key, &payload).await?;
        }
    } else {
        let mut part_sink = store.begin_put(&new_store_key).await?;
        let chunk_size = get_chunk_size(conflict.loser.size);

        let result: Result<()> = async {
            while let Some(encrypted) = encryptor.encrypt_next_part(chunk_size)? {
                let part = match nonce_prefix.take() {
                    Some(mut nonce) => {
                        nonce.extend(encrypted.ciphertext);
                        nonce
                    }
                    None => encrypted.ciphertext,
                };

                part_sink.write_part(&part).await?;
            }
            Ok(())
        }
        .await;

        match result {
            Ok(()) => part_sink.finish().await?,
            Err(e) => {
                let _ = part_sink.abort().await; // best effort - don't let a failed abort mask the real error
                return Err(e);
            }
        }
    }

    Ok(DeltaEntry {
        path: new_name,
        object_key: loser_object_key,
        plaintext_hash: conflict.loser.plaintext_hash,
        size: conflict.loser.size,
        mtime_utc: unix_timestamp(),
        deleted: false,
        deleted_at: 0,
        lamport: *lamport,
        device_id: state.device_id()?,
        base_hash: None,
    })
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};

    use super::*;
    use crate::{hash, store::memory::MemoryStore};

    #[tokio::test]
    async fn resolve_remote_conflict_uploads_loser_under_a_new_name() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let store = MemoryStore::new();
        let prefix = "rfm/";

        let mut content_key_bytes = [0u8; 32];
        rng().fill(&mut content_key_bytes);
        let content_key = SecretBox::new(Box::new(content_key_bytes));

        let mut name_key_bytes = [0u8; 32];
        rng().fill(&mut name_key_bytes);
        let name_key = SecretBox::new(Box::new(name_key_bytes));

        let path = "report.txt";
        let loser_content = b"loser content";
        let loser_hash = hash::hash_bytes(loser_content);
        let object_key = filename::object_key(&name_key, path).unwrap();
        let store_key = format!("{prefix}{object_key}");

        // Seed the object exactly the way upload()'s single-shot path would have
        // originally produced it: nonce prefix + ciphertext under `path` as AAD.
        let src = root.join("src.txt");
        std::fs::write(&src, loser_content).unwrap();
        let mut encryptor = StreamingEncryptor::new(&content_key, &src, path, None).unwrap();
        let encrypted = encryptor
            .encrypt_next_part(loser_content.len())
            .unwrap()
            .unwrap();
        let mut payload = encryptor.get_nonce().to_vec();
        payload.extend(encrypted.ciphertext);
        store.put_bytes(&store_key, &payload).await.unwrap();

        // resolve_remote_conflict never reads `winner` — it only exists to be
        // left alone — so it doesn't need any backing bytes in the store.
        let loser = DeltaEntry {
            path: path.to_string(),
            object_key: object_key.clone(),
            plaintext_hash: loser_hash,
            size: loser_content.len() as u64,
            mtime_utc: 0,
            deleted: false,
            deleted_at: 0,
            lamport: 5,
            device_id: "loser-device".to_string(),
            base_hash: None,
        };
        let winner = DeltaEntry {
            path: path.to_string(),
            object_key,
            plaintext_hash: hash::hash_bytes(b"winner content"),
            size: 14,
            mtime_utc: 0,
            deleted: false,
            deleted_at: 0,
            lamport: 3,
            device_id: "winner-device".to_string(),
            base_hash: None,
        };
        let conflict = RemoteConflict { winner, loser };

        let state = State::open(root).unwrap();

        let entry = resolve_remote_conflict(
            &store,
            &conflict,
            &content_key,
            &name_key,
            root,
            prefix,
            &state,
            &7,
        )
        .await
        .unwrap();

        // Lands under a new, renamed path — the original path is left for the
        // winner, untouched by this function entirely.
        assert_ne!(entry.path, path);
        assert!(entry.path.contains("conflicted copy"));
        assert!(entry.path.ends_with(".txt"));
        assert_eq!(entry.plaintext_hash, loser_hash);
        assert_eq!(entry.size, loser_content.len() as u64);
        assert!(!entry.deleted);
        assert_eq!(entry.base_hash, None);
        assert_eq!(entry.lamport, 7);

        // The bytes actually landed at the new object key and decrypt back to
        // the loser's original content under the new path as AAD.
        let new_store_key = format!("{prefix}{}", entry.object_key);
        let data = store.get(&new_store_key).await.unwrap();
        let (nonce, cipher_text) = data.split_at(NONCE_SIZE);
        let nonce_bytes: [u8; NONCE_SIZE] = nonce.try_into().unwrap();
        let mut decryptor =
            StreamingDecryptor::new(&content_key, nonce_bytes, &entry.path).unwrap();
        let mut plain_text = decryptor.feed(cipher_text).unwrap();
        plain_text.extend(decryptor.finish().unwrap());

        assert_eq!(plain_text, loser_content);
    }
}
