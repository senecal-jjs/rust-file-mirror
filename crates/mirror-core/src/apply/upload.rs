use std::path::Path;

use crate::{
    Error,
    apply::MAX_SINGLE_SHOT_PUT_SIZE,
    crypto::{content::StreamingEncryptor, filename, key::DerivedSubKeys},
    engine::Action,
    error::Result,
    hash::ContentHash,
    indicator::ProgressReporter,
    state::{PendingUpload, State},
    store::{ObjectStore, PartSink, get_chunk_size},
    util::file::hash_stable,
};

pub struct UploadResult {
    pub size: u64,
    pub mtime_ns: i64,
    pub content_hash: ContentHash,
    pub object_key: String,
}

/// Resumes an interrupted multipart upload. `stats` is the caller's own fresh
/// `hash_stable` result for the file — reused here rather than re-hashing
/// (potentially many GB) a second time, since the caller already had to compute
/// it to confirm the file hadn't changed and was safe to resume at all.
pub async fn resume_upload(
    store: &impl ObjectStore,
    pending_upload: &PendingUpload,
    stats: (u64, i64, ContentHash),
    enc_keys: &DerivedSubKeys,
    root: &Path,
    prefix: &str,
    state: &mut State,
) -> Result<UploadResult> {
    let local_path = root.join(&pending_upload.path);
    let path_str = pending_upload.path.to_str().ok_or_else(|| {
        Error::State(format!(
            "non-UTF8 path in pending upload: {:?}",
            pending_upload.path
        ))
    })?;
    let object_key = filename::object_key(&enc_keys.name_key, path_str)?;
    let store_key = format!("{prefix}{object_key}");
    let nonce: [u8; 19] = pending_upload
        .nonce
        .clone()
        .try_into()
        .expect("pending upload nonce must be 19 bytes");

    // The next part number that still needs uploading — 1 if nothing has been
    // confirmed yet (interrupted before the very first part finished), otherwise
    // one past whatever's already been confirmed on the remote. `max` on an
    // empty iterator is None, which `unwrap_or(0) + 1` correctly turns into 1.
    let next_part_number = pending_upload
        .completed_parts
        .iter()
        .map(|part| part.part_number)
        .max()
        .unwrap_or(0)
        + 1;

    // The nonce only needs prepending if nothing has ever reached the remote yet
    // — once part 1 exists there, it already carries the nonce, and prepending
    // it again would corrupt the object.
    let mut nonce_prefix = (next_part_number == 1).then(|| nonce.to_vec());

    let mut encryptor =
        StreamingEncryptor::new(&enc_keys.content_key, &local_path, path_str, Some(nonce))?;

    let mut part_sink = store
        .resume_put(
            &store_key,
            &pending_upload.upload_id,
            next_part_number,
            pending_upload.completed_parts.clone(),
        )
        .await?;

    let result: Result<()> = async {
        let mut part_number = 1;

        while let Some(encrypted) = encryptor.encrypt_next_part(pending_upload.part_size)? {
            if part_number >= next_part_number {
                let part = match nonce_prefix.take() {
                    Some(mut nonce) => {
                        nonce.extend(encrypted.ciphertext);
                        nonce
                    }
                    None => encrypted.ciphertext,
                };

                let part_record = part_sink.write_part(&part).await?;

                state.record_upload_part(
                    path_str,
                    part_record.part_number,
                    &part_record.etag,
                    &part_record.checksum_sha256,
                )?;
            }

            part_number += 1;
        }

        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            part_sink.finish().await?;
            state.clear_upload(path_str)?;
        }
        Err(e) => {
            let _ = part_sink.abort().await; // best effort - don't let a failed abort mask the real error
            state.clear_upload(path_str)?;
            return Err(e);
        }
    }

    Ok(UploadResult {
        size: stats.0,
        mtime_ns: stats.1,
        content_hash: stats.2,
        object_key,
    })
}

pub(crate) async fn upload<S: ObjectStore>(
    store: &S,
    root: &Path,
    action: &Action,
    enc_keys: &DerivedSubKeys,
    prefix: &str,
    reporter: &dyn ProgressReporter,
) -> Result<Option<UploadResult>> {
    let local_path = root.join(&action.path);
    let object_key = filename::object_key(&enc_keys.name_key, action.path.clone().as_str())?;
    let store_key = format!("{prefix}{object_key}");

    let Some(stats) = hash_stable(&local_path)? else {
        tracing::warn!(path = %local_path.display(), "file changed while hashing; deferring");
        return Ok(None); // skip this action, next sync pass will pick it up
    };

    let mut encryptor = StreamingEncryptor::new(
        &enc_keys.content_key,
        &local_path,
        &action.path.clone(),
        None,
    )?;

    // `decrypt`/`StreamingDecryptor` both expect the 19-byte nonce as the first
    // bytes of the object — StreamingEncryptor hands it back separately rather
    // than writing it anywhere itself, so the object is corrupt unless we prepend
    // it here, ahead of whichever chunk ends up being the first one actually sent.
    let mut nonce_prefix = Some(encryptor.get_nonce().to_vec());
    let mut tracker = reporter.start_file(&action.path, stats.0);

    if stats.0 <= MAX_SINGLE_SHOT_PUT_SIZE as u64 {
        if let Some(encrypted) = encryptor.encrypt_next_part(stats.0 as usize)? {
            let mut payload = nonce_prefix.take().unwrap_or_default();
            payload.extend(encrypted.ciphertext);
            store.put_bytes(&store_key, &payload).await?;
            tracker.add_bytes(encrypted.plaintext_len as u64);
        }
    } else {
        // db tracking to allow upload resumption if program is killed
        let mut db = State::open(root)?;
        let mut part_sink = store.begin_put(&store_key).await?;
        let chunk_size = get_chunk_size(stats.0);

        db.record_upload_start(
            &action.path,
            part_sink.upload_id(),
            chunk_size,
            stats.2,
            &encryptor.get_nonce(),
        )?;

        let result: Result<()> = async {
            while let Some(encrypted) = encryptor.encrypt_next_part(chunk_size)? {
                let part = match nonce_prefix.take() {
                    Some(mut nonce) => {
                        nonce.extend(encrypted.ciphertext);
                        nonce
                    }
                    None => encrypted.ciphertext,
                };

                let part_record = part_sink.write_part(&part).await?;

                db.record_upload_part(
                    &action.path,
                    part_record.part_number,
                    &part_record.etag,
                    &part_record.checksum_sha256,
                )?;

                tracker.add_bytes(encrypted.plaintext_len as u64);
            }
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                part_sink.finish().await?;
                db.clear_upload(&action.path)?;
            }
            Err(e) => {
                let _ = part_sink.abort().await; // best effort - don't let a failed abort mask the real error
                db.clear_upload(&action.path)?;
                return Err(e);
            }
        }
    }

    Ok(Some(UploadResult {
        size: stats.0,
        mtime_ns: stats.1,
        content_hash: stats.2,
        object_key,
    }))
}
