use std::path::Path;

use crate::{
    apply::MAX_SINGLE_SHOT_PUT_SIZE,
    crypto::{content::StreamingEncryptor, filename, key::DerivedSubKeys},
    engine::Action,
    error::Result,
    manifest::{Manifest, ManifestEntry},
    state::State,
    store::{ObjectStore, PartSink, get_chunk_size},
    util::file::hash_stable,
};

pub(crate) async fn upload<S: ObjectStore>(
    store: &S,
    root: &Path,
    action: &Action,
    state: &mut State,
    enc_keys: &DerivedSubKeys,
    manifest: &mut Manifest,
    prefix: &str,
) -> Result<()> {
    let local_path = root.join(&action.path);
    let object_key = filename::object_key(&enc_keys.name_key, action.path.clone().as_str())?;
    let store_key = format!("{prefix}{object_key}");

    let Some(stats) = hash_stable(&local_path)? else {
        tracing::warn!(path = %local_path.display(), "file changed while hashing; deferring");
        return Ok(()); // skip this action, next sync pass will pick it up
    };

    let mut encryptor =
        StreamingEncryptor::new(&enc_keys.content_key, &local_path, &action.path.clone())?;

    // `decrypt`/`StreamingDecryptor` both expect the 19-byte nonce as the first
    // bytes of the object — StreamingEncryptor hands it back separately rather
    // than writing it anywhere itself, so the object is corrupt unless we prepend
    // it here, ahead of whichever chunk ends up being the first one actually sent.
    let mut nonce_prefix = Some(encryptor.get_nonce().to_vec());

    if stats.0 <= MAX_SINGLE_SHOT_PUT_SIZE as u64 {
        if let Some(cipher_text) = encryptor.encrypt_next_part(stats.0 as usize)? {
            let mut payload = nonce_prefix.take().unwrap_or_default();
            payload.extend(cipher_text);
            store.put_bytes(&store_key, &payload).await?;
        }
    } else {
        let mut part_sink = store.begin_put(&store_key).await?;
        let chunk_size = get_chunk_size(stats.0);

        let result: Result<()> = async {
            while let Some(cipher_text) = encryptor.encrypt_next_part(chunk_size)? {
                let part = match nonce_prefix.take() {
                    Some(mut nonce) => {
                        nonce.extend(cipher_text);
                        nonce
                    }
                    None => cipher_text,
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

    manifest.insert(
        action.path.clone(),
        ManifestEntry {
            path: action.path.clone(),
            size: stats.0,
            content_hash: stats.2,
            object_key,
        },
    );

    state.confirm_sync(&action.path, stats.0, stats.1, stats.2)?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}
