//! An upload resumed after an interruption must be recorded in the remote log, or no
//! other device ever learns the file exists.

use std::sync::Arc;

use mirror_core::crypto::content::StreamingEncryptor;
use mirror_core::crypto::filename;
use mirror_core::hash;
use mirror_core::state::State;
use mirror_core::store::memory::MemoryStore;
use mirror_core::store::{ObjectStore, PartSink, get_chunk_size};
use mirror_core::sync::SyncOptions;
use rand::Rng;

mod common;
use common::{Device, test_keys};

#[tokio::test]
async fn resumed_upload_is_logged_for_other_devices() {
    let prefix = "resume/";
    let keys = Arc::new(test_keys());
    let store = Arc::new(MemoryStore::new());
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = Device {
        root: dir_a.path().to_path_buf(),
        store: Arc::clone(&store),
    };
    let b = Device {
        root: dir_b.path().to_path_buf(),
        store: Arc::clone(&store),
    };

    // Above the single-shot limit, so it goes multipart.
    let path = "large.bin";
    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(a.root.join(path), &content).unwrap();

    // Interrupt after the first part, as a crash would.
    let mut state = State::open(&a.root).unwrap();
    let content_hash = hash::hash_file(&a.root.join(path)).unwrap();
    let object_key = filename::object_key(&keys.name_key, path, &content_hash).unwrap();
    let chunk_size = get_chunk_size(size as u64);
    let mut encryptor =
        StreamingEncryptor::new(&keys.content_key, &a.root.join(path), path, None).unwrap();
    let nonce = encryptor.get_nonce();
    let mut sink = store
        .begin_put(&format!("{prefix}{object_key}"))
        .await
        .unwrap();
    state
        .record_upload_start(path, sink.upload_id(), chunk_size, content_hash, &nonce)
        .unwrap();

    let encrypted = encryptor.encrypt_next_part(chunk_size).unwrap().unwrap();
    let mut first_part = nonce.to_vec();
    first_part.extend(encrypted.ciphertext);
    let record = sink.write_part(&first_part).await.unwrap();
    state
        .record_upload_part(
            path,
            record.part_number,
            &record.etag,
            &record.checksum_sha256,
        )
        .unwrap();
    std::mem::forget(sink);
    drop(state);

    let outcome = a
        .sync_with(prefix, Arc::clone(&keys), &SyncOptions::default())
        .await;
    assert_eq!(
        outcome.uploads, 0,
        "the resumed upload replaces the planned one"
    );
    assert!(
        State::open(&a.root)
            .unwrap()
            .pending_uploads()
            .unwrap()
            .is_empty()
    );

    b.sync(prefix, Arc::clone(&keys)).await;
    assert_eq!(std::fs::read(b.root.join(path)).unwrap(), content);

    // A's next pass must agree it's in sync, not re-upload or delete anything.
    let outcome = a
        .sync_with(prefix, Arc::clone(&keys), &SyncOptions::default())
        .await;
    assert!(outcome.is_noop(), "{outcome:?}");
}
