//! Exercises the real `S3Store` against the MinIO instance from `docker-compose.yml`.
//! `#[ignore]`d so plain `cargo test` (no infra required) stays fast and self-contained;
//! run these explicitly with `cargo test -p mirror-core --test s3_integration -- --ignored`,
//! after `docker compose up -d` and with MinIO's credentials in the environment:
//!   AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin

use std::collections::BTreeSet;
use std::time::Duration;
use std::{path::Path, sync::Arc};

use mirror_core::apply::upload::resume_upload;
use mirror_core::config::Remote;
use mirror_core::crypto::content::{StreamingEncryptor, decrypt};
use mirror_core::crypto::filename;
use mirror_core::crypto::key::DerivedSubKeys;
use mirror_core::hash;
use mirror_core::placeholder;
use mirror_core::residency::Policy;
use mirror_core::state::State;
use mirror_core::store::s3::S3Store;
use mirror_core::store::{ObjectStore, PartSink, get_chunk_size};
use mirror_core::sync::SyncOptions;
use mirror_core::util::file::hash_stable;
use rand::Rng;

mod common;
use common::{
    Device, find_conflicted_copy, settle, sync_once, sync_read, sync_write, test_keys, tree_hashes,
};

// AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin cargo test -p mirror-core --test s3_integration -- --ignored --nocapture 2>&1 | tail -60

fn minio_remote(prefix: &str) -> Remote {
    Remote {
        bucket: "rfm-dev".to_string(),
        endpoint: Some("http://localhost:9000".to_string()),
        region: "us-east-1".to_string(),
        prefix: prefix.to_string(),
        path_style: true,
        profile: None,
    }
}

/// Self-healing: also guards against leftovers from a previous run that panicked
/// before it could clean up after itself.
async fn clean_prefix(store: &S3Store, prefix: &str) {
    for object in store.list(prefix, None).await.expect("list objects") {
        store.delete(&object.key).await.expect("delete object");
    }
}

#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn round_trip_against_minio() {
    let prefix = "it-round-trip/";
    let remote = minio_remote(prefix);

    let store = Arc::new(
        S3Store::connect(&remote)
            .await
            .expect("connect to MinIO — is docker compose up?"),
    );
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");

    clean_prefix(&store, prefix).await;

    let enc_keys = Arc::new(test_keys());

    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
    std::fs::write(root_a.path().join("b.txt"), b"two").unwrap();

    sync_once(
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await; // uploads a.txt, b.txt
    sync_once(
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await; // downloads both

    assert_eq!(
        std::fs::read(root_b.path().join("a.txt")).unwrap(),
        b"one".to_vec()
    );
    assert_eq!(
        std::fs::read(root_b.path().join("b.txt")).unwrap(),
        b"two".to_vec()
    );

    // mutate on A, both sides re-sync, B picks up the change
    std::fs::write(root_a.path().join("a.txt"), b"one-changed").unwrap();
    sync_once(
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;
    sync_once(
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;

    assert_eq!(
        std::fs::read(root_b.path().join("a.txt")).unwrap(),
        b"one-changed".to_vec()
    );

    // delete on A, both sides re-sync, B loses it too
    std::fs::remove_file(root_a.path().join("b.txt")).unwrap();
    sync_once(
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;
    sync_once(
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;

    assert!(!root_b.path().join("b.txt").exists());

    clean_prefix(&store, prefix).await; // leave the bucket as we found it
}
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn remote_conflict_resolves_cleanly() {
    let prefix = "it-remote-conflict/";
    let remote = minio_remote(prefix);

    let store = Arc::new(
        S3Store::connect(&remote)
            .await
            .expect("connect to MinIO — is docker compose up?"),
    );
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");

    clean_prefix(&store, prefix).await;

    let enc_keys = Arc::new(test_keys());

    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    // Both devices start out agreeing that a.txt = "one".
    std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
    sync_once(
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await; // A uploads "one"
    sync_once(
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await; // B downloads "one"

    // Each device now edits the same path, neither having seen the other.
    std::fs::write(root_a.path().join("a.txt"), b"edited by A").unwrap();
    std::fs::write(root_b.path().join("a.txt"), b"edited by B").unwrap();

    // The concurrent window: both read the log *before* either writes to it, so
    // both stamp base_hash = hash("one") and neither is aware of the other. This
    // interleaving is what makes it a remote conflict — had B read after A wrote,
    // B would have seen A's delta and raised a local-vs-remote conflict instead.
    let a_pending = sync_read(root_a.path(), store.as_ref(), prefix, &enc_keys).await;
    let b_pending = sync_read(root_b.path(), store.as_ref(), prefix, &enc_keys).await;

    sync_write(
        a_pending,
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;
    sync_write(
        b_pending,
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;

    // B synced second on the first pass, so B's lamport is higher and B's delta
    // wins. Note both devices wrote to the same deterministic object key, so the
    // stored bytes are whichever landed last — B's, which is also the winner's,
    // so the download below finds content matching the manifest.
    //
    // A is the loser, and is the only device holding the losing bytes, so A is
    // the only device that can preserve them.
    sync_once(
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;

    assert_eq!(
        std::fs::read(root_a.path().join("a.txt")).unwrap(),
        b"edited by B".to_vec(),
        "the winner keeps the original path"
    );

    let conflicted_a = find_conflicted_copy(root_a.path());
    assert_eq!(
        std::fs::read(&conflicted_a).unwrap(),
        b"edited by A".to_vec(),
        "the loser's content survives under the conflicted-copy name"
    );

    // Phase 4's exit criteria is that *both* devices converge on the same tree,
    // so B has to pick up the conflicted copy A published.
    sync_once(
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await;

    assert_eq!(
        std::fs::read(root_b.path().join("a.txt")).unwrap(),
        b"edited by B".to_vec()
    );

    let conflicted_b = find_conflicted_copy(root_b.path());
    assert_eq!(
        std::fs::read(&conflicted_b).unwrap(),
        b"edited by A".to_vec()
    );

    // Same name on both sides — the rename propagated through the log rather
    // than each device inventing its own.
    assert_eq!(conflicted_a.file_name(), conflicted_b.file_name());

    clean_prefix(&store, prefix).await; // leave the bucket as we found it
}

#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn multipart_upload_round_trips_a_large_file() {
    let prefix = "it-multipart/";
    let remote = minio_remote(prefix);

    let store = S3Store::connect(&remote)
        .await
        .expect("connect to MinIO — is docker compose up?");
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");

    clean_prefix(&store, prefix).await;

    // Comfortably above S3Store's 8 MB single-shot threshold, and big enough to
    // span multiple 5 MB parts (12 MB -> parts of 5, 5, and 2 MB) so the part-
    // boundary bookkeeping actually gets exercised, not just a single full part.
    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());

    let tmp = tempfile::tempdir().unwrap();

    let large_file = tmp.path().join("large.bin");
    std::fs::write(&large_file, &content).unwrap();

    let key = format!("{prefix}large.bin");

    store
        .put(&key, &large_file)
        .await
        .expect("multipart upload");

    let meta = store
        .head(&key)
        .await
        .expect("head object")
        .expect("object should exist after multipart upload");
    assert_eq!(meta.size, size as u64);

    let downloaded = store.get(&key).await.expect("download object");
    assert_eq!(downloaded, content);

    clean_prefix(&store, prefix).await; // leave the bucket as we found it
}

/// Unlike `multipart_upload_round_trips_a_large_file` above, this drives the sync
/// pipeline end to end (`apply::upload`/`download`) rather than calling `S3Store::put`
/// directly — that's what actually exercises `S3PartSink`/`PartSource`, and with them
/// the per-part SHA-256 checksums `write_part` now attaches and the composite checksum
/// `finish` now requires from `complete_multipart_upload`'s response. `put`'s own
/// `multipart_put` is a separate, older code path that doesn't request checksums at all.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn large_file_round_trips_through_streaming_multipart() {
    let prefix = "it-streaming-multipart/";
    let remote = minio_remote(prefix);

    let store = Arc::new(
        S3Store::connect(&remote)
            .await
            .expect("connect to MinIO — is docker compose up?"),
    );
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");

    clean_prefix(&store, prefix).await;

    let enc_keys = Arc::new(test_keys());

    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    // Comfortably above apply::upload's 8 MB single-shot threshold, and spanning
    // multiple parts, so both write_part's per-part checksum and finish's composite
    // checksum check actually run more than once.
    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());

    // sync a large number of files
    for i in 1..10 {
        std::fs::write(root_a.path().join(format!("large{}.bin", i)), &content).unwrap();
    }

    sync_once(
        root_a.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await; // uploads via S3PartSink
    sync_once(
        root_b.path(),
        Arc::clone(&store),
        prefix,
        Arc::clone(&enc_keys),
    )
    .await; // downloads via PartSource

    assert_eq!(
        std::fs::read(root_b.path().join("large1.bin")).unwrap(),
        content
    );

    clean_prefix(&store, prefix).await; // leave the bucket as we found it
}

/// Downloads `store_key` and decrypts it, asserting the result matches `content`
/// exactly — proof the object is actually correct, not just present.
async fn assert_object_decrypts_to(
    store: &S3Store,
    store_key: &str,
    enc_keys: &DerivedSubKeys,
    aad: &str,
    root: &Path,
    content: &[u8],
) {
    let downloaded = store.get(store_key).await.expect("download object");

    let ciphertext_path = root.join("downloaded.bin");
    std::fs::write(&ciphertext_path, &downloaded).unwrap();

    let decrypted_path = root.join("decrypted.bin");
    decrypt(
        &enc_keys.content_key,
        &ciphertext_path,
        &decrypted_path,
        aad,
    )
    .expect("resumed object should decrypt and authenticate correctly");

    assert_eq!(std::fs::read(decrypted_path).unwrap(), content);
}

/// Simulates a hard crash partway through a multipart upload — after the first
/// part has already reached S3 — and proves `resume_upload` picks up exactly
/// where it left off rather than either failing or corrupting the object.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn interrupted_upload_resumes_after_a_completed_part() {
    let prefix = "it-resume-with-part/";
    let remote = minio_remote(prefix);

    let store = Arc::new(
        S3Store::connect(&remote)
            .await
            .expect("connect to MinIO — is docker compose up?"),
    );
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");

    clean_prefix(&store, prefix).await;

    let enc_keys = test_keys();
    let root = tempfile::tempdir().unwrap();
    let path = "large.bin";

    // Comfortably above the 8 MB single-shot threshold, spanning multiple parts.
    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(root.path().join(path), &content).unwrap();

    let mut state = State::open(root.path()).unwrap();
    let content_hash = hash::hash_file(&root.path().join(path)).unwrap();
    let object_key = filename::object_key(&enc_keys.name_key, path, &content_hash).unwrap();
    let store_key = format!("{prefix}{object_key}");
    let chunk_size = get_chunk_size(size as u64);

    // --- Drive the low-level primitives directly, simulating a crash after the
    // first part reaches S3 but before the upload ever finishes or aborts. ---
    let mut encryptor =
        StreamingEncryptor::new(&enc_keys.content_key, &root.path().join(path), path, None)
            .unwrap();
    let nonce = encryptor.get_nonce();

    let mut part_sink = store.begin_put(&store_key).await.unwrap();

    state
        .record_upload_start(
            path,
            part_sink.upload_id(),
            chunk_size,
            content_hash,
            &nonce,
        )
        .unwrap();

    let encrypted = encryptor.encrypt_next_part(chunk_size).unwrap().unwrap();
    let mut first_part = nonce.to_vec();
    first_part.extend(encrypted.ciphertext);

    let part_record = part_sink.write_part(&first_part).await.unwrap();
    state
        .record_upload_part(
            path,
            part_record.part_number,
            &part_record.etag,
            &part_record.checksum_sha256,
        )
        .unwrap();

    // Neither finish() nor abort() ever runs, and mem::forget defeats the Drop
    // guard that would otherwise abort the multipart upload for us — a real
    // `kill -9` never gives Drop::drop a chance to run either.
    std::mem::forget(part_sink);
    drop(encryptor);

    // --- "Restart": read back what an interrupted process left behind and resume it. ---
    let pending = state.pending_uploads().unwrap();
    assert_eq!(pending.len(), 1, "the interrupted upload should be tracked");
    assert_eq!(pending[0].completed_parts.len(), 1);

    let stats = hash_stable(&root.path().join(path)).unwrap().unwrap();

    resume_upload(
        store.as_ref(),
        &pending[0],
        stats,
        &enc_keys,
        root.path(),
        prefix,
        &mut state,
    )
    .await
    .expect("resume should complete the upload");

    assert!(
        state.pending_uploads().unwrap().is_empty(),
        "tracking should be cleared once the resumed upload finishes"
    );

    assert_object_decrypts_to(&store, &store_key, &enc_keys, path, root.path(), &content).await;

    clean_prefix(&store, prefix).await;
}

/// Same idea, but the crash happens before even the first part reaches S3 — the
/// exact edge case that used to hard-error instead of resuming from part 1.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn interrupted_upload_resumes_before_any_part_completed() {
    let prefix = "it-resume-no-parts/";
    let remote = minio_remote(prefix);

    let store = Arc::new(
        S3Store::connect(&remote)
            .await
            .expect("connect to MinIO — is docker compose up?"),
    );
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");

    clean_prefix(&store, prefix).await;

    let enc_keys = test_keys();
    let root = tempfile::tempdir().unwrap();
    let path = "large.bin";

    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(root.path().join(path), &content).unwrap();

    let mut state = State::open(root.path()).unwrap();
    let content_hash = hash::hash_file(&root.path().join(path)).unwrap();
    let object_key = filename::object_key(&enc_keys.name_key, path, &content_hash).unwrap();
    let store_key = format!("{prefix}{object_key}");
    let chunk_size = get_chunk_size(size as u64);

    let encryptor =
        StreamingEncryptor::new(&enc_keys.content_key, &root.path().join(path), path, None)
            .unwrap();
    let nonce = encryptor.get_nonce();

    // Create the multipart upload and record it as started, then "crash" before
    // a single part is ever written.
    let part_sink = store.begin_put(&store_key).await.unwrap();

    state
        .record_upload_start(
            path,
            part_sink.upload_id(),
            chunk_size,
            content_hash,
            &nonce,
        )
        .unwrap();

    std::mem::forget(part_sink);
    drop(encryptor);

    let pending = state.pending_uploads().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(
        pending[0].completed_parts.is_empty(),
        "no parts should be recorded yet"
    );

    let stats = hash_stable(&root.path().join(path)).unwrap().unwrap();

    resume_upload(
        store.as_ref(),
        &pending[0],
        stats,
        &enc_keys,
        root.path(),
        prefix,
        &mut state,
    )
    .await
    .expect("resume should complete the upload even with zero completed parts");

    assert!(state.pending_uploads().unwrap().is_empty());

    assert_object_decrypts_to(&store, &store_key, &enc_keys, path, root.path(), &content).await;

    clean_prefix(&store, prefix).await;
}

/// Connects to MinIO, empties `prefix`, and returns `count` devices sharing it.
async fn minio_devices(
    prefix: &str,
    count: usize,
) -> (Arc<S3Store>, Vec<tempfile::TempDir>, Vec<Device<S3Store>>) {
    let store = Arc::new(
        S3Store::connect(&minio_remote(prefix))
            .await
            .expect("connect to MinIO — is docker compose up?"),
    );
    store
        .check()
        .await
        .expect("bucket reachable — is docker compose up, credentials set?");
    clean_prefix(&store, prefix).await;

    let dirs: Vec<tempfile::TempDir> = (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
    let devices = dirs
        .iter()
        .map(|dir| Device {
            root: dir.path().to_path_buf(),
            store: Arc::clone(&store),
        })
        .collect();

    (store, dirs, devices)
}

async fn bucket_keys(store: &S3Store, prefix: &str) -> Vec<String> {
    store
        .list(prefix, None)
        .await
        .expect("list objects")
        .into_iter()
        .map(|meta| meta.key)
        .collect()
}

fn stub(root: &Path, path: &str) -> std::path::PathBuf {
    root.join(format!("{path}.rfm"))
}

fn evicted_paths(root: &Path) -> BTreeSet<String> {
    State::open(root)
        .unwrap()
        .baseline()
        .unwrap()
        .into_values()
        .filter(|record| record.is_evicted())
        .map(|record| record.path)
        .collect()
}

/// A multipart-sized file is evicted (with full remote verification, so the real
/// streaming download path runs) and hydrated back, without touching the bucket.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn evict_and_hydrate_a_multipart_file_against_minio() {
    let prefix = "it-evict-hydrate/";
    let (store, _dirs, devices) = minio_devices(prefix, 2).await;
    let (a, b) = (&devices[0], &devices[1]);
    let keys = Arc::new(test_keys());

    let mut content = vec![0u8; 12 * 1024 * 1024];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(a.root.join("large.bin"), &content).unwrap();
    std::fs::write(a.root.join("small.txt"), b"small").unwrap();
    settle(&devices, prefix, &keys).await;

    let before = bucket_keys(&store, prefix).await;
    let options = SyncOptions {
        evict: BTreeSet::from(["large.bin".to_string()]),
        verify_before_evict: true,
        ..SyncOptions::default()
    };
    let outcome = a.sync_with(prefix, Arc::clone(&keys), &options).await;

    assert_eq!(outcome.evicted, 1, "{:?}", outcome.not_evicted);
    assert!(outcome.bytes_freed >= content.len() as u64 / 2);
    assert!(!a.root.join("large.bin").exists());
    let meta = placeholder::read(&stub(&a.root, "large.bin")).expect("placeholder");
    assert_eq!(meta.size, content.len() as u64);

    settle(&devices, prefix, &keys).await;
    assert_eq!(
        bucket_keys(&store, prefix).await,
        before,
        "eviction is device-local"
    );
    assert_eq!(std::fs::read(b.root.join("large.bin")).unwrap(), content);

    let outcome = a.hydrate(prefix, Arc::clone(&keys), "large.bin").await;
    assert_eq!(outcome.hydrated, 1);
    assert_eq!(std::fs::read(a.root.join("large.bin")).unwrap(), content);
    assert!(!stub(&a.root, "large.bin").exists());
    assert_eq!(tree_hashes(&a.root), tree_hashes(&b.root));

    clean_prefix(&store, prefix).await;
}

/// A device joining online-only gets placeholders; a placeholder it renames is
/// re-encrypted under the new path on the real backend.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn online_only_device_and_moved_placeholder_against_minio() {
    let prefix = "it-online-only/";
    let (store, _dirs, devices) = minio_devices(prefix, 2).await;
    let (a, b) = (&devices[0], &devices[1]);
    let keys = Arc::new(test_keys());

    std::fs::write(a.root.join("one.txt"), b"one").unwrap();
    std::fs::write(a.root.join("two.txt"), b"two").unwrap();
    a.sync(prefix, Arc::clone(&keys)).await;

    let online_only = SyncOptions {
        policy: Policy::new(&[], &[], &[], true).unwrap(),
        ..SyncOptions::default()
    };
    let outcome = b.sync_with(prefix, Arc::clone(&keys), &online_only).await;
    assert_eq!(outcome.placeholders, 2);
    assert_eq!(outcome.downloads, 0);
    assert!(tree_hashes(&b.root).is_empty());

    std::fs::rename(stub(&b.root, "one.txt"), stub(&b.root, "renamed.txt")).unwrap();
    let outcome = b.sync_with(prefix, Arc::clone(&keys), &online_only).await;
    assert_eq!(outcome.relocated, 1);
    assert_eq!(outcome.deletes_remote, 1);
    assert!(evicted_paths(&b.root).contains("renamed.txt"));

    a.sync(prefix, Arc::clone(&keys)).await;
    assert!(!a.root.join("one.txt").exists());
    assert_eq!(std::fs::read(a.root.join("renamed.txt")).unwrap(), b"one");

    let outcome = b.hydrate(prefix, Arc::clone(&keys), "renamed.txt").await;
    assert_eq!(outcome.hydrated, 1);
    assert_eq!(std::fs::read(b.root.join("renamed.txt")).unwrap(), b"one");

    clean_prefix(&store, prefix).await;
}

/// Deleting a placeholder only tombstones the file; compaction GC (using MinIO's
/// real `last_modified`) reclaims superseded versions but never referenced ones.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn placeholder_delete_and_object_gc_against_minio() {
    let prefix = "it-tombstone-gc/";
    let (store, _dirs, devices) = minio_devices(prefix, 2).await;
    let (a, b) = (&devices[0], &devices[1]);
    let keys = Arc::new(test_keys());
    let data_keys = |keys: Vec<String>| -> BTreeSet<String> {
        keys.into_iter().filter(|k| k.contains("/data/")).collect()
    };

    std::fs::write(a.root.join("gone.txt"), b"gone").unwrap();
    std::fs::write(a.root.join("edited.txt"), b"v1").unwrap();
    settle(&devices, prefix, &keys).await;
    let v1_objects = data_keys(bucket_keys(&store, prefix).await);
    assert_eq!(v1_objects.len(), 2);

    a.evict(prefix, Arc::clone(&keys), "gone.txt").await;
    std::fs::remove_file(stub(&a.root, "gone.txt")).unwrap();
    std::fs::write(b.root.join("edited.txt"), b"v2").unwrap();
    settle(&devices, prefix, &keys).await;

    assert!(!b.root.join("gone.txt").exists());
    let after_edit = data_keys(bucket_keys(&store, prefix).await);
    assert!(
        after_edit.is_superset(&v1_objects),
        "a delete must not remove objects"
    );
    assert_eq!(after_edit.len(), 3);

    // Zero grace and zero retention: only the superseded `edited.txt` v1 is unreferenced.
    a.compact(prefix, Arc::clone(&keys), Duration::ZERO).await;
    let after_gc = data_keys(bucket_keys(&store, prefix).await);
    assert_eq!(after_gc.len(), 2, "{after_gc:?}");

    // Everything still referenced stays readable.
    let fresh = tempfile::tempdir().unwrap();
    let c = Device {
        root: fresh.path().to_path_buf(),
        store: Arc::clone(&store),
    };
    c.sync(prefix, Arc::clone(&keys)).await;
    assert_eq!(std::fs::read(c.root.join("edited.txt")).unwrap(), b"v2");
    assert!(!c.root.join("gone.txt").exists());

    clean_prefix(&store, prefix).await;
}

/// Plan §6 on the real backend: the loser of a concurrent edit had already evicted
/// its version, which comes back from its own object key as a conflicted copy.
#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn evicted_conflict_loser_is_relocated_against_minio() {
    let prefix = "it-evicted-loser/";
    let (store, _dirs, devices) = minio_devices(prefix, 2).await;
    let (a, b) = (&devices[0], &devices[1]);
    let keys = Arc::new(test_keys());

    std::fs::write(a.root.join("f.txt"), b"v1").unwrap();
    settle(&devices, prefix, &keys).await;
    // Every pass advances a device's Lamport clock, so B wins the coming conflict.
    for _ in 0..3 {
        b.sync(prefix, Arc::clone(&keys)).await;
    }

    std::fs::write(a.root.join("f.txt"), b"from-a").unwrap();
    std::fs::write(b.root.join("f.txt"), b"from-b").unwrap();
    let pending_a = sync_read(&a.root, store.as_ref(), prefix, &keys).await;
    let pending_b = sync_read(&b.root, store.as_ref(), prefix, &keys).await;
    sync_write(
        pending_a,
        &a.root,
        Arc::clone(&store),
        prefix,
        Arc::clone(&keys),
    )
    .await;

    assert_eq!(a.evict(prefix, Arc::clone(&keys), "f.txt").await.evicted, 1);
    sync_write(
        pending_b,
        &b.root,
        Arc::clone(&store),
        prefix,
        Arc::clone(&keys),
    )
    .await;

    let outcome = a
        .sync_with(prefix, Arc::clone(&keys), &SyncOptions::default())
        .await;
    assert_eq!(outcome.relocated, 1, "the evicted loser must be relocated");

    settle(&devices, prefix, &keys).await;
    for device in &devices {
        let options = SyncOptions {
            hydrate: evicted_paths(&device.root),
            ..SyncOptions::default()
        };
        device.sync_with(prefix, Arc::clone(&keys), &options).await;
    }
    settle(&devices, prefix, &keys).await;

    assert_eq!(std::fs::read(a.root.join("f.txt")).unwrap(), b"from-b");
    assert_eq!(
        std::fs::read(find_conflicted_copy(&a.root)).unwrap(),
        b"from-a"
    );
    assert_eq!(tree_hashes(&a.root), tree_hashes(&b.root));

    clean_prefix(&store, prefix).await;
}
