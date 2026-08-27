//! Exercises the real `S3Store` against the MinIO instance from `docker-compose.yml`.
//! `#[ignore]`d so plain `cargo test` (no infra required) stays fast and self-contained;
//! run these explicitly with `cargo test -p mirror-core --test s3_integration -- --ignored`,
//! after `docker compose up -d` and with MinIO's credentials in the environment:
//!   AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin

use std::{path::Path, sync::Arc};

use mirror_core::apply::apply;
use mirror_core::apply::upload::resume_upload;
use mirror_core::config::Remote;
use mirror_core::crypto::content::{StreamingEncryptor, decrypt};
use mirror_core::crypto::filename;
use mirror_core::crypto::key::DerivedSubKeys;
use mirror_core::engine::reconcile;
use mirror_core::hash;
use mirror_core::indicator::PrintReporter;
use mirror_core::manifest;
use mirror_core::scanner::Scanner;
use mirror_core::state::State;
use mirror_core::store::s3::S3Store;
use mirror_core::store::{ObjectStore, PartSink, get_chunk_size};
use mirror_core::util::file::hash_stable;
use rand::Rng;
use secrecy::SecretBox;

// AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin cargo test -p mirror-core --test s3_integration -- --ignored --nocapture 2>&1 | tail -60

fn minio_remote(prefix: &str) -> Remote {
    Remote {
        bucket: "rfm-dev".to_string(),
        endpoint: Some("http://localhost:9000".to_string()),
        region: "us-east-1".to_string(),
        prefix: prefix.to_string(),
        path_style: true,
    }
}

/// Self-healing: also guards against leftovers from a previous run that panicked
/// before it could clean up after itself.
async fn clean_prefix(store: &S3Store, prefix: &str) {
    for object in store.list(prefix).await.expect("list objects") {
        store.delete(&object.key).await.expect("delete object");
    }
}

async fn sync_once(root: &Path, store: Arc<S3Store>, prefix: &str, enc_keys: Arc<DerivedSubKeys>) {
    let mut state = State::open(root).expect("open state");
    let baseline = state.baseline().expect("read baseline");

    let scanner = Scanner::new(root, ".mirrorignore");
    let entries = scanner.scan(&baseline).expect("scan local tree");

    let mut remote =
        manifest::from_store(store.as_ref(), &enc_keys.manifest_key, prefix, &mut state)
            .await
            .expect("build remote manifest");
    let plan = reconcile(&entries, &baseline, &remote);
    let reporter = PrintReporter {};

    apply(
        &plan,
        store,
        root.to_path_buf(),
        prefix.to_string(),
        &mut state,
        &mut remote,
        enc_keys,
        Arc::new(reporter),
    )
    .await
    .expect("apply plan");
    state.record_scan(&entries).expect("record scan");
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

    let mut content_key_bytes = [0u8; 32];
    rand::rng().fill(&mut content_key_bytes);
    let content_key = SecretBox::new(Box::new(content_key_bytes));

    let mut manifest_key_bytes = [0u8; 32];
    rand::rng().fill(&mut manifest_key_bytes);
    let manifest_key = SecretBox::new(Box::new(manifest_key_bytes));

    let mut name_key_bytes = [0u8; 32];
    rand::rng().fill(&mut name_key_bytes);
    let name_key = SecretBox::new(Box::new(name_key_bytes));

    let mut keycheck_bytes = [0u8; 32];
    rand::rng().fill(&mut keycheck_bytes);
    let keycheck_bytes = SecretBox::new(Box::new(keycheck_bytes));

    let enc_keys = Arc::new(DerivedSubKeys {
        content_key,
        name_key,
        manifest_key,
        keycheck_bytes,
    });

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

    let mut content_key_bytes = [0u8; 32];
    rand::rng().fill(&mut content_key_bytes);
    let content_key = SecretBox::new(Box::new(content_key_bytes));

    let mut manifest_key_bytes = [0u8; 32];
    rand::rng().fill(&mut manifest_key_bytes);
    let manifest_key = SecretBox::new(Box::new(manifest_key_bytes));

    let mut name_key_bytes = [0u8; 32];
    rand::rng().fill(&mut name_key_bytes);
    let name_key = SecretBox::new(Box::new(name_key_bytes));

    let mut keycheck_bytes = [0u8; 32];
    rand::rng().fill(&mut keycheck_bytes);
    let keycheck_bytes = SecretBox::new(Box::new(keycheck_bytes));

    let enc_keys = Arc::new(DerivedSubKeys {
        content_key,
        name_key,
        manifest_key,
        keycheck_bytes,
    });

    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    // Comfortably above apply::upload's 8 MB single-shot threshold, and spanning
    // multiple parts, so both write_part's per-part checksum and finish's composite
    // checksum check actually run more than once.
    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(root_a.path().join("large.bin"), &content).unwrap();

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
        std::fs::read(root_b.path().join("large.bin")).unwrap(),
        content
    );

    clean_prefix(&store, prefix).await; // leave the bucket as we found it
}

fn resume_test_keys() -> DerivedSubKeys {
    let mut content_key_bytes = [0u8; 32];
    rand::rng().fill(&mut content_key_bytes);

    let mut name_key_bytes = [0u8; 32];
    rand::rng().fill(&mut name_key_bytes);

    let mut manifest_key_bytes = [0u8; 32];
    rand::rng().fill(&mut manifest_key_bytes);

    let mut keycheck_bytes = [0u8; 32];
    rand::rng().fill(&mut keycheck_bytes);

    DerivedSubKeys {
        content_key: SecretBox::new(Box::new(content_key_bytes)),
        name_key: SecretBox::new(Box::new(name_key_bytes)),
        manifest_key: SecretBox::new(Box::new(manifest_key_bytes)),
        keycheck_bytes: SecretBox::new(Box::new(keycheck_bytes)),
    }
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

    let enc_keys = resume_test_keys();
    let root = tempfile::tempdir().unwrap();
    let path = "large.bin";

    // Comfortably above the 8 MB single-shot threshold, spanning multiple parts.
    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(root.path().join(path), &content).unwrap();

    let mut state = State::open(root.path()).unwrap();
    let object_key = filename::object_key(&enc_keys.name_key, path).unwrap();
    let store_key = format!("{prefix}{object_key}");
    let chunk_size = get_chunk_size(size as u64);

    // --- Drive the low-level primitives directly, simulating a crash after the
    // first part reaches S3 but before the upload ever finishes or aborts. ---
    let mut encryptor =
        StreamingEncryptor::new(&enc_keys.content_key, &root.path().join(path), path, None)
            .unwrap();
    let nonce = encryptor.get_nonce();

    let mut part_sink = store.begin_put(&store_key).await.unwrap();
    let content_hash = hash::hash_file(&root.path().join(path)).unwrap();

    state
        .record_upload_start(
            path,
            part_sink.upload_id(),
            chunk_size,
            content_hash,
            &nonce,
        )
        .unwrap();

    let cipher_text = encryptor.encrypt_next_part(chunk_size).unwrap().unwrap();
    let mut first_part = nonce.to_vec();
    first_part.extend(cipher_text);

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

    let enc_keys = resume_test_keys();
    let root = tempfile::tempdir().unwrap();
    let path = "large.bin";

    let size = 12 * 1024 * 1024;
    let mut content = vec![0u8; size];
    rand::rng().fill(content.as_mut_slice());
    std::fs::write(root.path().join(path), &content).unwrap();

    let mut state = State::open(root.path()).unwrap();
    let object_key = filename::object_key(&enc_keys.name_key, path).unwrap();
    let store_key = format!("{prefix}{object_key}");
    let chunk_size = get_chunk_size(size as u64);

    let encryptor =
        StreamingEncryptor::new(&enc_keys.content_key, &root.path().join(path), path, None)
            .unwrap();
    let nonce = encryptor.get_nonce();

    // Create the multipart upload and record it as started, then "crash" before
    // a single part is ever written.
    let part_sink = store.begin_put(&store_key).await.unwrap();
    let content_hash = hash::hash_file(&root.path().join(path)).unwrap();

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
