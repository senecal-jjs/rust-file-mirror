//! Exercises the real `S3Store` against the MinIO instance from `docker-compose.yml`.
//! `#[ignore]`d so plain `cargo test` (no infra required) stays fast and self-contained;
//! run these explicitly with `cargo test -p mirror-core --test s3_integration -- --ignored`,
//! after `docker compose up -d` and with MinIO's credentials in the environment:
//!   AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin

use std::path::Path;

use mirror_core::apply::apply;
use mirror_core::config::Remote;
use mirror_core::engine::reconcile;
use mirror_core::manifest;
use mirror_core::scanner::Scanner;
use mirror_core::state::State;
use mirror_core::store::ObjectStore;
use mirror_core::store::s3::S3Store;
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

async fn sync_once(
    root: &Path,
    store: &S3Store,
    prefix: &str,
    content_key: &SecretBox<[u8; 32]>,
    manifest_key: &SecretBox<[u8; 32]>,
) {
    let mut state = State::open(root).expect("open state");
    let baseline = state.baseline().expect("read baseline");

    let scanner = Scanner::new(root, ".mirrorignore");
    let entries = scanner.scan(&baseline).expect("scan local tree");

    let remote = manifest::from_store(store, manifest_key, prefix)
        .await
        .expect("build remote manifest");
    let plan = reconcile(&entries, &baseline, &remote);

    apply(&plan, store, root, prefix, &mut state, &remote, content_key)
        .await
        .expect("apply plan");
    state.record_scan(&entries).expect("record scan");
}

#[tokio::test]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn round_trip_against_minio() {
    let prefix = "it-round-trip/";
    let remote = minio_remote(prefix);

    let store = S3Store::connect(&remote)
        .await
        .expect("connect to MinIO — is docker compose up?");
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

    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
    std::fs::write(root_a.path().join("b.txt"), b"two").unwrap();

    sync_once(root_a.path(), &store, prefix, &content_key, &manifest_key).await; // uploads a.txt, b.txt
    sync_once(root_b.path(), &store, prefix, &content_key, &manifest_key).await; // downloads both

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
    sync_once(root_a.path(), &store, prefix, &content_key, &manifest_key).await;
    sync_once(root_b.path(), &store, prefix, &content_key, &manifest_key).await;

    assert_eq!(
        std::fs::read(root_b.path().join("a.txt")).unwrap(),
        b"one-changed".to_vec()
    );

    // delete on A, both sides re-sync, B loses it too
    std::fs::remove_file(root_a.path().join("b.txt")).unwrap();
    sync_once(root_a.path(), &store, prefix, &content_key, &manifest_key).await;
    sync_once(root_b.path(), &store, prefix, &content_key, &manifest_key).await;

    assert!(!root_b.path().join("b.txt").exists());

    clean_prefix(&store, prefix).await; // leave the bucket as we found it
}
