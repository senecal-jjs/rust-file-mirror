//! Backup, verify, and restore against the MinIO instance from `docker-compose.yml`.
//! `#[ignore]`d like mirror-core's S3 tests; run with:
//!   docker compose up -d
//!   AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
//!     cargo test -p backup-core --test s3_integration -- --ignored

use std::fs;
use std::sync::Arc;

use backup_core::archiver::{self, Options as BackupOptions};
use backup_core::crypto::Keys;
use backup_core::index;
use backup_core::repo::{self, InitOptions, Repository};
use backup_core::restorer::{self, Options as RestoreOptions};
use backup_core::verify::{self, Options as VerifyOptions};
use mirror_core::config::Remote;
use mirror_core::store::ObjectStore;
use mirror_core::store::s3::S3Store;
use rand::{Rng, SeedableRng};
use secrecy::SecretBox;

async fn minio(prefix: &str) -> Arc<S3Store> {
    let store = S3Store::connect(&Remote {
        bucket: "rfm-dev".into(),
        endpoint: Some("http://localhost:9000".into()),
        region: "us-east-1".into(),
        prefix: prefix.into(),
        path_style: true,
        profile: None,
    })
    .await
    .expect("connect to MinIO");
    for object in store.list(prefix, None).await.expect("list") {
        store.delete(&object.key).await.expect("delete");
    }
    Arc::new(store)
}

fn keys() -> Keys {
    Keys::derive(&SecretBox::new(Box::new([11; 32])))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires MinIO: docker compose up -d, plus AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY=minioadmin"]
async fn backup_verify_restore_against_minio() {
    let prefix = "it-backup/";
    let store = minio(prefix).await;

    let src = tempfile::tempdir().unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let mut big = vec![0u8; 6 * 1024 * 1024];
    rng.fill(&mut big[..]);
    fs::write(src.path().join("big.bin"), &big).unwrap();
    fs::create_dir(src.path().join("sub")).unwrap();
    for i in 0..50 {
        fs::write(
            src.path().join(format!("sub/small{i}")),
            format!("small {i}"),
        )
        .unwrap();
    }

    let mut repo = Repository::init(
        Arc::clone(&store),
        prefix,
        keys(),
        InitOptions::default(),
        None,
    )
    .await
    .unwrap();
    repo.set_pack_target(2 * 1024 * 1024); // several packs from one big file
    let repo = Arc::new(repo);
    let first = archiver::backup(
        Arc::clone(&repo),
        &[src.path().to_path_buf()],
        BackupOptions::default(),
    )
    .await
    .unwrap();

    // A second process: incremental backup reads nothing.
    let repo = Arc::new(
        Repository::open(Arc::clone(&store), prefix, keys(), None)
            .await
            .unwrap(),
    );
    let second = archiver::backup(
        Arc::clone(&repo),
        &[src.path().to_path_buf()],
        BackupOptions {
            parent: Some(first.clone()),
            ..BackupOptions::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(second.stats.files_unmodified, 51);
    assert_eq!(second.stats.bytes_added, 0);

    let report = verify::verify(
        &repo,
        VerifyOptions {
            read_data: true,
            ..VerifyOptions::default()
        },
    )
    .await
    .unwrap();
    assert!(report.ok(), "{:?}", report.problems);
    assert!(report.packs_in_storage >= 3);

    // The packs alone are enough to rebuild the index.
    let base = repo::base(prefix);
    let rebuilt = index::rebuild(store.as_ref(), &base, &keys())
        .await
        .unwrap();
    assert_eq!(rebuilt.len(), repo.index().len());

    let dst = tempfile::tempdir().unwrap();
    let stats = restorer::restore(
        Arc::clone(&repo),
        &second,
        dst.path(),
        RestoreOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(stats.files, 51);
    let restored = dst.path().join(
        std::path::absolute(src.path())
            .unwrap()
            .strip_prefix("/")
            .unwrap(),
    );
    assert_eq!(fs::read(restored.join("big.bin")).unwrap(), big);
    assert_eq!(fs::read(restored.join("sub/small42")).unwrap(), b"small 42");

    for object in store.list(prefix, None).await.unwrap() {
        store.delete(&object.key).await.unwrap();
    }
}
