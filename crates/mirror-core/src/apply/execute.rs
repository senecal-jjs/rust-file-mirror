use std::path::Path;

use crate::{
    Error,
    apply::{
        conflict::conflict, delete_local::delete_local, delete_remote::delete_remote,
        download::download, upload::upload,
    },
    crypto::key::DerivedSubKeys,
    engine::{ActionKind, Plan},
    error::Result,
    manifest::{self, Manifest},
    state::State,
    store::ObjectStore,
};

pub async fn apply<S: ObjectStore>(
    plan: &Plan,
    store: &S,
    root: &Path,
    prefix: &str,
    state: &mut State,
    manifest: &mut Manifest,
    enc_keys: &DerivedSubKeys,
) -> Result<()> {
    for action in &plan.actions {
        match action.kind {
            ActionKind::Download => {
                let entry = manifest.get(&action.path).ok_or_else(|| {
                    Error::Store(format!("no remote manifest entry for {}", action.path))
                })?;

                download(
                    store,
                    root,
                    state,
                    prefix,
                    entry,
                    action,
                    &enc_keys.content_key,
                )
                .await?
            }
            ActionKind::Upload => {
                upload(store, root, action, state, enc_keys, manifest, prefix).await?
            }
            ActionKind::DeleteLocal => delete_local(root, action, state).await?,
            ActionKind::DeleteRemote => {
                delete_remote(store, action, prefix, state, manifest).await?
            }
            ActionKind::Conflict => conflict(action)?,
        }
    }

    manifest::to_store(manifest, store, &enc_keys.manifest_key, prefix, state).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use rand::{Rng, rng};
    use secrecy::SecretBox;

    use super::*;
    use crate::{
        crypto::{
            content::{decrypt, encrypt},
            filename,
        },
        engine::{Action, reconcile},
        hash,
        manifest::{self, ManifestEntry},
        scanner::Scanner,
        store::memory::MemoryStore,
    };

    #[tokio::test]
    async fn download_writes_file_and_confirms_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let store = MemoryStore::new();
        let src = root.join("src.txt");
        std::fs::write(&src, b"hello").unwrap();

        let mut content_enc_key = [0u8; 32];
        rng().fill(&mut content_enc_key);
        let content_enc_key = SecretBox::new(Box::new(content_enc_key));

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        // download decrypts whatever it fetches, so the store needs to actually
        // hold ciphertext produced under the same key — not the raw plaintext.
        let content_hash = hash::hash_file(&src).unwrap();
        let ciphertext = tmp.path().join("ciphertext.bin");
        let object_key = filename::object_key(&name_enc_key, src.to_str().unwrap()).unwrap();
        let prefix = "rfm/";
        let store_key = format!("{prefix}{}", object_key);

        encrypt(&content_enc_key, &src, &ciphertext, "a.txt").unwrap();
        store.put(&store_key, &ciphertext).await.unwrap();

        let mut state = State::open(root).unwrap();
        let entry = ManifestEntry {
            path: "a.txt".to_string(),
            content_hash,
            size: 5,
            object_key,
        };
        let action = Action {
            path: "a.txt".to_string(),
            kind: ActionKind::Download,
        };

        download(
            &store,
            root,
            &mut state,
            "rfm/",
            &entry,
            &action,
            &content_enc_key,
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(root.join("a.txt")).unwrap(),
            b"hello".to_vec()
        );

        let baseline = state.baseline().unwrap();
        assert_eq!(baseline["a.txt"].last_synced_hash, Some(entry.content_hash));
    }

    #[tokio::test]
    async fn upload_puts_file_and_confirms_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.txt"), b"hello").unwrap();

        let store = MemoryStore::new();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "a.txt".to_string(),
            kind: ActionKind::Upload,
        };

        let mut content_enc_key = [0u8; 32];
        rng().fill(&mut content_enc_key);
        let content_enc_key = SecretBox::new(Box::new(content_enc_key));

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let enc_keys = DerivedSubKeys {
            content_key: content_enc_key,
            name_key: name_enc_key,
            manifest_key: SecretBox::new(Box::new([0u8; 32])),
            keycheck_bytes: SecretBox::new(Box::new([0u8; 32])),
        };

        let mut manifest = Manifest::new();
        let prefix = "rfm/";

        upload(
            &store,
            root,
            &action,
            &mut state,
            &enc_keys,
            &mut manifest,
            prefix,
        )
        .await
        .unwrap();

        // What's stored is ciphertext, not the plaintext bytes — round-trip it back
        // through decrypt to confirm the upload actually encrypted correctly.
        let object_key = manifest.get("a.txt").unwrap().object_key.clone();
        let store_key = format!("{prefix}{object_key}");
        let ciphertext = store.get(&store_key).await.unwrap();
        assert_ne!(ciphertext, b"hello".to_vec());

        let ciphertext_path = tmp.path().join("ciphertext.bin");
        std::fs::write(&ciphertext_path, &ciphertext).unwrap();
        let decrypted_path = tmp.path().join("decrypted.txt");
        decrypt(
            &enc_keys.content_key,
            &ciphertext_path,
            &decrypted_path,
            "a.txt",
        )
        .unwrap();

        assert_eq!(std::fs::read(decrypted_path).unwrap(), b"hello".to_vec());

        let baseline = state.baseline().unwrap();
        assert!(baseline["a.txt"].last_synced_hash.is_some());
    }

    #[tokio::test]
    async fn delete_local_is_idempotent_on_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "missing.txt".to_string(),
            kind: ActionKind::DeleteLocal,
        };

        delete_local(root, &action, &mut state).await.unwrap();
        delete_local(root, &action, &mut state).await.unwrap();
    }

    #[tokio::test]
    async fn delete_remote_is_idempotent_on_missing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let store = MemoryStore::new();
        let mut state = State::open(root).unwrap();
        let action = Action {
            path: "missing.txt".to_string(),
            kind: ActionKind::DeleteRemote,
        };
        let mut manifest = Manifest::new();
        let store_key = format!("rfm/{}", action.path);

        manifest.insert(
            store_key,
            ManifestEntry {
                path: action.path.clone(),
                size: 0,
                content_hash: hash::hash_bytes(&[0u8; 32]),
                object_key: "doesnt matter".to_string(),
            },
        );

        delete_remote(&store, &action, "rfm/", &mut state, &mut manifest)
            .await
            .unwrap();
        delete_remote(&store, &action, "rfm/", &mut state, &mut manifest)
            .await
            .unwrap();
    }

    /// Phase 1's stated exit criteria, as a test: sync a tree, mutate, re-sync;
    /// a second empty root converges to an identical tree via a shared `MemoryStore`.
    #[tokio::test]
    async fn round_trip_two_devices_converge() {
        async fn sync_once(
            root: &Path,
            store: &MemoryStore,
            prefix: &str,
            enc_keys: &DerivedSubKeys,
        ) {
            let mut state = State::open(root).unwrap();
            let baseline = state.baseline().unwrap();

            let scanner = Scanner::new(root, ".mirrorignore");
            let entries = scanner.scan(&baseline).unwrap();

            let mut manifest =
                manifest::from_store(store, &enc_keys.manifest_key, prefix, &mut state)
                    .await
                    .unwrap();
            let plan = reconcile(&entries, &baseline, &manifest);

            apply(
                &plan,
                store,
                root,
                prefix,
                &mut state,
                &mut manifest,
                enc_keys,
            )
            .await
            .unwrap();
            state.record_scan(&entries).unwrap();
        }

        let root_a = tempfile::tempdir().unwrap();
        let root_b = tempfile::tempdir().unwrap();
        let store = MemoryStore::new();
        let prefix = "rfm/";

        // Both "devices" share one derived key, same as two machines deriving the
        // same content key from the same passphrase — a fresh key per sync_once
        // call would mean root_a and root_b can never decrypt each other's uploads.
        let mut content_enc_key = [0u8; 32];
        rng().fill(&mut content_enc_key);
        let content_enc_key = SecretBox::new(Box::new(content_enc_key));

        let mut manifest_enc_key = [0u8; 32];
        rng().fill(&mut manifest_enc_key);
        let manifest_enc_key = SecretBox::new(Box::new(manifest_enc_key));

        let mut name_enc_key = [0u8; 32];
        rng().fill(&mut name_enc_key);
        let name_enc_key = SecretBox::new(Box::new(name_enc_key));

        let mut keycheck_bytes = [0u8; 32];
        rng().fill(&mut keycheck_bytes);
        let keycheck_bytes = SecretBox::new(Box::new(keycheck_bytes));

        std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
        std::fs::write(root_a.path().join("b.txt"), b"two").unwrap();

        let enc_keys = DerivedSubKeys {
            content_key: content_enc_key,
            name_key: name_enc_key,
            manifest_key: manifest_enc_key,
            keycheck_bytes,
        };

        sync_once(root_a.path(), &store, prefix, &enc_keys).await; // uploads a.txt, b.txt
        sync_once(root_b.path(), &store, prefix, &enc_keys).await; // downloads both

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
        sync_once(root_a.path(), &store, prefix, &enc_keys).await;
        sync_once(root_b.path(), &store, prefix, &enc_keys).await;

        assert_eq!(
            std::fs::read(root_b.path().join("a.txt")).unwrap(),
            b"one-changed".to_vec()
        );

        // delete on A, both sides re-sync, B loses it too
        std::fs::remove_file(root_a.path().join("b.txt")).unwrap();
        sync_once(root_a.path(), &store, prefix, &enc_keys).await;
        sync_once(root_b.path(), &store, prefix, &enc_keys).await;

        assert!(!root_b.path().join("b.txt").exists());
    }
}
