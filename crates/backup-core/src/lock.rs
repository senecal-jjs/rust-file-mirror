//! Repository locks, kept in the bucket so they span every device using it.
//!
//! Backups take a shared lock and `prune` an exclusive one. Prune deletes data that
//! no snapshot references, which is only safe if no backup is running anywhere: a
//! running backup may have deduplicated against a chunk prune is about to delete,
//! and would then publish a snapshot pointing at nothing.
//!
//! A lock is a small sealed object under `<base>locks/`, re-written every
//! `REFRESH_EVERY` while held. One not refreshed for `STALE_AFTER` (a crashed
//! process, a laptop asleep) is ignored, and `prune` deletes it. Ages are measured
//! with the bucket's own `last_modified` times against the acquirer's freshly
//! written lock, so clock differences between devices don't matter.
//!
//! The refresher checks the lock still exists before rewriting it. If it's gone (a
//! prune judged it stale and removed it), the lock is marked lost, and
//! `ensure_held` fails: a backup checks that before publishing its snapshot.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use mirror_core::store::{ObjectMeta, ObjectStore};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::crypto::{Id, KeyKind, Keys};
use crate::error::{Error, Result};

pub const DIR: &str = "locks/";
pub const REFRESH_EVERY: Duration = Duration::from_secs(5 * 60);
pub const STALE_AFTER: Duration = Duration::from_secs(30 * 60);

fn aad(id: &str) -> String {
    format!("rfm-backup:v1:lock:{id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub exclusive: bool,
    pub hostname: String,
    pub pid: u32,
    pub created: DateTime<Utc>,
}

impl LockInfo {
    fn describe(&self) -> String {
        let kind = if self.exclusive {
            "a prune"
        } else {
            "a backup"
        };
        format!(
            "{kind} on {} (pid {}) since {}",
            self.hostname,
            self.pid,
            self.created.format("%Y-%m-%d %H:%M UTC")
        )
    }
}

pub struct Lock<S: ObjectStore + 'static> {
    store: Arc<S>,
    base: String,
    key: String,
    /// The bucket's clock when this lock was written.
    acquired_at: SystemTime,
    lost: Arc<AtomicBool>,
    refresher: Option<JoinHandle<()>>,
}

/// Whether `meta` was written within `STALE_AFTER` of `now`. An unknown time counts
/// as fresh: a lock is only ignored with evidence it's abandoned.
fn is_fresh(meta: &ObjectMeta, now: SystemTime) -> bool {
    meta.last_modified.is_none_or(|modified| {
        now.duration_since(modified)
            .is_ok_and(|age| age < STALE_AFTER)
            || modified > now
    })
}

impl<S: ObjectStore + 'static> Lock<S> {
    /// Takes a lock, failing with `Error::Locked` if a conflicting one is held: an
    /// exclusive lock conflicts with any other, a shared one only with exclusive.
    pub async fn acquire(store: Arc<S>, base: &str, keys: &Keys, exclusive: bool) -> Result<Self> {
        let id = Id::random().to_string();
        let key = format!("{base}{DIR}{id}");
        let info = LockInfo {
            exclusive,
            hostname: gethostname::gethostname().to_string_lossy().into_owned(),
            pid: std::process::id(),
            created: Utc::now(),
        };
        let plaintext = serde_json::to_vec(&info).expect("lock info serializes");
        let sealed = keys.seal(KeyKind::Meta, &plaintext, &aad(&id))?;
        store.put_bytes(&key, &sealed).await?;

        let locks = store.list(&format!("{base}{DIR}"), None).await?;
        let acquired_at = locks
            .iter()
            .find(|m| m.key == key)
            .and_then(|m| m.last_modified)
            .unwrap_or_else(SystemTime::now);

        for other in locks
            .iter()
            .filter(|m| m.key != key && is_fresh(m, acquired_at))
        {
            // A lock that can't be read is treated as exclusive: when in doubt, wait.
            let holder = read_info(store.as_ref(), keys, &other.key).await;
            let other_exclusive = holder.as_ref().is_none_or(|h| h.exclusive);
            if exclusive || other_exclusive {
                let _ = store.delete(&key).await;
                let who = holder.map_or_else(|| "an unreadable lock".to_string(), |h| h.describe());
                return Err(Error::Locked(format!(
                    "held by {who}; try again later (locks expire after {} minutes without a refresh)",
                    STALE_AFTER.as_secs() / 60
                )));
            }
        }

        let lost = Arc::new(AtomicBool::new(false));
        let refresher = tokio::spawn(refresh(
            Arc::clone(&store),
            key.clone(),
            sealed,
            Arc::clone(&lost),
        ));
        Ok(Self {
            store,
            base: base.to_string(),
            key,
            acquired_at,
            lost,
            refresher: Some(refresher),
        })
    }

    /// Errors if the lock was removed while held (see the module docs).
    pub fn ensure_held(&self) -> Result<()> {
        if self.lost.load(Ordering::Relaxed) {
            return Err(Error::Locked(
                "this run's lock was removed while it ran (most likely a prune treated it as abandoned); \
                 refusing to continue"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Deletes locks nobody has refreshed in `STALE_AFTER`. Only call while holding
    /// an exclusive lock.
    pub async fn remove_stale(&self) -> Result<usize> {
        let mut removed = 0;
        for meta in self
            .store
            .list(&format!("{}{DIR}", self.base), None)
            .await?
        {
            if meta.key != self.key && !is_fresh(&meta, self.acquired_at) {
                self.store.delete(&meta.key).await?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub async fn release(mut self) -> Result<()> {
        if let Some(refresher) = self.refresher.take() {
            refresher.abort();
        }
        self.store.delete(&self.key).await?;
        Ok(())
    }
}

impl<S: ObjectStore + 'static> Drop for Lock<S> {
    /// Without `release` the object stays until it goes stale; at least stop
    /// refreshing it.
    fn drop(&mut self) {
        if let Some(refresher) = self.refresher.take() {
            refresher.abort();
        }
    }
}

async fn read_info(store: &impl ObjectStore, keys: &Keys, key: &str) -> Option<LockInfo> {
    let id = key.rsplit('/').next()?;
    let sealed = store.get(key).await.ok()?;
    let plaintext = keys.open(KeyKind::Meta, &sealed, &aad(id), "lock").ok()?;
    serde_json::from_slice(&plaintext).ok()
}

async fn refresh<S: ObjectStore>(
    store: Arc<S>,
    key: String,
    sealed: Vec<u8>,
    lost: Arc<AtomicBool>,
) {
    loop {
        tokio::time::sleep(REFRESH_EVERY).await;
        match store.head(&key).await {
            Ok(None) => {
                lost.store(true, Ordering::Relaxed);
                tracing::warn!(%key, "repository lock disappeared while held");
                return;
            }
            Ok(Some(_)) => {
                if let Err(e) = store.put_bytes(&key, &sealed).await {
                    tracing::warn!(error = %e, "refreshing repository lock failed");
                }
            }
            // A transient error: try again next time rather than give up the lock.
            Err(e) => tracing::warn!(error = %e, "checking repository lock failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_keys;
    use mirror_core::store::memory::MemoryStore;

    const BASE: &str = "rfm/backup/";

    async fn locks(store: &MemoryStore) -> Vec<String> {
        store
            .list(&format!("{BASE}{DIR}"), None)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key)
            .collect()
    }

    fn age(store: &MemoryStore, key: &str, by: Duration) {
        store.set_modified_at(key, SystemTime::now() - by);
    }

    #[tokio::test]
    async fn shared_locks_coexist_and_release_cleans_up() {
        let (store, keys) = (Arc::new(MemoryStore::new()), test_keys());
        let a = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .unwrap();
        let b = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .unwrap();
        assert_eq!(locks(&store).await.len(), 2);
        a.release().await.unwrap();
        b.release().await.unwrap();
        assert!(locks(&store).await.is_empty());
    }

    #[tokio::test]
    async fn exclusive_and_shared_exclude_each_other_without_leaving_debris() {
        let (store, keys) = (Arc::new(MemoryStore::new()), test_keys());
        let shared = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .unwrap();
        let err = Lock::acquire(Arc::clone(&store), BASE, &keys, true)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, Error::Locked(msg) if msg.contains("a backup on")),
            "{err}"
        );
        assert_eq!(
            locks(&store).await.len(),
            1,
            "the failed attempt removed its own lock"
        );
        shared.release().await.unwrap();

        let exclusive = Lock::acquire(Arc::clone(&store), BASE, &keys, true)
            .await
            .unwrap();
        let err = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, Error::Locked(msg) if msg.contains("a prune on")),
            "{err}"
        );
        assert!(
            Lock::acquire(Arc::clone(&store), BASE, &keys, true)
                .await
                .is_err()
        );
        exclusive.release().await.unwrap();
    }

    #[tokio::test]
    async fn unreadable_locks_count_as_exclusive() {
        let (store, keys) = (Arc::new(MemoryStore::new()), test_keys());
        store
            .put_bytes(&format!("{BASE}{DIR}{}", Id::random()), b"garbage")
            .await
            .unwrap();
        assert!(
            Lock::acquire(Arc::clone(&store), BASE, &keys, false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn stale_locks_are_ignored_and_removable() {
        let (store, keys) = (Arc::new(MemoryStore::new()), test_keys());
        let abandoned = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .unwrap();
        let abandoned_key = abandoned.key.clone();
        drop(abandoned); // crashed: never released
        age(
            &store,
            &abandoned_key,
            STALE_AFTER + Duration::from_secs(60),
        );

        let prune = Lock::acquire(Arc::clone(&store), BASE, &keys, true)
            .await
            .unwrap();
        assert_eq!(prune.remove_stale().await.unwrap(), 1);
        assert_eq!(locks(&store).await, vec![prune.key.clone()]);

        // A recent lock is never removed as stale.
        age(&store, &prune.key, Duration::from_secs(60));
        assert_eq!(prune.remove_stale().await.unwrap(), 0);
        prune.release().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn refresher_keeps_a_lock_fresh() {
        let (store, keys) = (Arc::new(MemoryStore::new()), test_keys());
        let lock = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .unwrap();
        age(&store, &lock.key, STALE_AFTER + Duration::from_secs(60));

        tokio::time::sleep(REFRESH_EVERY + Duration::from_secs(1)).await;
        let meta = store.head(&lock.key).await.unwrap().unwrap();
        assert!(
            is_fresh(&meta, SystemTime::now()),
            "rewritten by the refresher"
        );
        assert!(lock.ensure_held().is_ok());
        lock.release().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_removed_while_held_is_reported_lost() {
        let (store, keys) = (Arc::new(MemoryStore::new()), test_keys());
        let lock = Lock::acquire(Arc::clone(&store), BASE, &keys, false)
            .await
            .unwrap();
        store.delete(&lock.key).await.unwrap(); // a prune decided it was stale

        tokio::time::sleep(REFRESH_EVERY + Duration::from_secs(1)).await;
        assert!(matches!(lock.ensure_held(), Err(Error::Locked(_))));
        assert!(
            locks(&store).await.is_empty(),
            "not resurrected by the refresher"
        );
    }
}
