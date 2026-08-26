use crate::{error::Result, manifest::ManifestEntry, store::ObjectStore};

pub(crate) async fn delete_remote<S: ObjectStore>(
    store: &S,
    prefix: &str,
    manifest_entry: Option<&ManifestEntry>,
) -> Result<()> {
    if let Some(manifest_entry) = manifest_entry {
        let store_key = format!("{prefix}{}", manifest_entry.object_key);

        store.delete(&store_key).await?;
    }

    Ok(())
}
