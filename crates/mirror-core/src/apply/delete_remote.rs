use crate::{error::Result, manifest::DeltaEntry, store::ObjectStore};

pub(crate) async fn delete_remote<S: ObjectStore>(
    store: &S,
    prefix: &str,
    manifest_entry: Option<&DeltaEntry>,
) -> Result<()> {
    if let Some(manifest_entry) = manifest_entry {
        let store_key = format!("{prefix}{}", manifest_entry.object_key);

        store.delete(&store_key).await?;
    }

    Ok(())
}
