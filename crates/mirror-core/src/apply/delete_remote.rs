use crate::{engine::Action, error::Result, manifest::Manifest, state::State, store::ObjectStore};

pub(crate) async fn delete_remote<S: ObjectStore>(
    store: &S,
    action: &Action,
    prefix: &str,
    state: &mut State,
    manifest: &mut Manifest,
) -> Result<()> {
    if let Some(manifest_entry) = manifest.get(&action.path) {
        let store_key = format!("{prefix}{}", manifest_entry.object_key);

        store.delete(&store_key).await?;
        manifest.remove_entry(&action.path);
    }

    state.remove(&action.path)?;

    println!("Applied {:<14} {}", action.kind, action.path);

    Ok(())
}
