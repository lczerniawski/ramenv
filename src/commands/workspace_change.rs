use anyhow::Result;
use indexmap::IndexMap;

use crate::services::{EncryptionKeyService, VaultService, WorkspaceService};

type Environments = IndexMap<String, IndexMap<String, String>>;
pub(super) type Snapshot = (usize, Environments);

pub(super) fn snapshots(environment: &str, vaults: &[impl VaultService]) -> Vec<Snapshot> {
    vaults
        .iter()
        .enumerate()
        .filter_map(|(index, vault)| {
            let environments = vault.all_env_vaults();
            environments
                .contains_key(environment)
                .then_some((index, environments))
        })
        .collect()
}

// Restore every staged vault in memory, but only rewrite files whose commit was attempted.
// Continue after rollback errors so a single unwritable vault cannot prevent other restores.
fn rollback_vaults(
    vaults: &mut [impl VaultService],
    originals: &[Snapshot],
    attempted: usize,
) -> Result<()> {
    let mut errors = Vec::new();
    for (position, (index, environments)) in originals.iter().enumerate() {
        let vault = &mut vaults[*index];
        for env in vault.all_env_vaults().keys() {
            vault.remove_env_vault(env);
        }
        for (env, values) in environments {
            vault.set_env_vault(env, values.clone());
        }
        if position < attempted
            && let Err(error) = vault.commit()
        {
            errors.push(format!("vault {index}: {error:#}"));
        }
    }
    if !errors.is_empty() {
        anyhow::bail!("failed to roll back vaults: {}", errors.join("; "));
    }
    Ok(())
}

pub(super) async fn commit_change(
    environment: &str,
    replacement_key: Option<String>,
    keys: &mut impl EncryptionKeyService,
    vaults: &mut [impl VaultService],
    originals: &[Snapshot],
    workspace: &impl WorkspaceService,
) -> Result<()> {
    let old_key = keys.env_key(environment)?.to_owned();
    for (position, (index, _)) in originals.iter().enumerate() {
        if let Err(error) = vaults[*index].commit() {
            let rollback = rollback_vaults(vaults, originals, position + 1);
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback) => Err(error.context(format!("{rollback:#}"))),
            };
        }
    }

    match replacement_key {
        Some(key) => keys.set_env_key(environment, key),
        None => keys.remove_env_key(environment),
    }
    if let Err(error) = keys.commit(workspace.get_workspace_name()).await {
        // Providers may fail after persisting a change, so compensate in the key store too.
        keys.set_env_key(environment, old_key);
        let key_rollback = keys.commit(workspace.get_workspace_name()).await;
        let vault_rollback = rollback_vaults(vaults, originals, originals.len());
        let mut failures = Vec::new();
        if let Err(rollback) = key_rollback {
            failures.push(format!("failed to roll back key: {rollback:#}"));
        }
        if let Err(rollback) = vault_rollback {
            failures.push(format!("{rollback:#}"));
        }
        return if failures.is_empty() {
            Err(error)
        } else {
            Err(error.context(failures.join("; ")))
        };
    }
    Ok(())
}
