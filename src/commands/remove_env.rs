use anyhow::Result;
use log::info;

use crate::services;

pub async fn remove_env_command(
    environment: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vaults: &mut [impl services::VaultService],
    workspace_service: &impl services::WorkspaceService,
) -> Result<()> {
    encryption_key_service
        .env_key(environment)
        .map_err(|_| anyhow::anyhow!("key for provided environment does not exist"))?;
    let originals = super::workspace_change::snapshots(environment, vaults);
    if originals.is_empty() {
        anyhow::bail!("vault for provided environment does not exist");
    }
    for (index, _) in &originals {
        vaults[*index].remove_env_vault(environment);
    }
    super::workspace_change::commit_change(
        environment,
        None,
        encryption_key_service,
        vaults,
        &originals,
        workspace_service,
    )
    .await?;

    info!(
        "✅ successfully removed environment: {} from {} workspace vault(s)",
        environment,
        originals.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::commands::test_support::{KEY, Keys, Vault, Workspace};

    #[tokio::test]
    async fn removes_existing_environment_from_both_services() {
        let mut keys = Keys::with_env("staging");
        let mut vaults = [Vault::with_env("staging", IndexMap::new())];
        remove_env_command("staging", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap();
        assert!(!keys.values.contains_key("staging"));
        assert!(!vaults[0].environments.contains_key("staging"));
        assert_eq!(keys.commits.get(), 1);
        assert_eq!(vaults[0].commits.get(), 1);
    }

    #[tokio::test]
    async fn removes_environment_from_all_vaults_and_preserves_other_state() {
        let mut keys = Keys::with_env("staging");
        keys.values.insert("prod".into(), KEY.into());
        let mut vaults = [
            Vault::with_env("staging", IndexMap::new()),
            Vault::with_env("staging", IndexMap::new()),
            Vault::with_env("prod", IndexMap::new()),
        ];
        vaults[0].environments.insert(
            "prod".into(),
            IndexMap::from([("KEEP".into(), "unchanged".into())]),
        );
        remove_env_command("staging", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap();
        assert!(!keys.values.contains_key("staging"));
        assert_eq!(keys.values["prod"], KEY);
        assert!(
            vaults
                .iter()
                .all(|vault| !vault.environments.contains_key("staging"))
        );
        assert_eq!(vaults[0].environments["prod"]["KEEP"], "unchanged");
        assert_eq!(vaults[0].commits.get(), 1);
        assert_eq!(vaults[1].commits.get(), 1);
        assert_eq!(vaults[2].commits.get(), 0);
        assert_eq!(keys.commits.get(), 1);
    }

    #[tokio::test]
    async fn rejects_missing_key_or_vault_before_committing() {
        let mut keys = Keys::default();
        let mut vaults = [Vault::with_env("staging", IndexMap::new())];
        assert!(
            remove_env_command("staging", &mut keys, &mut vaults, &Workspace::default())
                .await
                .is_err()
        );
        assert_eq!(vaults[0].commits.get(), 0);
        let mut keys = Keys::with_env("staging");
        let mut vaults = [Vault::default()];
        assert!(
            remove_env_command("staging", &mut keys, &mut vaults, &Workspace::default())
                .await
                .is_err()
        );
        assert_eq!(keys.commits.get(), 0);
    }

    #[tokio::test]
    async fn rolls_back_vaults_before_deleting_key_when_a_commit_fails() {
        let mut keys = Keys::with_env("staging");
        let mut vaults = [
            Vault::with_env("staging", IndexMap::new()),
            Vault {
                fail_commit_at: Some(1),
                ..Vault::with_env("staging", IndexMap::new())
            },
        ];
        let originals: Vec<_> = vaults
            .iter()
            .map(|vault| vault.environments.clone())
            .collect();
        assert!(
            remove_env_command("staging", &mut keys, &mut vaults, &Workspace::default())
                .await
                .is_err()
        );
        assert_eq!(keys.values["staging"], KEY);
        assert_eq!(keys.commits.get(), 0);
        for (vault, original) in vaults.iter().zip(originals) {
            assert_eq!(vault.environments, original);
            assert_eq!(vault.commits.get(), 2);
        }
    }

    #[tokio::test]
    async fn restores_vault_order_and_key_when_key_commit_fails() {
        let mut keys = Keys {
            fail_commit_at: Some(1),
            ..Keys::with_env("staging")
        };
        let mut vaults = [
            Vault::with_env("staging", IndexMap::new()),
            Vault::with_env("staging", IndexMap::new()),
        ];
        vaults[0]
            .environments
            .insert("prod".into(), IndexMap::new());
        let originals: Vec<_> = vaults
            .iter()
            .map(|vault| vault.environments.clone())
            .collect();
        let error = remove_env_command("staging", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "key commit failed");
        assert_eq!(keys.values["staging"], KEY);
        assert_eq!(keys.commits.get(), 2);
        for (vault, original) in vaults.iter().zip(originals) {
            assert_eq!(vault.environments, original);
            assert_eq!(
                vault.environments.keys().collect::<Vec<_>>(),
                original.keys().collect::<Vec<_>>()
            );
            assert_eq!(vault.commits.get(), 2);
        }
    }
}
