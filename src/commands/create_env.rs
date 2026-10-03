use crate::services;
use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;
use log::info;

pub async fn create_env_command(
    environment: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
    workspace_service: &impl services::WorkspaceService,
) -> Result<()> {
    if encryption_key_service.env_key(environment).is_ok() {
        anyhow::bail!("key for provided environment already exists")
    }

    if vault_service.env_vault(environment).is_ok() {
        anyhow::bail!("vault for provided environment already exists");
    }

    encryption_key_service.store_new_env_key(environment);
    if let Err(error) = encryption_key_service
        .commit(workspace_service.get_workspace_name())
        .await
    {
        encryption_key_service.remove_env_key(environment);
        return Err(error).context("failed to synchronize keys back to file");
    }

    vault_service.set_env_vault(environment, IndexMap::new());
    if let Err(error) = vault_service.commit() {
        vault_service.remove_env_vault(environment);
        encryption_key_service.remove_env_key(environment);
        encryption_key_service
            .commit(workspace_service.get_workspace_name())
            .await
            .context("failed to roll back key after vault commit failure")?;
        return Err(error).context("failed to synchronize secrets back to file");
    }

    info!("✅ successfully created new environment: {}", environment);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{Keys, Vault, Workspace};

    #[tokio::test]
    async fn creates_key_and_empty_vault_and_commits_each_service() {
        let mut keys = Keys::default();
        let mut vault = Vault::default();
        let workspace = Workspace::default();
        create_env_command("staging", &mut keys, &mut vault, &workspace)
            .await
            .unwrap();
        assert_eq!(keys.values["staging"].len(), 64);
        assert!(vault.environments["staging"].is_empty());
        assert_eq!(keys.commits.get(), 1);
        assert_eq!(vault.commits.get(), 1);
    }

    #[tokio::test]
    async fn rejects_an_existing_key_or_vault_without_mutating() {
        let mut keys = Keys::with_env("staging");
        let mut vault = Vault::default();
        let workspace = Workspace::default();
        assert!(
            create_env_command("staging", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(keys.commits.get(), 0);

        let mut keys = Keys::default();
        let mut vault = Vault::with_env("staging", IndexMap::new());
        let workspace = Workspace::default();
        assert!(
            create_env_command("staging", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(keys.commits.get(), 0);
    }

    #[tokio::test]
    async fn propagates_key_and_vault_commit_failures() {
        let mut keys = Keys {
            fail_commit: true,
            ..Keys::default()
        };
        let mut vault = Vault::default();
        let workspace = Workspace::default();
        assert!(
            create_env_command("staging", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(vault.commits.get(), 0);
        assert!(!keys.values.contains_key("staging"));

        let mut keys = Keys::default();
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::default()
        };
        let workspace = Workspace::default();
        assert!(
            create_env_command("staging", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(keys.commits.get(), 2);
        assert!(!keys.values.contains_key("staging"));
        assert!(!vault.environments.contains_key("staging"));
    }
}
