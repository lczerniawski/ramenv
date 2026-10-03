use anyhow::{Context, Result};
use indexmap::IndexMap;
use log::info;

use crate::{
    crypto, services,
    utils::{self, StringExt},
};

pub async fn rotate_command(
    env: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_registry: &mut impl services::VaultService,
    workspace_service: &impl services::WorkspaceService,
) -> Result<()> {
    let encryption_key = encryption_key_service.env_key(env)?.to_owned();
    let vault = vault_registry.env_vault(env)?;

    let mut new_vault = IndexMap::new();
    let new_encryption_key = crypto::generate_master_key_hex();

    for (key, value) in vault.iter() {
        if value.is_secret() {
            let plaintext = utils::get_plaintext(value, &encryption_key)?;
            let rotated_secret = crypto::encrypt_value(&plaintext, &new_encryption_key)?;
            new_vault.insert(key.to_string(), rotated_secret);
        } else {
            new_vault.insert(key.to_string(), value.clone());
        }
    }

    vault_registry.set_env_vault(env, new_vault);
    encryption_key_service.set_env_key(env, new_encryption_key);

    if let Err(error) = vault_registry.commit() {
        vault_registry.set_env_vault(env, vault);
        encryption_key_service.set_env_key(env, encryption_key);
        return Err(error);
    }
    if let Err(error) = encryption_key_service
        .commit(workspace_service.get_workspace_name())
        .await
    {
        vault_registry.set_env_vault(env, vault);
        encryption_key_service.set_env_key(env, encryption_key);
        vault_registry
            .commit()
            .context("failed to roll back vault after key commit failure")?;
        return Err(error);
    }

    info!(
        "🔄 successfully rotated encryption keys for environment: {}",
        env
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::commands::test_support::{KEY, Keys, Vault, Workspace};

    #[tokio::test]
    async fn rotates_only_encrypted_values_and_commits() {
        let encrypted = crypto::encrypt_value("secret value", KEY).unwrap();
        let mut keys = Keys::with_env("dev");
        let mut vault = Vault::with_env(
            "dev",
            IndexMap::from([
                ("SECRET".into(), encrypted.clone()),
                ("PLAIN".into(), "plain value".into()),
            ]),
        );
        let workspace = Workspace::default();
        rotate_command("dev", &mut keys, &mut vault, &workspace)
            .await
            .unwrap();
        let new_key = &keys.values["dev"];
        assert_ne!(new_key, KEY);
        assert_ne!(vault.environments["dev"]["SECRET"], encrypted);
        assert_eq!(
            crypto::decrypt_value(&vault.environments["dev"]["SECRET"], new_key).unwrap(),
            "secret value"
        );
        assert_eq!(vault.environments["dev"]["PLAIN"], "plain value");
        assert_eq!(vault.commits.get(), 1);
        assert_eq!(keys.commits.get(), 1);
    }

    #[tokio::test]
    async fn rejects_missing_state_or_corrupt_ciphertext() {
        let mut keys = Keys::default();
        let mut vault = Vault::with_env("dev", IndexMap::new());
        let workspace = Workspace::default();
        assert!(
            rotate_command("dev", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );

        let mut keys = Keys::with_env("dev");
        let mut vault = Vault::default();
        let workspace = Workspace::default();
        assert!(
            rotate_command("dev", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );

        let mut keys = Keys::with_env("dev");
        let mut vault = Vault::with_env(
            "dev",
            IndexMap::from([("SECRET".into(), "secret:invalid".into())]),
        );
        let workspace = Workspace::default();
        assert!(
            rotate_command("dev", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(vault.commits.get(), 0);
    }

    #[tokio::test]
    async fn propagates_vault_commit_failure_without_committing_keys() {
        let mut keys = Keys::with_env("dev");
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::with_env("dev", IndexMap::new())
        };
        let workspace = Workspace::default();
        assert!(
            rotate_command("dev", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(keys.commits.get(), 0);
        assert_eq!(keys.values["dev"], KEY);
        assert!(vault.environments["dev"].is_empty());
    }

    #[tokio::test]
    async fn rolls_back_vault_when_key_commit_fails() {
        let encrypted = crypto::encrypt_value("secret value", KEY).unwrap();
        let mut keys = Keys {
            fail_commit: true,
            ..Keys::with_env("dev")
        };
        let mut vault = Vault::with_env(
            "dev",
            IndexMap::from([("SECRET".into(), encrypted.clone())]),
        );
        let workspace = Workspace::default();
        assert!(
            rotate_command("dev", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        assert_eq!(keys.values["dev"], KEY);
        assert_eq!(vault.environments["dev"]["SECRET"], encrypted);
        assert_eq!(vault.commits.get(), 2);
    }
}
