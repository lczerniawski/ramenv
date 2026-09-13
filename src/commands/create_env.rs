use crate::services;
use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;
use log::info;

pub fn create_env_command(
    environment: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    if encryption_key_service.env_key(environment).is_ok() {
        anyhow::bail!("key for provided environment already exists")
    }

    if vault_service.env_vault(environment).is_ok() {
        anyhow::bail!("vault for provided environment already exists");
    }

    encryption_key_service.store_new_env_key(environment);
    if let Err(error) = encryption_key_service.commit() {
        encryption_key_service.remove_env_key(environment);
        return Err(error).context("failed to synchronize keys back to file");
    }

    vault_service.set_env_vault(environment, IndexMap::new());
    if let Err(error) = vault_service.commit() {
        vault_service.remove_env_vault(environment);
        encryption_key_service.remove_env_key(environment);
        encryption_key_service
            .commit()
            .context("failed to roll back key after vault commit failure")?;
        return Err(error).context("failed to synchronize secrets back to file");
    }

    info!("✅ successfully created new environment: {}", environment);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{Keys, Vault};

    #[test]
    fn creates_key_and_empty_vault_and_commits_each_service() {
        let mut keys = Keys::default();
        let mut vault = Vault::default();
        create_env_command("staging", &mut keys, &mut vault).unwrap();
        assert_eq!(keys.values["staging"].len(), 64);
        assert!(vault.environments["staging"].is_empty());
        assert_eq!(keys.commits.get(), 1);
        assert_eq!(vault.commits.get(), 1);
    }

    #[test]
    fn rejects_an_existing_key_or_vault_without_mutating() {
        let mut keys = Keys::with_env("staging");
        let mut vault = Vault::default();
        assert!(create_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(keys.commits.get(), 0);

        let mut keys = Keys::default();
        let mut vault = Vault::with_env("staging", IndexMap::new());
        assert!(create_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(keys.commits.get(), 0);
    }

    #[test]
    fn propagates_key_and_vault_commit_failures() {
        let mut keys = Keys {
            fail_commit: true,
            ..Keys::default()
        };
        let mut vault = Vault::default();
        assert!(create_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(vault.commits.get(), 0);
        assert!(!keys.values.contains_key("staging"));

        let mut keys = Keys::default();
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::default()
        };
        assert!(create_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(keys.commits.get(), 2);
        assert!(!keys.values.contains_key("staging"));
        assert!(!vault.environments.contains_key("staging"));
    }
}
