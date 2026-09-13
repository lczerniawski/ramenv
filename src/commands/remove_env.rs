use anyhow::{Context, Result};
use log::info;

use crate::services;

pub fn remove_env_command(
    environment: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    let old_key = encryption_key_service
        .env_key(environment)
        .map(str::to_owned)
        .map_err(|_| anyhow::anyhow!("key for provided environment does not exist"))?;
    let old_vault = vault_service
        .env_vault(environment)
        .map_err(|_| anyhow::anyhow!("vault for provided environment does not exist"))?;

    encryption_key_service.remove_env_key(environment);
    vault_service.remove_env_vault(environment);
    if let Err(error) = encryption_key_service.commit() {
        encryption_key_service.set_env_key(environment, old_key);
        vault_service.set_env_vault(environment, old_vault);
        return Err(error);
    }
    if let Err(error) = vault_service.commit() {
        encryption_key_service.set_env_key(environment, old_key);
        vault_service.set_env_vault(environment, old_vault);
        encryption_key_service
            .commit()
            .context("failed to roll back key after vault commit failure")?;
        return Err(error);
    }

    info!("✅ successfully removed environment: {}", environment);
    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::commands::test_support::{Keys, Vault};

    #[test]
    fn removes_existing_environment_from_both_services() {
        let mut keys = Keys::with_env("staging");
        let mut vault = Vault::with_env("staging", IndexMap::new());
        remove_env_command("staging", &mut keys, &mut vault).unwrap();
        assert!(!keys.values.contains_key("staging"));
        assert!(!vault.environments.contains_key("staging"));
        assert_eq!(keys.commits.get(), 1);
        assert_eq!(vault.commits.get(), 1);
    }

    #[test]
    fn rejects_missing_key_or_vault_before_committing() {
        let mut keys = Keys::default();
        let mut vault = Vault::with_env("staging", IndexMap::new());
        assert!(remove_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(vault.commits.get(), 0);

        let mut keys = Keys::with_env("staging");
        let mut vault = Vault::default();
        assert!(remove_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(keys.commits.get(), 0);
    }

    #[test]
    fn propagates_commit_failures() {
        let mut keys = Keys {
            fail_commit: true,
            ..Keys::with_env("staging")
        };
        let mut vault = Vault::with_env("staging", IndexMap::new());
        assert!(remove_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(vault.commits.get(), 0);
        assert!(keys.values.contains_key("staging"));
        assert!(vault.environments.contains_key("staging"));

        let mut keys = Keys::with_env("staging");
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::with_env("staging", IndexMap::from([("KEY".into(), "value".into())]))
        };
        assert!(remove_env_command("staging", &mut keys, &mut vault).is_err());
        assert_eq!(keys.commits.get(), 2);
        assert!(keys.values.contains_key("staging"));
        assert_eq!(vault.environments["staging"]["KEY"], "value");
    }
}
