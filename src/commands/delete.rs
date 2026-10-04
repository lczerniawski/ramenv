use anyhow::{Ok, Result};
use log::info;

use crate::services;

pub fn delete_command(
    environment: &str,
    key: &str,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    let mut vault = vault_service.env_vault(environment)?;
    let mut validation_rules = vault_service.validation_rules();

    if vault.shift_remove(key).is_some() {
        let used_elsewhere = vault_service
            .all_env_vaults()
            .iter()
            .any(|(env, values)| env != environment && values.contains_key(key));
        if !used_elsewhere {
            validation_rules.shift_remove(key);
        }
        vault_service.set_env_vault(environment, vault);
        vault_service.set_validation_rules(validation_rules);
        vault_service.commit()?;
        info!("✅ key {} deleted successfully", key);
        return Ok(());
    }
    anyhow::bail!("❌ key {} not found", key);
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::{
        commands::test_support::Vault,
        validation::{RuleType, ValidationRule},
    };

    #[test]
    fn deletes_value_and_matching_rule_then_commits() {
        let mut vault =
            Vault::with_env("dev", IndexMap::from([("API_KEY".into(), "value".into())]));
        vault.rules.insert(
            "API_KEY".into(),
            ValidationRule::new(RuleType::Boolean, true),
        );
        delete_command("dev", "API_KEY", &mut vault).unwrap();
        assert!(vault.environments["dev"].is_empty());
        assert!(vault.rules.is_empty());
        assert_eq!(vault.commits.get(), 1);
    }

    #[test]
    fn preserves_rules_used_by_other_environments() {
        let mut vault = Vault::with_env("dev", IndexMap::from([("API_KEY".into(), "true".into())]));
        vault.environments.insert(
            "production".into(),
            IndexMap::from([("API_KEY".into(), "invalid".into())]),
        );
        vault.rules.insert(
            "API_KEY".into(),
            ValidationRule::new(RuleType::Boolean, true),
        );
        delete_command("dev", "API_KEY", &mut vault).unwrap();
        assert!(vault.environments["dev"].is_empty());
        assert_eq!(vault.environments["production"]["API_KEY"], "invalid");
        assert!(
            vault.rules["API_KEY"]
                .rule_type
                .validate("API_KEY", "invalid", "production")
                .is_err()
        );
        assert_eq!(vault.commits.get(), 1);

        delete_command("production", "API_KEY", &mut vault).unwrap();
        assert!(vault.rules.is_empty());
    }

    #[test]
    fn missing_environment_or_key_is_an_error_without_commit() {
        let mut vault = Vault::default();
        assert!(delete_command("dev", "KEY", &mut vault).is_err());
        let mut vault = Vault::with_env("dev", IndexMap::new());
        assert!(delete_command("dev", "KEY", &mut vault).is_err());
        assert_eq!(vault.commits.get(), 0);
    }

    #[test]
    fn commit_failure_is_propagated() {
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::with_env("dev", IndexMap::from([("KEY".into(), "value".into())]))
        };
        assert!(delete_command("dev", "KEY", &mut vault).is_err());
    }
}
