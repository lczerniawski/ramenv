use anyhow::{Ok, Result};
use indexmap::IndexMap;
use log::{error, info};

use crate::{
    services,
    utils::{self},
};

pub fn validate_command(
    environment: Option<String>,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let validation_rules = vault_service.validation_rules();

    if let Some(env) = environment {
        let encryption_key = encryption_key_service.env_key(&env)?;
        let vault = vault_service.env_vault(&env)?;

        validate_vault(encryption_key, vault, &validation_rules, env.clone())?;
        info!("✅ validation passed for environment: {}", env);
    } else {
        for (env, vault) in vault_service.all_env_vaults() {
            let encryption_key = encryption_key_service.env_key(&env)?;

            validate_vault(encryption_key, vault, &validation_rules, env)?;
        }
        info!("✅ validation passed for all environments");
    }
    Ok(())
}

fn validate_vault(
    encryption_key: &str,
    vault: indexmap::IndexMap<String, String>,
    validation_rules: &IndexMap<String, crate::validation::ValidationRule>,
    env: String,
) -> Result<()> {
    let mut was_successful = true;

    for (key, rule) in validation_rules.iter() {
        if let Some(value) = vault.get(key) {
            let value_to_validate = utils::get_plaintext(value, encryption_key)?;
            let result = rule.rule_type.validate(key, &value_to_validate, &env);
            if let Err(e) = result {
                error!("{}", e);
                was_successful = false;
            }
        } else if rule.required {
            error!(
                "[{}] Key '{}' is required but not present in the vault",
                env, key
            );
            was_successful = false;
        }
    }

    if !was_successful {
        anyhow::bail!("Validation failed for environment: {}", env);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::{
        commands::test_support::{KEY, Keys, Vault},
        crypto,
        validation::{RuleType, ValidationRule},
    };

    #[test]
    fn validates_selected_and_all_environments() {
        let keys = Keys {
            values: IndexMap::from([("one".into(), KEY.into()), ("two".into(), KEY.into())]),
            ..Keys::default()
        };
        let mut vault = Vault {
            environments: IndexMap::from([
                ("one".into(), IndexMap::from([("PORT".into(), "80".into())])),
                (
                    "two".into(),
                    IndexMap::from([("PORT".into(), "443".into())]),
                ),
            ]),
            ..Vault::default()
        };
        vault
            .rules
            .insert("PORT".into(), ValidationRule::new(RuleType::Port, true));
        assert!(validate_command(Some("one".into()), &keys, &vault).is_ok());
        assert!(validate_command(None, &keys, &vault).is_ok());
    }

    #[test]
    fn optional_missing_values_pass_but_required_invalid_and_corrupt_values_fail() {
        let optional = IndexMap::from([(
            "OPTIONAL".into(),
            ValidationRule::new(RuleType::Boolean, false),
        )]);
        assert!(validate_vault(KEY, IndexMap::new(), &optional, "dev".into()).is_ok());

        let required = IndexMap::from([("PORT".into(), ValidationRule::new(RuleType::Port, true))]);
        assert!(validate_vault(KEY, IndexMap::new(), &required, "dev".into()).is_err());
        assert!(
            validate_vault(
                KEY,
                IndexMap::from([("PORT".into(), "invalid".into())]),
                &required,
                "dev".into()
            )
            .is_err()
        );
        assert!(
            validate_vault(
                KEY,
                IndexMap::from([("PORT".into(), "secret:bad".into())]),
                &required,
                "dev".into()
            )
            .is_err()
        );
    }

    #[test]
    fn decrypts_valid_encrypted_values() {
        let rules = IndexMap::from([("PORT".into(), ValidationRule::new(RuleType::Port, true))]);
        let value = crypto::encrypt_value("8080", KEY).unwrap();
        assert!(
            validate_vault(
                KEY,
                IndexMap::from([("PORT".into(), value)]),
                &rules,
                "dev".into()
            )
            .is_ok()
        );
    }
}
