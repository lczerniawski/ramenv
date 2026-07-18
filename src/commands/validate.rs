use anyhow::{Ok, Result};
use indexmap::IndexMap;
use log::error;

use crate::{commands::utils::StringExt, crypto, services};

pub fn validate_command(
    environment: Option<String>,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let validation_rules = vault_service.validation_rules();

    if let Some(env) = environment {
        let encryption_key = encryption_key_service.env_key(&env)?;
        let vault = vault_service.env_vault(&env)?;

        validate_vault(encryption_key, vault, &validation_rules, env)?;
    } else {
        for (env, vault) in vault_service.all_env_vaults() {
            let encryption_key = encryption_key_service.env_key(&env)?;

            validate_vault(encryption_key, vault, &validation_rules, env)?;
        }
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
            let value_to_validate = if value.is_secret() {
                crypto::decrypt_value(value, encryption_key)?
            } else {
                value.to_string()
            };
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
