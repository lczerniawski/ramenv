use std::{collections::HashMap, path::Path};

use anyhow::Context;
use indexmap::IndexMap;
use inquire::MultiSelect;
use log::info;

use crate::{
    crypto, services,
    validation::{RuleType, ValidationRule},
};

pub fn on_board_command(
    current_working_path: &Path,
    environment: &str,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> anyhow::Result<()> {
    let env_file_path = current_working_path.join(".env");

    if !env_file_path.exists() {
        info!(".env file does not exist, nothing to onboard");
        return Ok(());
    }
    let encryption_key = encryption_key_service
        .env_key(environment)
        .context(format!(
            "No encryption key found for environment: {}",
            environment
        ))?;

    let mut env_file_data = HashMap::new();
    for item in dotenvy::from_path_iter(env_file_path).context("parsing .env file failed")? {
        let (key, val) = item.context("failed to parse key value pair in .env file")?;
        env_file_data.insert(key, val);
    }

    let keys_to_encrypt: Vec<String> = env_file_data.keys().cloned().collect();
    let keys_selected_for_encryption = MultiSelect::new(
        "Select secrets that you wish to become encrypted in the vault:",
        keys_to_encrypt,
    )
    .prompt()
    .context("failed to prompt user for key selection")?;

    merge_env_data(
        environment,
        env_file_data,
        &keys_selected_for_encryption,
        encryption_key,
        vault_service,
    )
}

fn merge_env_data(
    environment: &str,
    env_file_data: HashMap<String, String>,
    keys_selected_for_encryption: &[String],
    encryption_key: &str,
    vault_service: &mut impl services::VaultService,
) -> anyhow::Result<()> {
    let mut validation_rules = vault_service.validation_rules();

    let vault_data: IndexMap<String, String> = env_file_data
        .into_iter()
        .map(|(key, value)| {
            validation_rules.insert(
                key.to_string(),
                ValidationRule::new(
                    RuleType::String {
                        min_len: None,
                        max_len: None,
                    },
                    true,
                ),
            );
            if keys_selected_for_encryption.contains(&key) {
                let encrypted_data = crypto::encrypt_value(&value, encryption_key)?;
                Ok((key, encrypted_data))
            } else {
                Ok((key, value))
            }
        })
        .collect::<anyhow::Result<IndexMap<_, _>>>()?;

    vault_service.merge_env_vault(environment, vault_data)?;
    vault_service.set_validation_rules(validation_rules);
    vault_service
        .commit()
        .context("failed to commit configuration into vault file")?;

    info!("🍜 vault onboarded successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::test_support::{KEY, Vault},
        services::VaultService,
        validation::RuleType,
    };

    #[test]
    fn merges_plain_and_encrypted_values_and_creates_rules() {
        let mut vault =
            Vault::with_env("dev", IndexMap::from([("EXISTING".into(), "kept".into())]));
        merge_env_data(
            "dev",
            HashMap::from([
                ("SECRET".into(), "sensitive".into()),
                ("PLAIN".into(), "visible".into()),
            ]),
            &["SECRET".into()],
            KEY,
            &mut vault,
        )
        .unwrap();
        let values = vault.env_vault("dev").unwrap();
        assert_eq!(values["EXISTING"], "kept");
        assert_eq!(values["PLAIN"], "visible");
        assert_eq!(
            crypto::decrypt_value(&values["SECRET"], KEY).unwrap(),
            "sensitive"
        );
        assert_eq!(vault.rules.len(), 2);
        assert!(vault.rules.values().all(|rule| rule.required));
        assert!(
            vault
                .rules
                .values()
                .all(|rule| matches!(rule.rule_type, RuleType::String { .. }))
        );
        assert_eq!(vault.commits.get(), 1);
    }

    #[test]
    fn reports_missing_environment_bad_key_and_commit_failure() {
        assert!(merge_env_data("dev", HashMap::new(), &[], KEY, &mut Vault::default()).is_err());
        assert!(
            merge_env_data(
                "dev",
                HashMap::from([("SECRET".into(), "value".into())]),
                &["SECRET".into()],
                "bad-key",
                &mut Vault::with_env("dev", IndexMap::new())
            )
            .is_err()
        );
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::with_env("dev", IndexMap::new())
        };
        assert!(merge_env_data("dev", HashMap::new(), &[], KEY, &mut vault).is_err());
    }
}
