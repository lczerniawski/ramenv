use anyhow::{Context, Result};
use inquire::{Password, Text};
use log::info;

use crate::{
    crypto, services,
    validation::{RuleType, ValidationRule},
};

pub fn set_command(
    environment: &str,
    key: &str,
    is_plaintext: bool,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    let encryption_key = encryption_key_service.env_key(environment)?;
    let value = if is_plaintext {
        let plaintext_value = Text::new(&format!("enter plaintext value for {}:", key))
            .prompt()
            .context("failed to get the plaintext value")?;
        SetValue::Plaintext(plaintext_value)
    } else {
        let secret_value = Password::new(&format!("enter secret value for {}:", key))
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .context("failed to safely get the secret value")?;
        SetValue::Secret(secret_value)
    };

    set_value(environment, key, value, encryption_key, vault_service)
}

enum SetValue {
    Plaintext(String),
    Secret(String),
}

fn set_value(
    environment: &str,
    key: &str,
    value: SetValue,
    encryption_key: &str,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    let mut vault = vault_service.env_vault(environment)?;
    let mut validation_rules = vault_service.validation_rules();

    match value {
        SetValue::Plaintext(plaintext_value) => {
            if plaintext_value.is_empty() {
                anyhow::bail!("plaintext value cannot be empty");
            }
            vault.insert(key.to_string(), plaintext_value);
        }
        SetValue::Secret(secret_value) => {
            if secret_value.is_empty() {
                anyhow::bail!("secret value cannot be empty");
            }
            vault.insert(
                key.to_string(),
                crypto::encrypt_value(&secret_value, encryption_key)
                    .context("failed to encrypt provided value")?,
            );
        }
    }

    if !validation_rules.contains_key(key) {
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

        vault_service.set_validation_rules(validation_rules);
    }

    vault_service.set_env_vault(environment, vault);
    vault_service.commit()?;

    info!("🔐 successfully set secret value for key: {}", key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::{
        commands::test_support::{KEY, Vault},
        services::VaultService,
        validation::{RuleType, ValidationRule},
    };

    #[test]
    fn stores_plaintext_and_adds_default_rule() {
        let mut vault = Vault::with_env("dev", IndexMap::new());
        set_value(
            "dev",
            "PLAIN",
            SetValue::Plaintext("value".into()),
            KEY,
            &mut vault,
        )
        .unwrap();
        assert_eq!(vault.environments["dev"]["PLAIN"], "value");
        assert!(vault.rules["PLAIN"].required);
        assert!(matches!(
            vault.rules["PLAIN"].rule_type,
            RuleType::String { .. }
        ));
        assert_eq!(vault.commits.get(), 1);
    }

    #[test]
    fn encrypts_secret_and_preserves_existing_rule() {
        let mut vault = Vault::with_env("dev", IndexMap::new());
        vault.rules.insert(
            "SECRET".into(),
            ValidationRule::new(RuleType::Boolean, false),
        );
        set_value(
            "dev",
            "SECRET",
            SetValue::Secret("sensitive".into()),
            KEY,
            &mut vault,
        )
        .unwrap();
        assert_eq!(
            crypto::decrypt_value(&vault.environments["dev"]["SECRET"], KEY).unwrap(),
            "sensitive"
        );
        assert!(matches!(vault.rules["SECRET"].rule_type, RuleType::Boolean));
        assert!(!vault.rules["SECRET"].required);
    }

    #[test]
    fn rejects_empty_values_missing_vault_and_bad_key() {
        for value in [
            SetValue::Plaintext(String::new()),
            SetValue::Secret(String::new()),
        ] {
            let mut vault = Vault::with_env("dev", IndexMap::new());
            assert!(set_value("dev", "KEY", value, KEY, &mut vault).is_err());
            assert_eq!(vault.commits.get(), 0);
        }
        assert!(
            set_value(
                "dev",
                "KEY",
                SetValue::Plaintext("value".into()),
                KEY,
                &mut Vault::default()
            )
            .is_err()
        );
        assert!(
            set_value(
                "dev",
                "KEY",
                SetValue::Secret("value".into()),
                "bad-key",
                &mut Vault::with_env("dev", IndexMap::new())
            )
            .is_err()
        );
    }

    #[test]
    fn propagates_commit_failure() {
        let mut vault = Vault {
            fail_commit: true,
            ..Vault::with_env("dev", IndexMap::new())
        };
        assert!(
            set_value(
                "dev",
                "KEY",
                SetValue::Plaintext("value".into()),
                KEY,
                &mut vault
            )
            .is_err()
        );
        assert_eq!(vault.commits.get(), 1);
        assert!(vault.env_vault("dev").unwrap().contains_key("KEY"));
    }
}
