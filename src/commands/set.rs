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
    let mut vault = vault_service.env_vault(environment)?;
    let mut validation_rules = vault_service.validation_rules();

    if is_plaintext {
        let plaintext_value = Text::new(&format!("enter plaintext value for {}:", key))
            .prompt()
            .context("failed to get the plaintext value")?;

        if plaintext_value.is_empty() {
            anyhow::bail!("plaintext value cannot be empty");
        }

        vault.insert(key.to_string(), plaintext_value);
    } else {
        let secret_value = Password::new(&format!("enter secret value for {}:", key))
            .with_display_mode(inquire::PasswordDisplayMode::Masked)
            .prompt()
            .context("failed to safely get the secret value")?;

        if secret_value.is_empty() {
            anyhow::bail!("secret value cannot be empty");
        }

        vault.insert(
            key.to_string(),
            crypto::encrypt_value(&secret_value, encryption_key)
                .context("failed to encrypt provided value")?,
        );
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
