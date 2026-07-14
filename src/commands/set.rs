use std::process::exit;

use anyhow::{Context, Result};
use inquire::Password;
use log::{error, info};

use crate::{crypto, services};

pub fn set_command(
    environment: &str,
    key: &str,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    let encryption_key = encryption_key_service
        .env_key(environment)
        .unwrap_or_else(|| {
            error!(
                "key for selected environment does not exist, please run `ramenv create-env` first"
            );
            exit(1);
        });
    let mut vault = vault_service.env_vault(environment).unwrap_or_else(|| {
        error!(
            "vault for selected environment does not exist, please run `ramenv create-env` first"
        );
        exit(1);
    });

    let secret_value = Password::new(&format!("enter secret value for {}:", key))
        .with_display_mode(inquire::PasswordDisplayMode::Masked)
        .prompt()
        .context("failed to safely get the secret value")?;

    if secret_value.is_empty() {
        error!("secret value cannot be empty");
        exit(1);
    }

    vault.insert(
        key.to_string(),
        crypto::encrypt_value(&secret_value, encryption_key)
            .context("failed to encrypt provided value")?,
    );
    vault_service.set_env_vault(environment, vault);
    vault_service.commit()?;

    info!("successfully set secret value for key: {}", key);
    Ok(())
}
