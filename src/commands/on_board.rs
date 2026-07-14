use std::{collections::HashMap, path::Path};

use anyhow::Context;
use inquire::MultiSelect;
use log::info;

use crate::{crypto, services};

pub fn on_board_command(
    current_working_path: &Path,
    environment: &str,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> anyhow::Result<()> {
    let env_file_path = current_working_path.join(".env");

    if !env_file_path.exists() {
        info!(".env file does not exist, nothing to onboard");
    }
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

    let encryption_key = encryption_key_service
        .env_key(environment)
        .context(format!(
            "No encryption key found for environment: {}",
            environment
        ))?;

    let vault_data: HashMap<String, String> = env_file_data
        .into_iter()
        .map(|(key, value)| {
            if keys_selected_for_encryption.contains(&key) {
                let encrypted_data = crypto::encrypt_value(&value, encryption_key)?;
                Ok((key, encrypted_data))
            } else {
                Ok((key, value))
            }
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()?;

    vault_service.merge_env_vault(environment, vault_data);
    vault_service
        .commit()
        .context("failed to commit configuration into vault file")?;

    info!("🎉 vault onboarded successfully!");
    Ok(())
}
