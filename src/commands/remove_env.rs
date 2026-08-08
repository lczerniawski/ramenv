use anyhow::Result;
use log::info;

use crate::services;

pub fn remove_env_command(
    environment: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    if encryption_key_service.env_key(environment).is_err() {
        anyhow::bail!("key for provided environment does not exist")
    }

    if vault_service.env_vault(environment).is_err() {
        anyhow::bail!("vault for provided environment does not exist");
    }

    encryption_key_service.remove_env_key(environment);
    vault_service.remove_env_vault(environment);
    encryption_key_service.commit()?;
    vault_service.commit()?;

    info!("✅ successfully removed environment: {}", environment);
    Ok(())
}
