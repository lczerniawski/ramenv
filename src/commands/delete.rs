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
        validation_rules.shift_remove(key);
        vault_service.set_env_vault(environment, vault);
        vault_service.set_validation_rules(validation_rules);
        vault_service.commit()?;
        info!("✅ key {} deleted successfully", key);
        return Ok(());
    }
    anyhow::bail!("❌ key {} not found", key);
}
