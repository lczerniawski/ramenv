use std::{collections::HashMap, process::exit};

use crate::services;
use anyhow::{Context, Ok, Result};
use log::info;

pub fn create_env_command(
    environment: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_service: &mut impl services::VaultService,
) -> Result<()> {
    if encryption_key_service.env_key(environment).is_some() {
        info!("key for provided environment already exists");
        exit(1);
    }

    if vault_service.env_vault(environment).is_some() {
        info!("vault for provided environment already exists");
        exit(1);
    }

    encryption_key_service.generate_new_env_key(environment);
    encryption_key_service
        .commit()
        .context("failed to synchronize keys back to file")?;

    vault_service.set_env_vault(environment, HashMap::new());
    vault_service
        .commit()
        .context("failed to synchronize secrets back to file")?;

    Ok(())
}
