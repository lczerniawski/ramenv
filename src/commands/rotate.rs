use anyhow::Result;
use indexmap::IndexMap;
use log::info;

use crate::{
    crypto, services,
    utils::{self, StringExt},
};

pub fn rotate_command(
    env: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vault_registry: &mut impl services::VaultService,
) -> Result<()> {
    let encryption_key = encryption_key_service.env_key(env)?.to_owned();
    let vault = vault_registry.env_vault(env)?;

    let mut new_vault = IndexMap::new();
    encryption_key_service.store_new_env_key(env);
    let new_encryption_key = encryption_key_service.env_key(env)?;

    for (key, value) in vault.iter() {
        if value.is_secret() {
            let plaintext = utils::get_plaintext(value, &encryption_key)?;
            let rotated_secret = crypto::encrypt_value(&plaintext, new_encryption_key)?;
            new_vault.insert(key.to_string(), rotated_secret);
        } else {
            new_vault.insert(key.to_string(), value.clone());
        }
    }

    vault_registry.set_env_vault(env, new_vault);

    vault_registry.commit()?;
    encryption_key_service.commit()?;

    info!(
        "🔄 successfully rotated encryption keys for environment: {}",
        env
    );
    Ok(())
}
