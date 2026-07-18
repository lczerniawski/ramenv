use anyhow::Result;
use comfy_table::{Table, presets::UTF8_FULL};

use crate::{commands::utils, crypto, services};
use utils::StringExt;

pub fn list_command(
    environment: &str,
    reveal_secrets: bool,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let encryption_key = encryption_key_service.env_key(environment).ok_or_else(|| {
        anyhow::anyhow!(
            "key for selected environment does not exist, please run `ramenv create-env` first"
        )
    })?;
    let vault = vault_service.env_vault(environment).ok_or_else(|| {
        anyhow::anyhow!(
            "vault for selected environment does not exist, please run `ramenv create-env` first"
        )
    })?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(["KEY", "VALUE"]);

    for (key, value) in vault {
        let display_value = if value.is_secret() {
            let plaintext = crypto::decrypt_value(&value, encryption_key)?;
            if reveal_secrets {
                plaintext
            } else {
                utils::mask_secret(&plaintext)
            }
        } else {
            value
        };

        table.add_row(vec![key, display_value]);
    }

    println!("{table}");
    Ok(())
}
