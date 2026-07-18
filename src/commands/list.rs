use anyhow::Result;
use comfy_table::{Table, presets::UTF8_FULL};

use crate::{services, utils};

pub fn list_command(
    environment: &str,
    reveal_secrets: bool,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let encryption_key = encryption_key_service.env_key(environment)?;
    let vault = vault_service.env_vault(environment)?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header(["KEY", "VALUE"]);

    for (key, value) in vault {
        let plaintext = utils::get_plaintext(&value, encryption_key)?;
        let display_value = utils::get_display_value(&plaintext, reveal_secrets)?;

        table.add_row(vec![key, display_value]);
    }

    println!("{table}");
    Ok(())
}
