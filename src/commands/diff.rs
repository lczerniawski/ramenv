use anyhow::{Ok, Result};
use comfy_table::{Table, presets::UTF8_FULL};

use crate::{commands::utils, crypto, services};
use utils::StringExt;

pub fn diff_command(
    env1: &str,
    env2: &str,
    reveal_secrets: bool,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let encryption_key1 = encryption_key_service.env_key(env1).ok_or_else(|| {
        anyhow::anyhow!(
            "key for {} environment does not exist, please run `ramenv create-env` first",
            env1
        )
    })?;
    let vault1 = vault_service.env_vault(env1).ok_or_else(|| {
        anyhow::anyhow!(
            "vault for {} environment does not exist, please run `ramenv create-env` first",
            env1
        )
    })?;

    let encryption_key2 = encryption_key_service.env_key(env2).ok_or_else(|| {
        anyhow::anyhow!(
            "key for {} environment does not exist, please run `ramenv create-env` first",
            env2
        )
    })?;
    let vault2 = vault_service.env_vault(env2).ok_or_else(|| {
        anyhow::anyhow!(
            "vault for {} environment does not exist, please run `ramenv create-env` first",
            env2
        )
    })?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header([
        "KEY",
        &format!("VALUE [{env1}]"),
        &format!("VALUE [{env2}]"),
        "STATUS",
    ]);

    for (key, value1) in vault1.iter() {
        let plaintext1 = get_plaintext(value1, encryption_key1)?;
        let display_value1 = get_display_value(&plaintext1, reveal_secrets)?;

        match vault2.get(key) {
            Some(value2) => {
                let plaintext2 = get_plaintext(value2, encryption_key2)?;
                let display_value2 = get_display_value(&plaintext2, reveal_secrets)?;

                if plaintext1 != plaintext2 {
                    table.add_row([key, &display_value1, &display_value2, "DIFFERENT"]);
                }
            }
            None => {
                table.add_row([key, &display_value1, "", &format!("NOT FOUND IN {env2}")]);
            }
        }
    }

    for (key, value2) in vault2.iter() {
        let plaintext2 = get_plaintext(value2, encryption_key2)?;
        let display_value2 = get_display_value(&plaintext2, reveal_secrets)?;

        if !vault1.contains_key(key) {
            table.add_row([key, "", &display_value2, &format!("NOT FOUND IN {env1}")]);
        }
    }

    println!("{table}");
    Ok(())
}

fn get_plaintext(value: &str, encryption_key: &str) -> Result<String> {
    if value.is_secret() {
        crypto::decrypt_value(value, encryption_key)
    } else {
        Ok(value.to_string())
    }
}

fn get_display_value(plaintext: &str, reveal_secrets: bool) -> Result<String> {
    if reveal_secrets {
        Ok(plaintext.to_string())
    } else {
        Ok(utils::mask_secret(plaintext))
    }
}
