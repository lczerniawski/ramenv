use std::process::exit;

use anyhow::Result;
use log::error;

use crate::{crypto, services};

pub fn list_command(
    environment: &str,
    reveal_secrets: bool,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let encryption_key = encryption_key_service
        .env_key(environment)
        .unwrap_or_else(|| {
            error!(
                "key for selected environment does not exist, please run `ramenv create-env` first"
            );
            exit(1);
        });
    let vault = vault_service.env_vault(environment).unwrap_or_else(|| {
        error!(
            "vault for selected environment does not exist, please run `ramenv create-env` first"
        );
        exit(1);
    });

    println!("{:<20} | {:<20}", "KEY", "VALUE");
    println!("{}", "-".repeat(43));

    for (key, value) in vault {
        let plaintext = crypto::decrypt_value(&value, encryption_key)?;
        let display_value = if reveal_secrets {
            plaintext
        } else {
            mask_secret(&plaintext)
        };

        println!("{:<20} | {:<20}", key, display_value);
    }

    Ok(())
}

fn mask_secret(secret: &str) -> String {
    let len = secret.len();

    if len <= 4 {
        return "••••".to_string();
    }

    if len <= 10 {
        return format!("{}••••{}", &secret[..1], &secret[len - 1..]);
    }

    format!("{}••••{}", &secret[..4], &secret[len - 4..])
}
