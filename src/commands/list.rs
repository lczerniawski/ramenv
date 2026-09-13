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

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::{
        commands::test_support::{KEY, Keys, Vault},
        crypto,
    };

    #[test]
    fn lists_plain_and_encrypted_values_in_masked_and_revealed_modes() {
        let keys = Keys::with_env("dev");
        let vault = Vault::with_env(
            "dev",
            IndexMap::from([
                (
                    "SECRET".into(),
                    crypto::encrypt_value("value", KEY).unwrap(),
                ),
                ("PLAIN".into(), "plain".into()),
            ]),
        );
        assert!(list_command("dev", false, &keys, &vault).is_ok());
        assert!(list_command("dev", true, &keys, &vault).is_ok());
    }

    #[test]
    fn reports_missing_key_vault_and_invalid_ciphertext() {
        assert!(
            list_command(
                "dev",
                false,
                &Keys::default(),
                &Vault::with_env("dev", IndexMap::new())
            )
            .is_err()
        );
        assert!(list_command("dev", false, &Keys::with_env("dev"), &Vault::default()).is_err());
        assert!(
            list_command(
                "dev",
                false,
                &Keys::with_env("dev"),
                &Vault::with_env("dev", IndexMap::from([("KEY".into(), "secret:bad".into())]))
            )
            .is_err()
        );
    }
}
