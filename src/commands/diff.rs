use anyhow::{Ok, Result};
use comfy_table::{Table, presets::UTF8_FULL};

use crate::{
    services,
    utils::{self},
};

pub fn diff_command(
    env1: &str,
    env2: &str,
    reveal_secrets: bool,
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    let encryption_key1 = encryption_key_service.env_key(env1)?;
    let vault1 = vault_service.env_vault(env1)?;

    let encryption_key2 = encryption_key_service.env_key(env2)?;
    let vault2 = vault_service.env_vault(env2)?;

    let mut table = Table::new();
    table.load_preset(UTF8_FULL).set_header([
        "KEY",
        &format!("VALUE [{env1}]"),
        &format!("VALUE [{env2}]"),
        "STATUS",
    ]);

    for (key, value1) in vault1.iter() {
        let plaintext1 = utils::get_plaintext(value1, encryption_key1)?;
        let display_value1 = utils::get_display_value(&plaintext1, reveal_secrets)?;

        match vault2.get(key) {
            Some(value2) => {
                let plaintext2 = utils::get_plaintext(value2, encryption_key2)?;
                let display_value2 = utils::get_display_value(&plaintext2, reveal_secrets)?;

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
        let plaintext2 = utils::get_plaintext(value2, encryption_key2)?;
        let display_value2 = utils::get_display_value(&plaintext2, reveal_secrets)?;

        if !vault1.contains_key(key) {
            table.add_row([key, "", &display_value2, &format!("NOT FOUND IN {env1}")]);
        }
    }

    println!("{table}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::commands::test_support::{KEY, Keys, Vault};

    fn services() -> (Keys, Vault) {
        let keys = Keys {
            values: IndexMap::from([("one".into(), KEY.into()), ("two".into(), KEY.into())]),
            ..Keys::default()
        };
        let vault = Vault {
            environments: IndexMap::from([
                (
                    "one".into(),
                    IndexMap::from([
                        ("SAME".into(), "same".into()),
                        ("CHANGED".into(), "one".into()),
                        ("ONLY_ONE".into(), "first".into()),
                    ]),
                ),
                (
                    "two".into(),
                    IndexMap::from([
                        ("SAME".into(), "same".into()),
                        ("CHANGED".into(), "two".into()),
                        ("ONLY_TWO".into(), "second".into()),
                    ]),
                ),
            ]),
            ..Vault::default()
        };
        (keys, vault)
    }

    #[test]
    fn handles_equal_changed_and_one_sided_values_in_both_display_modes() {
        let (keys, vault) = services();
        assert!(diff_command("one", "two", false, &keys, &vault).is_ok());
        assert!(diff_command("one", "two", true, &keys, &vault).is_ok());
    }

    #[test]
    fn reports_missing_state_and_bad_ciphertext() {
        let (keys, vault) = services();
        assert!(diff_command("missing", "two", false, &keys, &vault).is_err());
        assert!(diff_command("one", "missing", false, &keys, &vault).is_err());

        let mut vault = vault;
        vault.environments["one"].insert("BAD".into(), "secret:bad".into());
        assert!(diff_command("one", "two", false, &keys, &vault).is_err());
    }
}
