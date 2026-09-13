mod create_env;
mod delete;
mod diff;
mod init;
mod list;
mod on_board;
mod remove_env;
mod rotate;
mod run;
mod set;
mod validate;

pub use create_env::create_env_command;
pub use delete::delete_command;
pub use diff::diff_command;
pub use init::init_command;
pub use list::list_command;
pub use on_board::on_board_command;
pub use remove_env::remove_env_command;
pub use rotate::rotate_command;
pub use run::run_command;
pub use set::set_command;
pub use validate::validate_command;

#[cfg(test)]
pub(super) mod test_support {
    use std::cell::Cell;

    use anyhow::Result;
    use indexmap::IndexMap;

    use crate::{services, validation::ValidationRule};

    pub const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[derive(Default)]
    pub struct Keys {
        pub values: IndexMap<String, String>,
        pub signatures: IndexMap<String, String>,
        pub commits: Cell<usize>,
        pub fail_commit: bool,
    }

    impl Keys {
        pub fn with_env(environment: &str) -> Self {
            Self {
                values: IndexMap::from([(environment.into(), KEY.into())]),
                ..Self::default()
            }
        }
    }

    impl services::EncryptionKeyService for Keys {
        fn env_key(&self, environment: &str) -> Result<&str> {
            self.values
                .get(environment)
                .map(String::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing key"))
        }

        fn set_env_key(&mut self, environment: &str, key: String) {
            self.values.insert(environment.into(), key);
        }

        fn store_new_env_key(&mut self, environment: &str) {
            self.values
                .insert(environment.into(), crate::crypto::generate_master_key_hex());
        }

        fn remove_env_key(&mut self, environment: &str) {
            self.values.shift_remove(environment);
        }

        fn vault_signature_key(&self, vault: &str) -> Result<&str> {
            self.signatures
                .get(vault)
                .map(String::as_str)
                .ok_or_else(|| anyhow::anyhow!("missing signature key"))
        }

        fn store_new_vault_signature_key(&mut self, vault: &str) {
            self.signatures
                .insert(vault.into(), crate::crypto::generate_signature_key_hex());
        }

        fn commit(&self) -> Result<()> {
            self.commits.set(self.commits.get() + 1);
            if self.fail_commit {
                anyhow::bail!("key commit failed");
            }
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct Vault {
        pub environments: IndexMap<String, IndexMap<String, String>>,
        pub rules: IndexMap<String, ValidationRule>,
        pub commits: Cell<usize>,
        pub fail_commit: bool,
    }

    impl Vault {
        pub fn with_env(environment: &str, values: IndexMap<String, String>) -> Self {
            Self {
                environments: IndexMap::from([(environment.into(), values)]),
                ..Self::default()
            }
        }
    }

    impl services::VaultService for Vault {
        fn env_vault(&self, environment: &str) -> Result<IndexMap<String, String>> {
            self.environments
                .get(environment)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing vault"))
        }

        fn all_env_vaults(&self) -> IndexMap<String, IndexMap<String, String>> {
            self.environments.clone()
        }

        fn set_env_vault(&mut self, environment: &str, values: IndexMap<String, String>) {
            self.environments.insert(environment.into(), values);
        }

        fn remove_env_vault(&mut self, environment: &str) {
            self.environments.shift_remove(environment);
        }

        fn merge_env_vault(
            &mut self,
            environment: &str,
            values: IndexMap<String, String>,
        ) -> Result<()> {
            let existing = self
                .environments
                .get_mut(environment)
                .ok_or_else(|| anyhow::anyhow!("missing vault"))?;
            existing.extend(values);
            Ok(())
        }

        fn validation_rules(&self) -> IndexMap<String, ValidationRule> {
            self.rules.clone()
        }

        fn set_validation_rules(&mut self, rules: IndexMap<String, ValidationRule>) {
            self.rules = rules;
        }

        fn commit(&self) -> Result<()> {
            self.commits.set(self.commits.get() + 1);
            if self.fail_commit {
                anyhow::bail!("vault commit failed");
            }
            Ok(())
        }
    }
}
