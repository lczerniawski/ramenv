use std::path::{Path, PathBuf};

use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;

use crate::{crypto, models, validation::ValidationRule};

pub trait EncryptionKeyService {
    fn env_key(&self, environment: &str) -> Option<&str>;
    fn generate_new_env_key(&mut self, environment: &str);
    fn commit(&self) -> anyhow::Result<()>;
}

pub struct LocalEncryptionKeyService {
    keys_path: PathBuf,
    keys: IndexMap<String, String>,
}

impl LocalEncryptionKeyService {
    pub fn new(current_working_path: &Path) -> Result<Self> {
        let keys_file_path = current_working_path.join(".ramenv.keys");
        if !keys_file_path.exists() {
            anyhow::bail!("Keys file does not exist, please run `ramenv init` first");
        }

        std::fs::read_to_string(keys_file_path.clone())
            .map_err(|e| anyhow::anyhow!("Failed to read keys file: {}", e))
            .ok()
            .and_then(|content| {
                toml::from_str::<models::KeysFile>(&content)
                    .map_err(|e| anyhow::anyhow!("Failed to parse keys file: {}", e))
                    .ok()
            })
            .map(|key_file| {
                Ok(Self {
                    keys_path: keys_file_path,
                    keys: key_file.keys,
                })
            })
            .unwrap_or_else(|| anyhow::bail!("Failed to initialize EncryptionKeyService"))
    }
}

impl EncryptionKeyService for LocalEncryptionKeyService {
    fn env_key(&self, environment: &str) -> Option<&str> {
        self.keys.get(environment).map(|s| s.as_str())
    }

    fn generate_new_env_key(&mut self, environment: &str) {
        self.keys
            .insert(environment.to_string(), crypto::generate_master_key_hex());
    }

    fn commit(&self) -> anyhow::Result<()> {
        if !self.keys_path.exists() {
            anyhow::bail!("Keys file does not exist, please run `ramenv init` first");
        }

        let new_keys_file_content = models::KeysFile {
            keys: self.keys.clone(),
        };
        let new_keys_file_content =
            toml::to_string(&new_keys_file_content).context("failed to serialize keys to TOML")?;
        std::fs::write(&self.keys_path, &new_keys_file_content)
            .context("failed to write to keys file")?;

        Ok(())
    }
}

pub trait VaultService {
    fn env_vault(&self, environment: &str) -> Option<IndexMap<String, String>>;
    fn all_env_vaults(&self) -> IndexMap<String, IndexMap<String, String>>;
    fn set_env_vault(&mut self, environment: &str, values: IndexMap<String, String>);
    fn merge_env_vault(
        &mut self,
        environment: &str,
        values: IndexMap<String, String>,
    ) -> Result<()>;
    fn validation_rules(&self) -> IndexMap<String, ValidationRule>;
    fn set_validation_rules(&mut self, rules: IndexMap<String, ValidationRule>);
    fn commit(&self) -> Result<()>;
}

pub struct VaultRegistry {
    vault_path: PathBuf,
    name: String,
    version: String,
    validation: IndexMap<String, ValidationRule>,
    vaults: IndexMap<String, IndexMap<String, String>>,
}

impl VaultRegistry {
    pub fn new(current_working_path: &Path) -> Result<Self> {
        let vault_file_path = Path::new(current_working_path).join(".ramenv.vault.toml");
        if !vault_file_path.exists() {
            anyhow::bail!("Vault file does not exist, please run `ramenv init` first");
        }

        std::fs::read_to_string(vault_file_path.clone())
            .map_err(|e| anyhow::anyhow!("Failed to read vault file: {}", e))
            .ok()
            .and_then(|content| {
                toml::from_str::<models::VaultFile>(content.as_str())
                    .map_err(|e| anyhow::anyhow!("Failed to parse vault file: {}", e))
                    .ok()
            })
            .map(|vault_file| {
                Ok(Self {
                    vault_path: vault_file_path,
                    name: vault_file.name,
                    version: vault_file.version,
                    validation: vault_file.validation,
                    vaults: vault_file.environments,
                })
            })
            .unwrap_or_else(|| anyhow::bail!("Failed to initialize VaultService"))
    }
}

impl VaultService for VaultRegistry {
    fn env_vault(&self, environment: &str) -> Option<IndexMap<String, String>> {
        self.vaults.get(environment).cloned()
    }

    fn all_env_vaults(&self) -> IndexMap<String, IndexMap<String, String>> {
        self.vaults.clone()
    }

    fn set_env_vault(&mut self, environment: &str, values: IndexMap<String, String>) {
        self.vaults.insert(environment.to_string(), values);
    }

    fn merge_env_vault(
        &mut self,
        environment: &str,
        values: IndexMap<String, String>,
    ) -> Result<()> {
        let existing_vault = self
            .vaults
            .get_mut(environment)
            .ok_or_else(|| anyhow::anyhow!("Environment not found!"))?;

        for (key, value) in values {
            existing_vault.insert(key.to_string(), value.to_string());
        }

        Ok(())
    }

    fn commit(&self) -> anyhow::Result<()> {
        if !self.vault_path.exists() {
            anyhow::bail!("Vault file does not exist, please run `ramenv init` first");
        }

        let new_vault_file_content = models::VaultFile {
            name: self.name.clone(),
            version: self.version.clone(),
            validation: self.validation.clone(),
            environments: self.vaults.clone(),
        };
        let serialized_vault = toml::to_string(&new_vault_file_content)
            .context("failed to serialize vault file to TOML")?;
        std::fs::write(&self.vault_path, &serialized_vault)
            .context("failed to write to vault file")?;

        Ok(())
    }

    fn validation_rules(&self) -> IndexMap<String, ValidationRule> {
        self.validation.clone()
    }

    fn set_validation_rules(&mut self, rules: IndexMap<String, ValidationRule>) {
        self.validation = rules;
    }
}
