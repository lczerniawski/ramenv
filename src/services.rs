use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::exit,
};

use anyhow::Ok;
use log::error;

use crate::models;

pub trait EncryptionKeyService {
    fn key(&self, environment: &str) -> Option<&str>;
}

pub struct LocalEncryptionKeyService {
    keys: HashMap<String, String>,
}

impl LocalEncryptionKeyService {
    pub fn new(current_working_path: &Path) -> Self {
        let keys_file_path = current_working_path.join(".ramenv.keys");
        if !keys_file_path.exists() {
            error!("Keys file does not exist, please run `ramenv init` first");
            exit(1);
        }

        std::fs::read_to_string(keys_file_path)
            .map_err(|e| {
                error!("Failed to read keys file: {}", e);
                exit(1);
            })
            .ok()
            .and_then(|content| {
                toml::from_str::<models::KeysFile>(&content)
                    .map_err(|e| {
                        error!("Failed to parse keys file: {}", e);
                        exit(1);
                    })
                    .ok()
            })
            .map(|key_file| Self {
                keys: key_file.keys,
            })
            .unwrap_or_else(|| {
                error!("Failed to initialize EncryptionKeyService");
                exit(1);
            })
    }
}

impl EncryptionKeyService for LocalEncryptionKeyService {
    fn key(&self, environemnt: &str) -> Option<&str> {
        self.keys.get(environemnt).map(|s| s.as_str())
    }
}

pub trait VaultService {
    fn vault(&self, environemnt: &str) -> Option<HashMap<String, String>>;
    fn set_vault(&mut self, environemnt: &str, values: HashMap<String, String>);
    fn merge_vault(&mut self, environemnt: &str, values: HashMap<String, String>);
    fn commit(&self) -> anyhow::Result<()>;
}

pub struct VaultRegistry {
    vault_path: PathBuf,
    vaults: HashMap<String, HashMap<String, String>>,
}

impl VaultRegistry {
    pub fn new(current_working_path: &Path) -> Self {
        let vault_file_path = Path::new(current_working_path).join(".ramenv.vault.toml");
        if !vault_file_path.exists() {
            error!("Vault file does not exist, please run `ramenv init` first");
            exit(1);
        }

        std::fs::read_to_string(vault_file_path.clone())
            .map_err(|e| {
                error!("Failed to read vault file: {}", e);
                exit(1);
            })
            .ok()
            .and_then(|content| {
                toml::from_str::<models::VaultFile>(content.as_str())
                    .map_err(|e| {
                        error!("Failed to parse vault file: {}", e);
                        exit(1);
                    })
                    .ok()
            })
            .map(|vault_file| Self {
                vault_path: vault_file_path,
                vaults: vault_file.environemnts,
            })
            .unwrap_or_else(|| {
                error!("Failed to initialize VaultService");
                exit(1);
            })
    }
}

impl VaultService for VaultRegistry {
    fn vault(&self, environment: &str) -> Option<HashMap<String, String>> {
        self.vaults.get(environment).cloned()
    }

    fn set_vault(&mut self, environment: &str, values: HashMap<String, String>) {
        self.vaults.insert(environment.to_string(), values);
    }

    fn merge_vault(&mut self, environment: &str, values: HashMap<String, String>) {
        let existing_vault = self.vaults.get_mut(environment).unwrap_or_else(|| {
            error!("Environment not found!");
            exit(1);
        });

        for (key, value) in values {
            existing_vault.insert(key.to_string(), value.to_string());
        }
    }

    fn commit(&self) -> anyhow::Result<()> {
        if !self.vault_path.exists() {
            anyhow::bail!("Vault file does not exist, please run `ramenv init` first");
        }

        let new_vault_file_content = models::VaultFile {
            environemnts: self.vaults.clone(),
        };
        let serialized_vault = toml::to_string(&new_vault_file_content)?;
        std::fs::write(&self.vault_path, &serialized_vault)?;

        Ok(())
    }
}
