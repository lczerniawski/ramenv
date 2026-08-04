use std::path::{Path, PathBuf};

use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;

use crate::{crypto, models, validation::ValidationRule};

pub trait EncryptionKeyService {
    fn env_key(&self, environment: &str) -> Result<&str>;
    fn store_new_env_key(&mut self, environment: &str);
    fn vault_signature_key(&self, vault: &str) -> Result<&str>;
    fn store_new_vault_signature_key(&mut self, vault: &str);
    fn commit(&self) -> anyhow::Result<()>;
}

pub struct LocalEncryptionKeyService {
    keys_path: PathBuf,
    keys: IndexMap<String, String>,
    signatures: IndexMap<String, String>,
}

impl LocalEncryptionKeyService {
    pub fn new(workspace_root: &Path) -> Result<Self> {
        let keys_file_path = workspace_root.join(".ramenv.keys");
        if !keys_file_path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }

        std::fs::read_to_string(keys_file_path.clone())
            .map_err(|e| anyhow::anyhow!("failed to read keys file: {}", e))
            .ok()
            .and_then(|content| {
                toml::from_str::<models::KeysFile>(&content)
                    .map_err(|e| anyhow::anyhow!("failed to parse keys file: {}", e))
                    .ok()
            })
            .map(|key_file| {
                Ok(Self {
                    keys_path: keys_file_path,
                    keys: key_file.keys,
                    signatures: key_file.signatures,
                })
            })
            .unwrap_or_else(|| anyhow::bail!("failed to initialize encryption key service"))
    }
}

impl EncryptionKeyService for LocalEncryptionKeyService {
    fn env_key(&self, environment: &str) -> Result<&str> {
        self.keys
            .get(environment)
            .map(|s| s.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "key for {} environment does not exist, please run `ramenv create-env` first",
                    environment
                )
            })
    }

    fn store_new_env_key(&mut self, environment: &str) {
        self.keys
            .insert(environment.to_string(), crypto::generate_master_key_hex());
    }

    fn vault_signature_key(&self, vault: &str) -> Result<&str> {
        self.signatures
            .get(vault)
            .map(|s| s.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "signature key for {} vault does not exist, please run `ramenv init` first",
                    vault
                )
            })
    }

    fn store_new_vault_signature_key(&mut self, vault: &str) {
        self.signatures
            .insert(vault.to_string(), crypto::generate_signature_key_hex());
    }

    fn commit(&self) -> anyhow::Result<()> {
        if !self.keys_path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }

        let new_keys_file_content = models::KeysFile {
            keys: self.keys.clone(),
            signatures: self.signatures.clone(),
        };
        let new_keys_file_content =
            toml::to_string(&new_keys_file_content).context("failed to serialize keys to TOML")?;
        std::fs::write(&self.keys_path, &new_keys_file_content)
            .context("failed to write to keys file")?;

        Ok(())
    }
}

pub trait VaultService {
    fn env_vault(&self, environment: &str) -> Result<IndexMap<String, String>>;
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
    vault_signing_key: String,
    validation: IndexMap<String, ValidationRule>,
    environments: IndexMap<String, IndexMap<String, String>>,
}

impl VaultRegistry {
    pub fn new(current_working_path: &Path, vault_signing_key: &str) -> Result<Self> {
        let vault_file_path = Path::new(current_working_path).join(".ramenv.vault.toml");
        if !vault_file_path.exists() {
            anyhow::bail!("vault file does not exist, please run `ramenv init` first");
        }

        std::fs::read_to_string(vault_file_path.clone())
            .map_err(|e| anyhow::anyhow!("failed to read vault file: {}", e))
            .ok()
            .and_then(|content| {
                toml::from_str::<models::VaultFile>(content.as_str())
                    .map_err(|e| anyhow::anyhow!("failed to parse vault file: {}", e))
                    .ok()
            })
            .map(|vault_file| {
                let canonical_vault = models::CanonicalVault {
                    validation: vault_file.validation.clone(),
                    environments: vault_file.environments.clone(),
                };
                let canonical_value_str = serde_json::to_string(&canonical_vault)
                    .context("failed to serialize vault for verification")?;
                crypto::verify_signature(
                    &canonical_value_str,
                    &vault_file.metadata.signature,
                    vault_signing_key,
                )
                .context("failed to verify vault signature")?;

                Ok(Self {
                    vault_path: vault_file_path,
                    vault_signing_key: vault_signing_key.to_string(),
                    validation: vault_file.validation,
                    environments: vault_file.environments,
                })
            })
            .unwrap_or_else(|| anyhow::bail!("failed to initialize vault service"))
    }
}

impl VaultService for VaultRegistry {
    fn env_vault(&self, environment: &str) -> Result<IndexMap<String, String>> {
        self.environments.get(environment).cloned().ok_or_else(|| {
            anyhow::anyhow!(
                "vault for {} environment does not exist, please run `ramenv create-env` first",
                environment
            )
        })
    }

    fn all_env_vaults(&self) -> IndexMap<String, IndexMap<String, String>> {
        self.environments.clone()
    }

    fn set_env_vault(&mut self, environment: &str, values: IndexMap<String, String>) {
        self.environments.insert(environment.to_string(), values);
    }

    fn merge_env_vault(
        &mut self,
        environment: &str,
        values: IndexMap<String, String>,
    ) -> Result<()> {
        let existing_vault = self
            .environments
            .get_mut(environment)
            .ok_or_else(|| anyhow::anyhow!("environment not found!"))?;

        for (key, value) in values {
            existing_vault.insert(key.to_string(), value.to_string());
        }

        Ok(())
    }

    fn commit(&self) -> anyhow::Result<()> {
        if !self.vault_path.exists() {
            anyhow::bail!("vault file does not exist, please run `ramenv init` first");
        }

        let canonical_vault = models::CanonicalVault {
            validation: self.validation.clone(),
            environments: self.environments.clone(),
        };
        let canonical_vault_str = serde_json::to_string(&canonical_vault)
            .context("failed to serialize vault for verification")?;
        let signature = crypto::generate_signature(&canonical_vault_str, &self.vault_signing_key)?;
        let metadata = models::VaultMetadata {
            signature,
            signature_version: "1".to_string(),
            signed_at: chrono::Utc::now().to_rfc3339(),
        };

        let new_vault_file_content = models::VaultFile {
            validation: self.validation.clone(),
            environments: self.environments.clone(),
            metadata,
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

pub trait WorkspaceService {
    fn get_workspace_root(&self) -> PathBuf;
}

pub struct WorkspaceRegistry {
    workspace_root: PathBuf,
    #[allow(dead_code)]
    workspace_name: String,
    #[allow(dead_code)]
    schema_version: String,
}

impl WorkspaceRegistry {
    pub fn new(current_working_path: &Path) -> Result<Self> {
        let workspace_root = Self::find_workspace_root(current_working_path)?;
        let workspace = Self::load_workspace(&workspace_root)?;

        Ok(Self {
            workspace_root,
            workspace_name: workspace.workspace_name,
            schema_version: workspace.schema_version,
        })
    }

    fn find_workspace_root(start: &Path) -> Result<PathBuf> {
        let mut current = start.to_path_buf();

        loop {
            let has_workspace = current.join(".ramenv.workspace.toml").exists();
            let has_keys = current.join(".ramenv.keys").exists();

            if has_workspace || has_keys {
                return Ok(current);
            }

            if current.join(".git").exists() {
                anyhow::bail!(
                    "found .git but no .ramenv.workspace.toml or .ramenv.keys. Run `ramenv init`."
                );
            }

            if !current.pop() {
                anyhow::bail!("no ramenv workspace found. Run `ramenv init`.");
            }
        }
    }

    fn load_workspace(root: &Path) -> Result<models::WorkspaceFile> {
        let workspace_file_path = root.join(".ramenv.workspace.toml");
        if !workspace_file_path.exists() {
            anyhow::bail!("workspace file does not exist, please run `ramenv init` first");
        }

        let content = std::fs::read_to_string(&workspace_file_path)?;
        toml::from_str(&content).context("failed to parse workspace file")
    }
}

impl WorkspaceService for WorkspaceRegistry {
    fn get_workspace_root(&self) -> PathBuf {
        self.workspace_root.to_path_buf()
    }
}
