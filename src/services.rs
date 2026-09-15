use std::path::{Path, PathBuf};

use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;

use crate::{crypto, models, validation::ValidationRule};

pub trait EncryptionKeyService {
    fn env_key(&self, environment: &str) -> Result<&str>;
    fn set_env_key(&mut self, environment: &str, key: String);
    fn store_new_env_key(&mut self, environment: &str);
    fn remove_env_key(&mut self, environment: &str);
    fn vault_signature_key(&self, vault: &str) -> Result<&str>;
    fn store_new_vault_signature_key(&mut self, vault: &str);
    fn commit(&self) -> anyhow::Result<()>;
}

pub struct LocalEncryptionKeyService {
    keys_path: PathBuf,
    encryption_keys: IndexMap<String, String>,
    signature_keys: IndexMap<String, String>,
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
                    encryption_keys: key_file.encryption_keys,
                    signature_keys: key_file.signature_keys,
                })
            })
            .unwrap_or_else(|| anyhow::bail!("failed to initialize encryption key service"))
    }
}

impl EncryptionKeyService for LocalEncryptionKeyService {
    fn env_key(&self, environment: &str) -> Result<&str> {
        self.encryption_keys
            .get(environment)
            .map(|s| s.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "key for {} environment does not exist, please run `ramenv create-env` first",
                    environment
                )
            })
    }

    fn set_env_key(&mut self, environment: &str, key: String) {
        self.encryption_keys.insert(environment.to_string(), key);
    }

    fn store_new_env_key(&mut self, environment: &str) {
        self.encryption_keys
            .insert(environment.to_string(), crypto::generate_master_key_hex());
    }

    fn remove_env_key(&mut self, environment: &str) {
        self.encryption_keys.shift_remove(environment);
    }

    fn vault_signature_key(&self, vault: &str) -> Result<&str> {
        self.signature_keys
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
        self.signature_keys
            .insert(vault.to_string(), crypto::generate_signature_key_hex());
    }

    fn commit(&self) -> anyhow::Result<()> {
        if !self.keys_path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }

        let new_keys_file_content = models::KeysFile {
            encryption_keys: self.encryption_keys.clone(),
            signature_keys: self.signature_keys.clone(),
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
    fn remove_env_vault(&mut self, environment: &str);
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

    fn remove_env_vault(&mut self, environment: &str) {
        self.environments.shift_remove(environment);
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

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::models::{
        CanonicalVault, KeysFile, Provider, VaultFile, VaultMetadata, WorkspaceFile,
    };

    const ENV_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SIGNING_KEY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "ramenv-unit-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_keys(root: &Path) {
        let mut file = KeysFile::default();
        file.encryption_keys
            .insert("development".into(), ENV_KEY.into());
        file.signature_keys.insert("/".into(), SIGNING_KEY.into());
        std::fs::write(root.join(".ramenv.keys"), toml::to_string(&file).unwrap()).unwrap();
    }

    fn write_vault(root: &Path) {
        let mut environments = IndexMap::new();
        environments.insert(
            "development".into(),
            IndexMap::from([("API_KEY".into(), "value".into())]),
        );
        let canonical = serde_json::to_string(&CanonicalVault {
            environments: environments.clone(),
        })
        .unwrap();
        let file = VaultFile {
            validation: IndexMap::new(),
            environments,
            metadata: VaultMetadata {
                signature: crypto::generate_signature(&canonical, SIGNING_KEY).unwrap(),
                signature_version: "1".into(),
                signed_at: "2026-01-01T00:00:00Z".into(),
            },
        };
        std::fs::write(
            root.join(".ramenv.vault.toml"),
            toml::to_string(&file).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn key_service_loads_mutates_and_persists_keys() {
        let root = TempDir::new("keys");
        write_keys(&root.0);
        let mut service = LocalEncryptionKeyService::new(&root.0).unwrap();
        assert_eq!(service.env_key("development").unwrap(), ENV_KEY);
        assert_eq!(service.vault_signature_key("/").unwrap(), SIGNING_KEY);

        service.store_new_env_key("production");
        service.store_new_vault_signature_key("services/api");
        assert_eq!(service.env_key("production").unwrap().len(), 64);
        service.remove_env_key("development");
        service.commit().unwrap();

        let reloaded = LocalEncryptionKeyService::new(&root.0).unwrap();
        assert!(reloaded.env_key("development").is_err());
        assert_eq!(reloaded.env_key("production").unwrap().len(), 64);
        assert_eq!(
            reloaded.vault_signature_key("services/api").unwrap().len(),
            128
        );
    }

    #[test]
    fn key_service_reports_missing_and_malformed_files() {
        let root = TempDir::new("bad-keys");
        assert!(LocalEncryptionKeyService::new(&root.0).is_err());

        std::fs::create_dir(root.0.join(".ramenv.keys")).unwrap();
        assert!(LocalEncryptionKeyService::new(&root.0).is_err());
        std::fs::remove_dir(root.0.join(".ramenv.keys")).unwrap();
        std::fs::write(root.0.join(".ramenv.keys"), "not = [valid").unwrap();
        assert!(LocalEncryptionKeyService::new(&root.0).is_err());
    }

    #[test]
    fn key_service_commit_fails_if_backing_file_was_removed() {
        let root = TempDir::new("removed-keys");
        write_keys(&root.0);
        let service = LocalEncryptionKeyService::new(&root.0).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.keys")).unwrap();
        assert!(service.commit().is_err());
    }

    #[test]
    fn key_service_commit_reports_an_unwritable_backing_path() {
        let root = TempDir::new("unwritable-keys");
        write_keys(&root.0);
        let service = LocalEncryptionKeyService::new(&root.0).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.keys")).unwrap();
        std::fs::create_dir(root.0.join(".ramenv.keys")).unwrap();
        assert!(service.commit().is_err());
    }

    #[test]
    fn vault_registry_verifies_and_persists_all_mutations() {
        let root = TempDir::new("vault");
        write_vault(&root.0);
        let mut registry = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        assert_eq!(
            registry.env_vault("development").unwrap()["API_KEY"],
            "value"
        );
        assert!(registry.env_vault("missing").is_err());

        registry
            .merge_env_vault(
                "development",
                IndexMap::from([("OTHER".into(), "second".into())]),
            )
            .unwrap();
        assert!(
            registry
                .merge_env_vault("missing", IndexMap::new())
                .is_err()
        );
        registry.set_env_vault("production", IndexMap::new());
        registry.remove_env_vault("production");
        let rules = IndexMap::from([(
            "API_KEY".into(),
            ValidationRule::new(
                crate::validation::RuleType::String {
                    min_len: Some(1),
                    max_len: None,
                },
                true,
            ),
        )]);
        registry.set_validation_rules(rules);
        registry.commit().unwrap();

        let reloaded = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        let vault = reloaded.env_vault("development").unwrap();
        assert_eq!(vault["OTHER"], "second");
        assert!(reloaded.validation_rules().contains_key("API_KEY"));
    }

    #[test]
    fn vault_registry_rejects_missing_malformed_tampered_and_wrongly_signed_files() {
        let root = TempDir::new("bad-vault");
        assert!(VaultRegistry::new(&root.0, SIGNING_KEY).is_err());
        std::fs::write(root.0.join(".ramenv.vault.toml"), "bad = [toml").unwrap();
        assert!(VaultRegistry::new(&root.0, SIGNING_KEY).is_err());

        write_vault(&root.0);
        assert!(VaultRegistry::new(&root.0, ENV_KEY).is_err());
        let mut file: VaultFile =
            toml::from_str(&std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap())
                .unwrap();
        file.environments
            .get_mut("development")
            .unwrap()
            .insert("TAMPERED".into(), "yes".into());
        std::fs::write(
            root.0.join(".ramenv.vault.toml"),
            toml::to_string(&file).unwrap(),
        )
        .unwrap();
        assert!(VaultRegistry::new(&root.0, SIGNING_KEY).is_err());
    }

    #[test]
    fn vault_commit_fails_if_backing_file_was_removed() {
        let root = TempDir::new("removed-vault");
        write_vault(&root.0);
        let registry = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.vault.toml")).unwrap();
        assert!(registry.commit().is_err());
    }

    #[test]
    fn vault_commit_reports_an_unwritable_backing_path() {
        let root = TempDir::new("unwritable-vault");
        write_vault(&root.0);
        let registry = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.vault.toml")).unwrap();
        std::fs::create_dir(root.0.join(".ramenv.vault.toml")).unwrap();
        assert!(registry.commit().is_err());
    }

    #[test]
    fn workspace_registry_finds_parent_from_nested_directory() {
        let root = TempDir::new("workspace");
        let nested = root.0.join("services/api/src");
        std::fs::create_dir_all(&nested).unwrap();
        let workspace = WorkspaceFile::new("1".into(), "monorepo".into(), Provider::Local);
        std::fs::write(
            root.0.join(".ramenv.workspace.toml"),
            toml::to_string(&workspace).unwrap(),
        )
        .unwrap();
        let registry = WorkspaceRegistry::new(&nested).unwrap();
        assert_eq!(registry.get_workspace_root(), root.0);
    }

    #[test]
    fn workspace_registry_reports_incomplete_malformed_and_absent_workspaces() {
        let root = TempDir::new("incomplete-workspace");
        std::fs::write(root.0.join(".ramenv.keys"), "keys = {}").unwrap();
        assert!(WorkspaceRegistry::new(&root.0).is_err());

        std::fs::write(root.0.join(".ramenv.workspace.toml"), "bad = true").unwrap();
        assert!(WorkspaceRegistry::new(&root.0).is_err());

        std::fs::remove_file(root.0.join(".ramenv.keys")).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.workspace.toml")).unwrap();
        std::fs::create_dir(root.0.join(".git")).unwrap();
        assert!(WorkspaceRegistry::new(&root.0).is_err());
    }

    #[test]
    fn create_environment_rolls_back_persisted_key_when_vault_write_fails() {
        let root = TempDir::new("create-rollback");
        write_keys(&root.0);
        write_vault(&root.0);
        let vault_path = root.0.join(".ramenv.vault.toml");
        let original_vault = std::fs::read_to_string(&vault_path).unwrap();
        let mut keys = LocalEncryptionKeyService::new(&root.0).unwrap();
        let mut vault = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        std::fs::remove_file(&vault_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();

        assert!(crate::commands::create_env_command("staging", &mut keys, &mut vault).is_err());
        let persisted_keys = LocalEncryptionKeyService::new(&root.0).unwrap();
        assert!(persisted_keys.env_key("staging").is_err());
        assert!(vault.env_vault("staging").is_err());

        std::fs::remove_dir(&vault_path).unwrap();
        std::fs::write(&vault_path, original_vault).unwrap();
    }

    #[test]
    fn remove_environment_restores_persisted_key_when_vault_write_fails() {
        let root = TempDir::new("remove-rollback");
        write_keys(&root.0);
        write_vault(&root.0);
        let vault_path = root.0.join(".ramenv.vault.toml");
        let original_vault = std::fs::read_to_string(&vault_path).unwrap();
        let mut keys = LocalEncryptionKeyService::new(&root.0).unwrap();
        let mut vault = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        std::fs::remove_file(&vault_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();

        assert!(crate::commands::remove_env_command("development", &mut keys, &mut vault).is_err());
        let persisted_keys = LocalEncryptionKeyService::new(&root.0).unwrap();
        assert_eq!(persisted_keys.env_key("development").unwrap(), ENV_KEY);
        assert!(vault.env_vault("development").is_ok());

        std::fs::remove_dir(&vault_path).unwrap();
        std::fs::write(&vault_path, original_vault).unwrap();
    }

    #[test]
    fn rotate_restores_persisted_vault_when_key_write_fails() {
        let root = TempDir::new("rotate-rollback");
        write_keys(&root.0);
        write_vault(&root.0);
        let keys_path = root.0.join(".ramenv.keys");
        let original_keys = std::fs::read_to_string(&keys_path).unwrap();
        let mut keys = LocalEncryptionKeyService::new(&root.0).unwrap();
        let mut vault = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        std::fs::remove_file(&keys_path).unwrap();
        std::fs::create_dir(&keys_path).unwrap();

        assert!(crate::commands::rotate_command("development", &mut keys, &mut vault).is_err());
        std::fs::remove_dir(&keys_path).unwrap();
        std::fs::write(&keys_path, original_keys).unwrap();

        let reloaded = VaultRegistry::new(&root.0, SIGNING_KEY).unwrap();
        assert_eq!(
            reloaded.env_vault("development").unwrap()["API_KEY"],
            "value"
        );
        assert_eq!(keys.env_key("development").unwrap(), ENV_KEY);
    }
}
