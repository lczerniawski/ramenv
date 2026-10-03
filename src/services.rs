use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Ok, Result};
use azure_core::credentials::TokenCredential;
use azure_security_keyvault_secrets::models::{SecretClientGetSecretOptions, SetSecretParameters};
use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
use indexmap::IndexMap;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{crypto, models, validation::ValidationRule};

pub trait EncryptionKeyService {
    fn env_key(&self, environment: &str) -> Result<&str>;
    fn set_env_key(&mut self, environment: &str, key: String);
    fn store_new_env_key(&mut self, environment: &str);
    fn remove_env_key(&mut self, environment: &str);
    fn vault_signature_key(&self, vault: &str) -> Result<&str>;
    fn store_new_vault_signature_key(&mut self, vault: &str);
    async fn commit(&mut self, workspace_name: &str) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyId {
    Encryption(String),
    Signature(String),
}

pub enum Change {
    Upsert,
    Remove,
}

pub trait KeyStore {
    async fn load(&self) -> Result<models::KeysFile>;
    async fn create(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        provider_url: Option<&str>,
    ) -> Result<()>;
    async fn save(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        pending: &IndexMap<KeyId, Change>,
    ) -> Result<()>;
}

pub struct KeyService<S: KeyStore> {
    store: S,
    encryption_keys: IndexMap<String, String>,
    signature_keys: IndexMap<String, String>,
    pending: IndexMap<KeyId, Change>,
}

impl<S: KeyStore> KeyService<S> {
    pub fn from_empty(store: S) -> Self {
        Self {
            store,
            encryption_keys: IndexMap::new(),
            signature_keys: IndexMap::new(),
            pending: IndexMap::new(),
        }
    }

    pub async fn from_store(store: S) -> Result<Self> {
        let keys = store.load().await?;
        Ok(Self {
            store,
            encryption_keys: keys.encryption_keys,
            signature_keys: keys.signature_keys,
            pending: IndexMap::new(),
        })
    }

    fn keys_file(&self) -> models::KeysFile {
        models::KeysFile {
            encryption_keys: self.encryption_keys.clone(),
            signature_keys: self.signature_keys.clone(),
        }
    }

    pub async fn create(&mut self, workspace_name: &str, provider_url: Option<&str>) -> Result<()> {
        self.store
            .create(&self.keys_file(), workspace_name, provider_url)
            .await
    }
}

impl<S: KeyStore> EncryptionKeyService for KeyService<S> {
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
        self.pending
            .insert(KeyId::Encryption(environment.to_string()), Change::Upsert);
    }

    fn store_new_env_key(&mut self, environment: &str) {
        self.encryption_keys
            .insert(environment.to_string(), crypto::generate_master_key_hex());
        self.pending
            .insert(KeyId::Encryption(environment.to_string()), Change::Upsert);
    }

    fn remove_env_key(&mut self, environment: &str) {
        self.encryption_keys.shift_remove(environment);
        self.pending
            .insert(KeyId::Encryption(environment.to_string()), Change::Remove);
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
        self.pending
            .insert(KeyId::Signature(vault.to_string()), Change::Upsert);
    }

    async fn commit(&mut self, workspace_name: &str) -> anyhow::Result<()> {
        self.store
            .save(&self.keys_file(), workspace_name, &self.pending)
            .await
    }
}

pub struct LocalKeyStore {
    path: PathBuf,
}

impl LocalKeyStore {
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            path: workspace_root.join(".ramenv.keys"),
        }
    }
}

fn write_file(path: &Path, content: &str, create: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    if create {
        options.create_new(true);
    } else {
        options.truncate(true);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))
}

impl KeyStore for LocalKeyStore {
    async fn load(&self) -> Result<models::KeysFile> {
        if !self.path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }
        let content = std::fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read keys file {}", self.path.display()))?;
        toml::from_str(&content).context("failed to parse keys file")
    }

    async fn create(
        &mut self,
        keys: &models::KeysFile,
        _workspace_name: &str,
        _provider_url: Option<&str>,
    ) -> Result<()> {
        write_file(
            &self.path,
            &toml::to_string(keys).context("failed to serialize keys")?,
            true,
        )
    }

    async fn save(
        &mut self,
        keys: &models::KeysFile,
        _workspace_name: &str,
        _pending: &IndexMap<KeyId, Change>,
    ) -> Result<()> {
        write_file(
            &self.path,
            &toml::to_string(keys).context("failed to serialize keys")?,
            false,
        )
    }
}

pub struct AzureKeyStore {
    path: PathBuf,
    credential: Arc<dyn TokenCredential>,
}

impl AzureKeyStore {
    pub fn new(workspace_root: &Path, credential: Arc<dyn TokenCredential>) -> Self {
        Self {
            path: workspace_root.join(".ramenv.keyrefs.toml"),
            credential,
        }
    }

    async fn read_key(&self, secret_uri: &str) -> Result<String> {
        let url = Url::parse(secret_uri)?;
        if url.scheme() != "https" {
            anyhow::bail!("Key Vault Secret reference must use HTTPS");
        }

        let parts = url
            .path_segments()
            .context("invalid key vault secret reference")?
            .collect::<Vec<_>>();

        let ["secrets", name, version] = parts.as_slice() else {
            anyhow::bail!("invalid key vault secret reference");
        };

        let vault_url = format!("{}/", url.origin().ascii_serialization());
        let client = SecretClient::new(&vault_url, self.credential.clone(), None)?;

        let options = SecretClientGetSecretOptions {
            secret_version: Some((*version).to_owned()),
            ..Default::default()
        };

        let secret = client.get_secret(name, Some(options)).await?.into_model()?;

        secret.value.context("Key Vault returned no secret value")
    }

    fn read_references(&self) -> Result<models::KeysReferenceFile> {
        let content = std::fs::read_to_string(&self.path)
            .with_context(|| format!("failed to read keys file {}", self.path.display()))?;
        Ok(toml::from_str(&content)?)
    }

    fn write_references(&self, references: &models::KeysReferenceFile, create: bool) -> Result<()> {
        write_file(
            &self.path,
            &toml::to_string(references).context("failed to serialize key references")?,
            create,
        )
    }

    fn secret_name(workspace_name: &str, kind: &str, key: &str) -> String {
        let name = format!("ramenv-{workspace_name}-{kind}-{key}");
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-';
        if name.len() <= 127 && name.bytes().all(allowed) {
            return name;
        }

        // Keep a readable ASCII prefix plus a digest of the original name so
        // replacing path separators or truncating long names does not merge keys.
        // 62 prefix bytes + one hyphen + 64 SHA-256 hex digits = 127 bytes.
        let prefix: String = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' {
                    ch
                } else {
                    '-'
                }
            })
            .take(62)
            .collect();
        let digest: String = Sha256::digest(name.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("{prefix}-{digest}")
    }

    fn encryption_key_name_format(&self, key: &str, workspace_name: &str) -> String {
        Self::secret_name(workspace_name, "encryption", key)
    }

    fn signature_key_name_format(&self, key: &str, workspace_name: &str) -> String {
        Self::secret_name(workspace_name, "signature", key)
    }
}

impl KeyStore for AzureKeyStore {
    async fn load(&self) -> Result<models::KeysFile> {
        if !self.path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }
        let reference_keys_file = self.read_references()?;

        let mut keys = models::KeysFile {
            encryption_keys: IndexMap::new(),
            signature_keys: IndexMap::new(),
        };

        for (key, value) in reference_keys_file.encryption_keys.iter() {
            let secret = self.read_key(value).await?;
            keys.encryption_keys.insert(key.clone(), secret);
        }
        for (key, value) in reference_keys_file.signature_keys.iter() {
            let secret = self.read_key(value).await?;
            keys.signature_keys.insert(key.clone(), secret);
        }

        Ok(keys)
    }

    async fn create(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        provider_url: Option<&str>,
    ) -> Result<()> {
        let provider_url = provider_url.expect("provider_url is required when creating keys");
        let client = SecretClient::new(provider_url, self.credential.clone(), None)?;
        let mut reference_keys_file = models::KeysReferenceFile::new(provider_url.to_string());

        for (key, value) in keys.encryption_keys.iter() {
            let secret_set_parameter = SetSecretParameters {
                value: Some(value.into()),
                ..Default::default()
            };
            let secret = client
                .set_secret(
                    &self.encryption_key_name_format(key, workspace_name),
                    secret_set_parameter.try_into()?,
                    None,
                )
                .await?
                .into_model()?;

            reference_keys_file
                .encryption_keys
                .insert(key.clone(), secret.resource_id()?.source_id);
        }

        for (key, value) in keys.signature_keys.iter() {
            let secret_set_parameter = SetSecretParameters {
                value: Some(value.into()),
                ..Default::default()
            };
            let secret = client
                .set_secret(
                    &self.signature_key_name_format(key, workspace_name),
                    secret_set_parameter.try_into()?,
                    None,
                )
                .await?
                .into_model()?;

            reference_keys_file
                .signature_keys
                .insert(key.clone(), secret.resource_id()?.source_id);
        }

        self.write_references(&reference_keys_file, true)
    }

    async fn save(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        pending: &IndexMap<KeyId, Change>,
    ) -> Result<()> {
        let mut reference_keys_file = self.read_references()?;
        let client = SecretClient::new(
            &reference_keys_file.provider_url,
            self.credential.clone(),
            None,
        )?;

        for (key_id, change) in pending {
            match change {
                Change::Upsert => match key_id {
                    KeyId::Encryption(key) => {
                        let encryption_key = keys
                            .encryption_keys
                            .get(key)
                            .cloned()
                            .expect("encryption key not found");
                        let secret_set_parameter = SetSecretParameters {
                            value: Some(encryption_key),
                            ..Default::default()
                        };
                        let secret = client
                            .set_secret(
                                &self.encryption_key_name_format(key, workspace_name),
                                secret_set_parameter.try_into()?,
                                None,
                            )
                            .await?
                            .into_model()?;

                        reference_keys_file
                            .encryption_keys
                            .insert(key.clone(), secret.resource_id()?.source_id);
                    }
                    KeyId::Signature(key) => {
                        let signature_key = keys
                            .signature_keys
                            .get(key)
                            .cloned()
                            .expect("encryption key not found");
                        let secret_set_parameter = SetSecretParameters {
                            value: Some(signature_key),
                            ..Default::default()
                        };
                        let secret = client
                            .set_secret(
                                &self.signature_key_name_format(key, workspace_name),
                                secret_set_parameter.try_into()?,
                                None,
                            )
                            .await?
                            .into_model()?;

                        reference_keys_file
                            .signature_keys
                            .insert(key.clone(), secret.resource_id()?.source_id);
                    }
                },
                Change::Remove => match key_id {
                    KeyId::Encryption(key) => {
                        client
                            .delete_secret(
                                &self.encryption_key_name_format(key, workspace_name),
                                None,
                            )
                            .await?;
                        reference_keys_file.encryption_keys.shift_remove(key);
                    }
                    KeyId::Signature(key) => {
                        client
                            .delete_secret(
                                &self.signature_key_name_format(key, workspace_name),
                                None,
                            )
                            .await?;
                        reference_keys_file.signature_keys.shift_remove(key);
                    }
                },
            }
        }

        self.write_references(&reference_keys_file, false)
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
    pub fn empty(current_working_path: &Path, vault_signing_key: &str) -> Self {
        Self {
            vault_path: current_working_path.join(".ramenv.vault.toml"),
            vault_signing_key: vault_signing_key.to_string(),
            validation: IndexMap::new(),
            environments: IndexMap::new(),
        }
    }

    pub fn load(current_working_path: &Path, vault_signing_key: &str) -> Result<Self> {
        let vault_file_path = current_working_path.join(".ramenv.vault.toml");
        if !vault_file_path.exists() {
            anyhow::bail!("vault file does not exist, please run `ramenv init` first");
        }
        let content = std::fs::read_to_string(&vault_file_path)
            .with_context(|| format!("failed to read vault file {}", vault_file_path.display()))?;
        let vault_file: models::VaultFile =
            toml::from_str(&content).context("failed to parse vault file")?;
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
    }

    fn serialize(&self) -> Result<String> {
        let canonical_vault = models::CanonicalVault {
            environments: self.environments.clone(),
        };
        let canonical_vault_str = serde_json::to_string(&canonical_vault)
            .context("failed to serialize vault for signing")?;
        let metadata = models::VaultMetadata {
            signature: crypto::generate_signature(&canonical_vault_str, &self.vault_signing_key)?,
            signature_version: "1".to_string(),
            signed_at: chrono::Utc::now().to_rfc3339(),
        };
        toml::to_string(&models::VaultFile {
            validation: self.validation.clone(),
            environments: self.environments.clone(),
            metadata,
        })
        .context("failed to serialize vault file to TOML")
    }

    pub fn create(&self) -> Result<()> {
        write_file(&self.vault_path, &self.serialize()?, true)
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
        write_file(&self.vault_path, &self.serialize()?, false)
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
    fn get_workspace_name(&self) -> &str;
    fn get_provider(&self) -> models::Provider;
}

pub struct WorkspaceRegistry {
    workspace_root: PathBuf,
    workspace_name: String,
    #[allow(dead_code)]
    schema_version: String,
    provider: models::Provider,
}

impl WorkspaceRegistry {
    pub fn create(workspace_root: &Path, workspace: models::WorkspaceFile) -> Result<Self> {
        let content = toml::to_string(&workspace).context("failed to serialize workspace file")?;
        write_file(
            &workspace_root.join(".ramenv.workspace.toml"),
            &content,
            true,
        )?;
        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            workspace_name: workspace.workspace_name,
            schema_version: workspace.schema_version,
            provider: workspace.ingredient,
        })
    }

    pub fn load(current_working_path: &Path) -> Result<Self> {
        let workspace_root = Self::find_workspace_root(current_working_path)?;
        let workspace = Self::load_workspace(&workspace_root)?;

        Ok(Self {
            workspace_root,
            workspace_name: workspace.workspace_name,
            schema_version: workspace.schema_version,
            provider: workspace.ingredient,
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

    fn get_workspace_name(&self) -> &str {
        &self.workspace_name
    }

    fn get_provider(&self) -> models::Provider {
        self.provider.clone()
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

    fn azure_store(root: &Path) -> AzureKeyStore {
        AzureKeyStore::new(
            root,
            azure_identity::DeveloperToolsCredential::new(None).unwrap(),
        )
    }

    fn assert_azure_secret_name(name: &str) {
        assert!((1..=127).contains(&name.len()), "invalid length: {name}");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "invalid characters: {name}"
        );
    }

    #[test]
    fn azure_secret_names_preserve_existing_valid_names() {
        let store = azure_store(Path::new("."));
        assert_eq!(
            store.encryption_key_name_format("development", "my-project"),
            "ramenv-my-project-encryption-development"
        );
        assert_eq!(
            store.signature_key_name_format("api", "my-project"),
            "ramenv-my-project-signature-api"
        );
    }

    #[test]
    fn azure_secret_names_support_underscores_paths_and_unicode() {
        let store = azure_store(Path::new("."));
        for workspace in ["azure_test", "my project", "项目"] {
            for key in ["development", "preview_env", "/", "services/api", "服务/api"] {
                assert_azure_secret_name(&store.encryption_key_name_format(key, workspace));
                assert_azure_secret_name(&store.signature_key_name_format(key, workspace));
            }
        }
    }

    #[test]
    fn azure_secret_names_are_stable_and_distinguish_normalized_inputs() {
        let store = azure_store(Path::new("."));
        let name = store.encryption_key_name_format("development", "azure_test");
        assert_eq!(
            name,
            store.encryption_key_name_format("development", "azure_test")
        );
        assert_ne!(
            name,
            store.encryption_key_name_format("development", "azure-test")
        );
        assert_ne!(
            store.signature_key_name_format("services/api", "test"),
            store.signature_key_name_format("services-api", "test")
        );
        assert_ne!(
            store.signature_key_name_format("services/api", "test"),
            store.signature_key_name_format("services_api", "test")
        );
    }

    #[test]
    fn azure_secret_names_enforce_length_without_truncation_collisions() {
        let store = azure_store(Path::new("."));
        let workspace = "a".repeat(200);
        let key = "b".repeat(200);
        let name = store.encryption_key_name_format(&key, &workspace);
        assert_azure_secret_name(&name);
        assert_azure_secret_name(&store.signature_key_name_format(&key, &workspace));
        assert_ne!(
            name,
            store.encryption_key_name_format(&format!("{key}c"), &workspace)
        );
        let boundary_workspace = "a".repeat(107);
        let boundary = store.encryption_key_name_format("x", &boundary_workspace);
        assert_eq!(boundary.len(), 127);
        assert_eq!(boundary, format!("ramenv-{boundary_workspace}-encryption-x"));
        assert_azure_secret_name(
            &store.encryption_key_name_format("xx", &boundary_workspace),
        );
    }

    #[test]
    fn azure_references_create_then_update_preserves_urls_and_logical_names() {
        let root = TempDir::new("azure-references");
        let store = azure_store(&root.0);
        let provider_url = "https://test.vault.azure.net/";
        let encryption_uri = "https://test.vault.azure.net/secrets/env-key/version1";
        let signature_uri = "https://test.vault.azure.net/secrets/signing-key/version2";
        let mut references = models::KeysReferenceFile::new(provider_url.into());
        references
            .encryption_keys
            .insert("preview_env".into(), encryption_uri.into());
        store.write_references(&references, true).unwrap();
        assert!(store.write_references(&references, true).is_err());

        references
            .signature_keys
            .insert("/".into(), signature_uri.into());
        store.write_references(&references, false).unwrap();
        let reloaded = store.read_references().unwrap();
        assert_eq!(reloaded.provider_url, provider_url);
        assert_eq!(reloaded.encryption_keys["preview_env"], encryption_uri);
        assert_eq!(reloaded.signature_keys["/"], signature_uri);

        references.encryption_keys.shift_remove("preview_env");
        store.write_references(&references, false).unwrap();
        let reloaded = store.read_references().unwrap();
        assert!(reloaded.encryption_keys.is_empty());
        assert_eq!(reloaded.signature_keys["/"], signature_uri);
    }

    fn write_keys(root: &Path) {
        let mut file = KeysFile::default();
        file.encryption_keys
            .insert("development".into(), ENV_KEY.into());
        file.signature_keys.insert("/".into(), SIGNING_KEY.into());
        std::fs::write(root.join(".ramenv.keys"), toml::to_string(&file).unwrap()).unwrap();
    }

    fn write_workspace(root: &Path) {
        let workspace = WorkspaceFile::new("1".into(), "test".into(), Provider::Local);
        WorkspaceRegistry::create(root, workspace).unwrap();
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

    #[tokio::test]
    async fn key_service_loads_mutates_and_persists_keys() {
        let root = TempDir::new("keys");
        write_keys(&root.0);
        let mut service = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        assert_eq!(service.env_key("development").unwrap(), ENV_KEY);
        assert_eq!(service.vault_signature_key("/").unwrap(), SIGNING_KEY);

        service.store_new_env_key("production");
        service.store_new_vault_signature_key("services/api");
        assert_eq!(service.env_key("production").unwrap().len(), 64);
        service.remove_env_key("development");
        service.commit("test").await.unwrap();

        let reloaded = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        assert!(reloaded.env_key("development").is_err());
        assert_eq!(reloaded.env_key("production").unwrap().len(), 64);
        assert_eq!(
            reloaded.vault_signature_key("services/api").unwrap().len(),
            128
        );
    }

    #[tokio::test]
    async fn empty_services_create_loadable_files_without_overwriting_them() {
        let root = TempDir::new("create-services");
        let mut keys = KeyService::from_empty(LocalKeyStore::new(&root.0));
        keys.store_new_env_key("development");
        keys.store_new_vault_signature_key("/");
        keys.create("test", None).await.unwrap();
        let key_content = std::fs::read_to_string(root.0.join(".ramenv.keys")).unwrap();
        assert!(keys.create("test", None).await.is_err());
        assert_eq!(
            std::fs::read_to_string(root.0.join(".ramenv.keys")).unwrap(),
            key_content
        );

        let signing_key = keys.vault_signature_key("/").unwrap();
        let mut vault = VaultRegistry::empty(&root.0, signing_key);
        vault.set_env_vault("development", IndexMap::new());
        vault.create().unwrap();
        let vault_content = std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap();
        assert!(vault.create().is_err());
        assert_eq!(
            std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap(),
            vault_content
        );
        assert!(VaultRegistry::load(&root.0, signing_key).is_ok());

        let workspace = WorkspaceFile::new("1".into(), "example".into(), Provider::Local);
        WorkspaceRegistry::create(&root.0, workspace).unwrap();
        assert!(WorkspaceRegistry::load(&root.0).is_ok());
        let second = WorkspaceFile::new("2".into(), "other".into(), Provider::Local);
        assert!(WorkspaceRegistry::create(&root.0, second).is_err());
    }

    #[tokio::test]
    async fn key_service_reports_missing_and_malformed_files() {
        let root = TempDir::new("bad-keys");
        assert!(
            KeyService::from_store(LocalKeyStore::new(&root.0))
                .await
                .is_err()
        );

        std::fs::create_dir(root.0.join(".ramenv.keys")).unwrap();
        assert!(
            KeyService::from_store(LocalKeyStore::new(&root.0))
                .await
                .is_err()
        );
        std::fs::remove_dir(root.0.join(".ramenv.keys")).unwrap();
        std::fs::write(root.0.join(".ramenv.keys"), "not = [valid").unwrap();
        assert!(
            KeyService::from_store(LocalKeyStore::new(&root.0))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn key_service_commit_fails_if_backing_file_was_removed() {
        let root = TempDir::new("removed-keys");
        write_keys(&root.0);
        let mut service = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        std::fs::remove_file(root.0.join(".ramenv.keys")).unwrap();
        assert!(service.commit("test").await.is_err());
    }

    #[tokio::test]
    async fn key_service_commit_reports_an_unwritable_backing_path() {
        let root = TempDir::new("unwritable-keys");
        write_keys(&root.0);
        let mut service = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        std::fs::remove_file(root.0.join(".ramenv.keys")).unwrap();
        std::fs::create_dir(root.0.join(".ramenv.keys")).unwrap();
        assert!(service.commit("test").await.is_err());
    }

    #[tokio::test]
    async fn vault_registry_verifies_and_persists_all_mutations() {
        let root = TempDir::new("vault");
        write_vault(&root.0);
        let mut registry = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
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

        let reloaded = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
        let vault = reloaded.env_vault("development").unwrap();
        assert_eq!(vault["OTHER"], "second");
        assert!(reloaded.validation_rules().contains_key("API_KEY"));
    }

    #[test]
    fn vault_registry_rejects_missing_malformed_tampered_and_wrongly_signed_files() {
        let root = TempDir::new("bad-vault");
        assert!(VaultRegistry::load(&root.0, SIGNING_KEY).is_err());
        std::fs::write(root.0.join(".ramenv.vault.toml"), "bad = [toml").unwrap();
        assert!(VaultRegistry::load(&root.0, SIGNING_KEY).is_err());

        write_vault(&root.0);
        assert!(VaultRegistry::load(&root.0, ENV_KEY).is_err());
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
        assert!(VaultRegistry::load(&root.0, SIGNING_KEY).is_err());
    }

    #[test]
    fn vault_commit_fails_if_backing_file_was_removed() {
        let root = TempDir::new("removed-vault");
        write_vault(&root.0);
        let registry = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.vault.toml")).unwrap();
        assert!(registry.commit().is_err());
    }

    #[test]
    fn vault_commit_reports_an_unwritable_backing_path() {
        let root = TempDir::new("unwritable-vault");
        write_vault(&root.0);
        let registry = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
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
        let registry = WorkspaceRegistry::load(&nested).unwrap();
        assert_eq!(registry.get_workspace_root(), root.0);
    }

    #[test]
    fn workspace_registry_reports_incomplete_malformed_and_absent_workspaces() {
        let root = TempDir::new("incomplete-workspace");
        std::fs::write(root.0.join(".ramenv.keys"), "keys = {}").unwrap();
        assert!(WorkspaceRegistry::load(&root.0).is_err());

        std::fs::write(root.0.join(".ramenv.workspace.toml"), "bad = true").unwrap();
        assert!(WorkspaceRegistry::load(&root.0).is_err());

        std::fs::remove_file(root.0.join(".ramenv.keys")).unwrap();
        std::fs::remove_file(root.0.join(".ramenv.workspace.toml")).unwrap();
        std::fs::create_dir(root.0.join(".git")).unwrap();
        assert!(WorkspaceRegistry::load(&root.0).is_err());
    }

    #[tokio::test]
    async fn create_environment_rolls_back_persisted_key_when_vault_write_fails() {
        let root = TempDir::new("create-rollback");
        write_workspace(&root.0);
        write_keys(&root.0);
        write_vault(&root.0);
        let vault_path = root.0.join(".ramenv.vault.toml");
        let original_vault = std::fs::read_to_string(&vault_path).unwrap();
        let mut keys = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        let mut vault = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
        let workspace = WorkspaceRegistry::load(&root.0).unwrap();
        std::fs::remove_file(&vault_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();

        assert!(
            crate::commands::create_env_command("staging", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        let persisted_keys = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        assert!(persisted_keys.env_key("staging").is_err());
        assert!(vault.env_vault("staging").is_err());

        std::fs::remove_dir(&vault_path).unwrap();
        std::fs::write(&vault_path, original_vault).unwrap();
    }

    #[tokio::test]
    async fn remove_environment_restores_persisted_key_when_vault_write_fails() {
        let root = TempDir::new("remove-rollback");
        write_workspace(&root.0);
        write_keys(&root.0);
        write_vault(&root.0);
        let vault_path = root.0.join(".ramenv.vault.toml");
        let original_vault = std::fs::read_to_string(&vault_path).unwrap();
        let mut keys = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        let mut vault = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
        let workspace = WorkspaceRegistry::load(&root.0).unwrap();
        std::fs::remove_file(&vault_path).unwrap();
        std::fs::create_dir(&vault_path).unwrap();

        assert!(
            crate::commands::remove_env_command("development", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        let persisted_keys = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        assert_eq!(persisted_keys.env_key("development").unwrap(), ENV_KEY);
        assert!(vault.env_vault("development").is_ok());

        std::fs::remove_dir(&vault_path).unwrap();
        std::fs::write(&vault_path, original_vault).unwrap();
    }

    #[tokio::test]
    async fn rotate_restores_persisted_vault_when_key_write_fails() {
        let root = TempDir::new("rotate-rollback");
        write_workspace(&root.0);
        write_keys(&root.0);
        write_vault(&root.0);
        let keys_path = root.0.join(".ramenv.keys");
        let original_keys = std::fs::read_to_string(&keys_path).unwrap();
        let mut keys = KeyService::from_store(LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        let mut vault = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
        let workspace = WorkspaceRegistry::load(&root.0).unwrap();

        std::fs::remove_file(&keys_path).unwrap();
        std::fs::create_dir(&keys_path).unwrap();

        assert!(
            crate::commands::rotate_command("development", &mut keys, &mut vault, &workspace)
                .await
                .is_err()
        );
        std::fs::remove_dir(&keys_path).unwrap();
        std::fs::write(&keys_path, original_keys).unwrap();

        let reloaded = VaultRegistry::load(&root.0, SIGNING_KEY).unwrap();
        assert_eq!(
            reloaded.env_vault("development").unwrap()["API_KEY"],
            "value"
        );
        assert_eq!(keys.env_key("development").unwrap(), ENV_KEY);
    }
}
