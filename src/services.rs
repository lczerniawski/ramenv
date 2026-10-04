use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use aws_config::{BehaviorVersion, SdkConfig};
use aws_sdk_secretsmanager::{Client as AwsSecretClient, config::Region};
use azure_core::credentials::TokenCredential;
use azure_security_keyvault_secrets::models::{SecretClientGetSecretOptions, SetSecretParameters};
use azure_security_keyvault_secrets::{ResourceExt, SecretClient};
use google_cloud_gax::error::rpc::Code;
use google_cloud_secretmanager_v1::{
    client::SecretManagerService,
    model::{Replication, Secret, SecretPayload, replication::Automatic},
};
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
        provider_location: Option<&str>,
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

    pub fn vault_names(&self) -> impl Iterator<Item = &str> {
        self.signature_keys.keys().map(String::as_str)
    }

    fn keys_file(&self) -> models::KeysFile {
        models::KeysFile {
            encryption_keys: self.encryption_keys.clone(),
            signature_keys: self.signature_keys.clone(),
        }
    }

    pub async fn create(
        &mut self,
        workspace_name: &str,
        provider_location: Option<&str>,
    ) -> Result<()> {
        self.store
            .create(&self.keys_file(), workspace_name, provider_location)
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

// A common naming format valid for all three cloud secret stores.
fn secret_name(workspace_name: &str, kind: &str, key: &str) -> String {
    let name = format!("ramenv-{workspace_name}-{kind}-{key}");

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

fn read_references(path: &Path) -> Result<models::KeysReferenceFile> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read keys file {}", path.display()))?;
    toml::from_str(&content).context("failed to parse key references")
}

fn write_references(
    path: &Path,
    references: &models::KeysReferenceFile,
    create: bool,
) -> Result<()> {
    write_file(
        path,
        &toml::to_string(references).context("failed to serialize key references")?,
        create,
    )
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
        _provider_location: Option<&str>,
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
}

impl KeyStore for AzureKeyStore {
    async fn load(&self) -> Result<models::KeysFile> {
        if !self.path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }
        let reference_keys_file = read_references(&self.path)?;

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
        provider_location: Option<&str>,
    ) -> Result<()> {
        let provider_location =
            provider_location.expect("provider_location is required when creating keys");
        let client = SecretClient::new(provider_location, self.credential.clone(), None)?;
        let mut reference_keys_file = models::KeysReferenceFile::new(provider_location.to_string());

        for (key, value) in keys.encryption_keys.iter() {
            let secret_set_parameter = SetSecretParameters {
                value: Some(value.into()),
                ..Default::default()
            };
            let secret = client
                .set_secret(
                    &secret_name(workspace_name, "encryption", key),
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
                    &secret_name(workspace_name, "signature", key),
                    secret_set_parameter.try_into()?,
                    None,
                )
                .await?
                .into_model()?;

            reference_keys_file
                .signature_keys
                .insert(key.clone(), secret.resource_id()?.source_id);
        }

        write_references(&self.path, &reference_keys_file, true)
    }

    async fn save(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        pending: &IndexMap<KeyId, Change>,
    ) -> Result<()> {
        let mut references = read_references(&self.path)?;
        let client =
            SecretClient::new(&references.provider_location, self.credential.clone(), None)?;

        for (id, change) in pending {
            let (key, kind, values, refs) = match id {
                KeyId::Encryption(key) => (
                    key,
                    "encryption",
                    &keys.encryption_keys,
                    &mut references.encryption_keys,
                ),
                KeyId::Signature(key) => (
                    key,
                    "signature",
                    &keys.signature_keys,
                    &mut references.signature_keys,
                ),
            };
            match change {
                Change::Upsert => {
                    let value = values
                        .get(key)
                        .with_context(|| format!("{kind} key not found for {key}"))?;
                    let parameters = SetSecretParameters {
                        value: Some(value.clone()),
                        ..Default::default()
                    };
                    let secret = client
                        .set_secret(
                            &secret_name(workspace_name, kind, key),
                            parameters.try_into()?,
                            None,
                        )
                        .await?
                        .into_model()?;
                    refs.insert(key.clone(), secret.resource_id()?.source_id);
                }
                Change::Remove => {
                    client
                        .delete_secret(&secret_name(workspace_name, kind, key), None)
                        .await?;
                    refs.shift_remove(key);
                }
            }
        }

        write_references(&self.path, &references, false)
    }
}

pub struct AwsKeyStore {
    path: PathBuf,
    config: SdkConfig,
}

impl AwsKeyStore {
    pub async fn new(workspace_root: &Path) -> Self {
        // Let the SDK's default credential chain select credentials automatically.
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        Self {
            path: workspace_root.join(".ramenv.keyrefs.toml"),
            config,
        }
    }

    fn region(provider_location: &str) -> Result<&str> {
        let region = provider_location.trim();
        if region.is_empty()
            || !region.contains('-')
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            anyhow::bail!("AWS provider location must be a region such as us-east-1");
        }
        Ok(region)
    }

    fn client(&self, region: &str) -> AwsSecretClient {
        AwsSecretClient::from_conf(
            aws_sdk_secretsmanager::config::Builder::from(&self.config)
                .region(Region::new(region.to_owned()))
                .build(),
        )
    }

    fn secret_reference<'a>(reference: &'a str, region: &str) -> Result<(&'a str, &'a str)> {
        let (arn, version) = reference
            .split_once('#')
            .context("invalid AWS secret reference: expected ARN#VersionId")?;
        let parts: Vec<_> = arn.splitn(7, ':').collect();
        if !matches!(parts.as_slice(), ["arn", partition, "secretsmanager", arn_region, account, "secret", name]
            if !partition.is_empty() && *arn_region == region && account.len() == 12
                && account.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty())
            || !(32..=64).contains(&version.len())
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            anyhow::bail!("invalid AWS secret reference or region mismatch");
        }
        Ok((arn, version))
    }

    fn version_reference(arn: Option<&str>, version: Option<&str>, region: &str) -> Result<String> {
        let reference = format!(
            "{}#{}",
            arn.context("AWS returned no secret ARN")?,
            version.context("AWS returned no secret version")?
        );
        Self::secret_reference(&reference, region)?;
        Ok(reference)
    }

    async fn read_key(&self, reference: &str, region: &str) -> Result<String> {
        let (arn, version) = Self::secret_reference(reference, region)?;
        let secret = self
            .client(region)
            .get_secret_value()
            .secret_id(arn)
            .version_id(version)
            .send()
            .await
            .context("failed to read AWS Secrets Manager secret")?;
        secret
            .secret_string
            .context("AWS returned no secret string")
    }

    async fn write_key(&self, region: &str, name: &str, value: &str) -> Result<String> {
        let client = self.client(region);
        match client
            .create_secret()
            .name(name)
            .secret_string(value)
            .send()
            .await
        {
            Ok(secret) => Self::version_reference(secret.arn(), secret.version_id(), region),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|e| e.is_resource_exists_exception()) =>
            {
                let secret = client
                    .put_secret_value()
                    .secret_id(name)
                    .secret_string(value)
                    .send()
                    .await
                    .context("failed to update AWS Secrets Manager secret")?;
                Self::version_reference(secret.arn(), secret.version_id(), region)
            }
            Err(error) => Err(error).context("failed to create AWS Secrets Manager secret"),
        }
    }

    async fn delete_key(&self, reference: &str, region: &str) -> Result<()> {
        let (arn, _) = Self::secret_reference(reference, region)?;
        // Keep AWS's default recovery window instead of force-deleting keys.
        match self
            .client(region)
            .delete_secret()
            .secret_id(arn)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|e| e.is_resource_not_found_exception()) =>
            {
                Ok(())
            }
            Err(error) => Err(error).context("failed to delete AWS Secrets Manager secret"),
        }
    }
}

impl KeyStore for AwsKeyStore {
    async fn load(&self) -> Result<models::KeysFile> {
        if !self.path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }
        let references = read_references(&self.path)?;
        let region = Self::region(&references.provider_location)?;
        let mut keys = models::KeysFile::default();
        for (key, reference) in &references.encryption_keys {
            keys.encryption_keys
                .insert(key.clone(), self.read_key(reference, region).await?);
        }
        for (key, reference) in &references.signature_keys {
            keys.signature_keys
                .insert(key.clone(), self.read_key(reference, region).await?);
        }
        Ok(keys)
    }

    async fn create(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        provider_location: Option<&str>,
    ) -> Result<()> {
        if self.path.exists() {
            anyhow::bail!("key references file already exists");
        }
        let region =
            Self::region(provider_location.context("AWS region is required when creating keys")?)?;
        let mut references = models::KeysReferenceFile::new(region.to_string());
        for (key, value) in &keys.encryption_keys {
            let reference = self
                .write_key(
                    region,
                    &secret_name(workspace_name, "encryption", key),
                    value,
                )
                .await?;
            references.encryption_keys.insert(key.clone(), reference);
        }
        for (key, value) in &keys.signature_keys {
            let reference = self
                .write_key(
                    region,
                    &secret_name(workspace_name, "signature", key),
                    value,
                )
                .await?;
            references.signature_keys.insert(key.clone(), reference);
        }
        write_references(&self.path, &references, true)
    }

    async fn save(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        pending: &IndexMap<KeyId, Change>,
    ) -> Result<()> {
        let mut references = read_references(&self.path)?;
        let region = Self::region(&references.provider_location)?.to_string();
        for (id, change) in pending {
            let (key, kind, values, refs) = match id {
                KeyId::Encryption(key) => (
                    key,
                    "encryption",
                    &keys.encryption_keys,
                    &mut references.encryption_keys,
                ),
                KeyId::Signature(key) => (
                    key,
                    "signature",
                    &keys.signature_keys,
                    &mut references.signature_keys,
                ),
            };
            match change {
                Change::Upsert => {
                    let value = values
                        .get(key)
                        .with_context(|| format!("{kind} key not found for {key}"))?;
                    let reference = self
                        .write_key(&region, &secret_name(workspace_name, kind, key), value)
                        .await?;
                    refs.insert(key.clone(), reference);
                }
                Change::Remove => {
                    if let Some(reference) = refs.get(key) {
                        self.delete_key(reference, &region).await?;
                        refs.shift_remove(key);
                    }
                }
            }
        }
        write_references(&self.path, &references, false)
    }
}

pub struct GoogleKeyStore {
    path: PathBuf,
    client: SecretManagerService,
}

impl GoogleKeyStore {
    pub async fn new(workspace_root: &Path) -> Result<Self> {
        // The default builder uses Google's Application Default Credentials.
        let client = SecretManagerService::builder()
            .build()
            .await
            .context("failed to configure Google Secret Manager client")?;
        Ok(Self {
            path: workspace_root.join(".ramenv.keyrefs.toml"),
            client,
        })
    }

    fn project(provider_location: &str) -> Result<String> {
        let project = provider_location
            .trim()
            .strip_prefix("projects/")
            .unwrap_or(provider_location.trim());
        if project.is_empty()
            || !project
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            anyhow::bail!("Google provider location must be a project ID or projects/<project-id>");
        }
        Ok(format!("projects/{project}"))
    }

    fn secret_reference<'a>(reference: &'a str, project: &str) -> Result<&'a str> {
        let (secret, version) = reference
            .rsplit_once("/versions/")
            .context("invalid Google secret reference: expected a versioned resource name")?;
        let prefix = format!("{project}/secrets/");
        let name = secret
            .strip_prefix(&prefix)
            .context("Google secret reference project mismatch")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !version.bytes().all(|b| b.is_ascii_digit())
            || !version.parse::<u64>().is_ok_and(|v| v > 0)
        {
            anyhow::bail!("invalid Google secret reference");
        }
        Ok(secret)
    }

    async fn read_key(&self, reference: &str, project: &str) -> Result<String> {
        Self::secret_reference(reference, project)?;
        let secret = self
            .client
            .access_secret_version()
            .set_name(reference)
            .send()
            .await
            .context("failed to read Google Secret Manager secret")?;
        let payload = secret
            .payload
            .context("Google returned no secret payload")?;
        String::from_utf8(payload.data.to_vec()).context("Google secret value is not UTF-8")
    }

    async fn write_key(&self, project: &str, name: &str, value: &str) -> Result<String> {
        let secret =
            Secret::new().set_replication(Replication::new().set_automatic(Automatic::new()));
        match self
            .client
            .create_secret()
            .set_parent(project)
            .set_secret_id(name)
            .set_secret(secret)
            .send()
            .await
        {
            Ok(_) => {}
            Err(error)
                if error
                    .status()
                    .is_some_and(|status| status.code == Code::AlreadyExists) => {}
            Err(error) => {
                return Err(error).context("failed to create Google Secret Manager secret");
            }
        }
        let version = self
            .client
            .add_secret_version()
            .set_parent(format!("{project}/secrets/{name}"))
            .set_payload(SecretPayload::new().set_data(value.to_owned().into_bytes()))
            .send()
            .await
            .context("failed to write Google Secret Manager secret version")?;
        Self::secret_reference(&version.name, project)?;
        Ok(version.name)
    }

    async fn delete_key(&self, reference: &str, project: &str) -> Result<()> {
        let secret = Self::secret_reference(reference, project)?;
        match self.client.delete_secret().set_name(secret).send().await {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .status()
                    .is_some_and(|status| status.code == Code::NotFound) =>
            {
                Ok(())
            }
            Err(error) => Err(error).context("failed to delete Google Secret Manager secret"),
        }
    }
}

impl KeyStore for GoogleKeyStore {
    async fn load(&self) -> Result<models::KeysFile> {
        if !self.path.exists() {
            anyhow::bail!("keys file does not exist, please run `ramenv init` first");
        }
        let references = read_references(&self.path)?;
        let project = Self::project(&references.provider_location)?;
        let mut keys = models::KeysFile::default();
        for (key, reference) in &references.encryption_keys {
            keys.encryption_keys
                .insert(key.clone(), self.read_key(reference, &project).await?);
        }
        for (key, reference) in &references.signature_keys {
            keys.signature_keys
                .insert(key.clone(), self.read_key(reference, &project).await?);
        }
        Ok(keys)
    }

    async fn create(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        provider_location: Option<&str>,
    ) -> Result<()> {
        if self.path.exists() {
            anyhow::bail!("key references file already exists");
        }
        let project = Self::project(
            provider_location.context("Google project is required when creating keys")?,
        )?;
        let mut references = models::KeysReferenceFile::new(project.clone());
        for (key, value) in &keys.encryption_keys {
            let reference = self
                .write_key(
                    &project,
                    &secret_name(workspace_name, "encryption", key),
                    value,
                )
                .await?;
            references.encryption_keys.insert(key.clone(), reference);
        }
        for (key, value) in &keys.signature_keys {
            let reference = self
                .write_key(
                    &project,
                    &secret_name(workspace_name, "signature", key),
                    value,
                )
                .await?;
            references.signature_keys.insert(key.clone(), reference);
        }
        write_references(&self.path, &references, true)
    }

    async fn save(
        &mut self,
        keys: &models::KeysFile,
        workspace_name: &str,
        pending: &IndexMap<KeyId, Change>,
    ) -> Result<()> {
        let mut references = read_references(&self.path)?;
        let project = Self::project(&references.provider_location)?;
        for (id, change) in pending {
            let (key, kind, values, refs) = match id {
                KeyId::Encryption(key) => (
                    key,
                    "encryption",
                    &keys.encryption_keys,
                    &mut references.encryption_keys,
                ),
                KeyId::Signature(key) => (
                    key,
                    "signature",
                    &keys.signature_keys,
                    &mut references.signature_keys,
                ),
            };
            match change {
                Change::Upsert => {
                    let value = values
                        .get(key)
                        .with_context(|| format!("{kind} key not found for {key}"))?;
                    let reference = self
                        .write_key(&project, &secret_name(workspace_name, kind, key), value)
                        .await?;
                    refs.insert(key.clone(), reference);
                }
                Change::Remove => {
                    if let Some(reference) = refs.get(key) {
                        self.delete_key(reference, &project).await?;
                        refs.shift_remove(key);
                    }
                }
            }
        }
        write_references(&self.path, &references, false)
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

    fn assert_secret_name(name: &str) {
        assert!((1..=127).contains(&name.len()), "invalid length: {name}");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "invalid characters: {name}"
        );
    }

    #[test]
    fn secret_names_always_include_digest() {
        assert_eq!(
            secret_name("my-project", "encryption", "development"),
            "ramenv-my-project-encryption-development-c185af168e7266c730e96307bcce6f6a4b74fe8a7ccb9527ce01de70d87bde0d"
        );
        assert_eq!(
            secret_name("my-project", "signature", "api"),
            "ramenv-my-project-signature-api-26b91ccabc1672d01a6e34014145b7a2abdb64064ea590aab814e2cce4b73247"
        );
    }

    #[test]
    fn secret_names_support_underscores_paths_and_unicode() {
        for workspace in ["cloud_test", "my project", "项目"] {
            for key in [
                "development",
                "preview_env",
                "/",
                "services/api",
                "服务/api",
            ] {
                assert_secret_name(&secret_name(workspace, "encryption", key));
                assert_secret_name(&secret_name(workspace, "signature", key));
            }
        }
    }

    #[test]
    fn secret_names_are_stable_and_distinguish_normalized_inputs() {
        let name = secret_name("cloud_test", "encryption", "development");
        assert_eq!(name, secret_name("cloud_test", "encryption", "development"));
        assert_ne!(name, secret_name("cloud-test", "encryption", "development"));
        assert_ne!(name, secret_name("cloud_test", "signature", "development"));
        assert_ne!(
            secret_name("test", "signature", "services/api"),
            secret_name("test", "signature", "services-api")
        );
        assert_ne!(
            secret_name("test", "signature", "services/api"),
            secret_name("test", "signature", "services_api")
        );
    }

    #[test]
    fn secret_names_enforce_length_without_truncation_collisions() {
        let workspace = "a".repeat(200);
        let key = "b".repeat(200);
        let name = secret_name(&workspace, "encryption", &key);
        assert_secret_name(&name);
        assert_secret_name(&secret_name(&workspace, "signature", &key));
        assert_ne!(
            name,
            secret_name(&workspace, "encryption", &format!("{key}c"))
        );
        let boundary_workspace = "a".repeat(107);
        let boundary = secret_name(&boundary_workspace, "encryption", "x");
        assert_eq!(boundary.len(), 127);
        assert_eq!(
            boundary,
            "ramenv-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dcaf694ac4d31bdcd7dd3f616c669fc7b22643d319436ed3b949c3f120a7199f"
        );
        assert_secret_name(&secret_name(&boundary_workspace, "encryption", "xx"));
    }

    #[test]
    fn key_references_create_then_update_preserves_locations_and_logical_names() {
        for (provider_location, encryption_reference, signature_reference) in [
            (
                "https://test.vault.azure.net/",
                "https://test.vault.azure.net/secrets/env-key/version1",
                "https://test.vault.azure.net/secrets/signing-key/version2",
            ),
            (
                AWS_REGION,
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:env-Abc123#11111111-1111-1111-1111-111111111111",
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:sig-Abc123#22222222-2222-2222-2222-222222222222",
            ),
            (
                "projects/test-project",
                "projects/test-project/secrets/env-key/versions/1",
                "projects/test-project/secrets/signing-key/versions/2",
            ),
        ] {
            let root = TempDir::new("key-references");
            let path = root.0.join(".ramenv.keyrefs.toml");
            let mut references = models::KeysReferenceFile::new(provider_location.into());
            references
                .encryption_keys
                .insert("preview_env".into(), encryption_reference.into());
            write_references(&path, &references, true).unwrap();
            let original_content = std::fs::read_to_string(&path).unwrap();

            references
                .signature_keys
                .insert("/".into(), signature_reference.into());
            assert!(write_references(&path, &references, true).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original_content);

            write_references(&path, &references, false).unwrap();
            let reloaded = read_references(&path).unwrap();
            assert_eq!(reloaded.provider_location, provider_location);
            assert_eq!(
                reloaded.encryption_keys["preview_env"],
                encryption_reference
            );
            assert_eq!(reloaded.signature_keys["/"], signature_reference);

            references.encryption_keys.shift_remove("preview_env");
            write_references(&path, &references, false).unwrap();
            let reloaded = read_references(&path).unwrap();
            assert_eq!(reloaded.provider_location, provider_location);
            assert!(reloaded.encryption_keys.is_empty());
            assert_eq!(reloaded.signature_keys["/"], signature_reference);
        }
    }

    #[test]
    fn key_references_report_missing_and_malformed_files() {
        let root = TempDir::new("key-references-invalid");
        let path = root.0.join(".ramenv.keyrefs.toml");
        assert_eq!(
            read_references(&path).unwrap_err().to_string(),
            format!("failed to read keys file {}", path.display())
        );
        for content in ["invalid = [toml", "provider_location = 'test'"] {
            std::fs::write(&path, content).unwrap();
            assert_eq!(
                read_references(&path).unwrap_err().to_string(),
                "failed to parse key references"
            );
        }
    }

    #[test]
    fn key_references_update_requires_existing_writable_file() {
        let root = TempDir::new("key-references-unwritable");
        let path = root.0.join(".ramenv.keyrefs.toml");
        let references = models::KeysReferenceFile::new("test".into());
        assert!(write_references(&path, &references, false).is_err());
        assert!(!path.exists());

        std::fs::create_dir(&path).unwrap();
        assert!(write_references(&path, &references, false).is_err());
        assert!(write_references(&path, &references, true).is_err());
        assert!(path.is_dir());
    }

    #[tokio::test]
    async fn azure_store_rejects_missing_upsert_values_without_changing_references() {
        let root = TempDir::new("azure-missing-upsert-values");
        let mut store = AzureKeyStore::new(
            &root.0,
            azure_identity::DeveloperToolsCredential::new(None).unwrap(),
        );
        let mut references = models::KeysReferenceFile::new("https://test.vault.azure.net/".into());
        references.encryption_keys.insert(
            "shared".into(),
            "https://test.vault.azure.net/secrets/env-key/version1".into(),
        );
        references.signature_keys.insert(
            "shared".into(),
            "https://test.vault.azure.net/secrets/signing-key/version2".into(),
        );
        write_references(&store.path, &references, true).unwrap();
        let before = std::fs::read_to_string(&store.path).unwrap();

        for (id, kind) in [
            (KeyId::Encryption("shared".into()), "encryption"),
            (KeyId::Signature("shared".into()), "signature"),
        ] {
            let mut keys = KeysFile::default();
            // A value in the other key kind must not satisfy the pending upsert.
            match &id {
                KeyId::Encryption(key) => {
                    keys.signature_keys.insert(key.clone(), SIGNING_KEY.into());
                }
                KeyId::Signature(key) => {
                    keys.encryption_keys.insert(key.clone(), ENV_KEY.into());
                }
            }
            let error = store
                .save(&keys, "workspace", &IndexMap::from([(id, Change::Upsert)]))
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("{kind} key not found for shared")
            );
            assert_eq!(std::fs::read_to_string(&store.path).unwrap(), before);
        }
    }

    const AWS_REGION: &str = "us-east-1";
    const AWS_ENV_ARN: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:env-Abc123";
    const AWS_SIG_ARN: &str = "arn:aws:secretsmanager:us-east-1:123456789012:secret:sig-Abc123";
    const AWS_VERSION: &str = "11111111-1111-1111-1111-111111111111";
    const AWS_NEXT_VERSION: &str = "22222222-2222-2222-2222-222222222222";

    fn aws_test_store(root: &Path, endpoint: &str) -> AwsKeyStore {
        let config = SdkConfig::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(AWS_REGION))
            .endpoint_url(endpoint)
            .credentials_provider(
                aws_sdk_secretsmanager::config::SharedCredentialsProvider::new(
                    aws_sdk_secretsmanager::config::Credentials::new(
                        "test", "test", None, None, "test",
                    ),
                ),
            )
            .build();
        AwsKeyStore {
            path: root.join(".ramenv.keyrefs.toml"),
            config,
        }
    }

    // Exercise the actual AWS SDK HTTP protocol without contacting AWS or finding credentials.
    fn aws_server(
        responses: Vec<(u16, serde_json::Value)>,
    ) -> (
        String,
        std::thread::JoinHandle<Vec<(String, serde_json::Value)>>,
    ) {
        use std::io::{Read, Write};
        use std::time::{Duration, Instant};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "timed out waiting for AWS request"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap().to_lowercase();
                let length: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let target = header
                    .lines()
                    .find_map(|line| line.strip_prefix("x-amz-target:"))
                    .unwrap()
                    .trim()
                    .to_string();
                let mut request = vec![0; length];
                stream.read_exact(&mut request).unwrap();
                requests.push((target, serde_json::from_slice(&request).unwrap()));
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status} Response\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        (endpoint, handle)
    }

    #[tokio::test]
    async fn aws_store_creates_loads_updates_and_removes_versioned_keys() {
        use serde_json::json;
        let root = TempDir::new("aws-store");
        let (endpoint, server) = aws_server(vec![
            (200, json!({"ARN": AWS_ENV_ARN, "VersionId": AWS_VERSION})),
            (200, json!({"ARN": AWS_SIG_ARN, "VersionId": AWS_VERSION})),
            (200, json!({"SecretString": ENV_KEY})),
            (200, json!({"SecretString": SIGNING_KEY})),
            (
                400,
                json!({"__type": "ResourceExistsException", "Message": "exists"}),
            ),
            (
                200,
                json!({"ARN": AWS_SIG_ARN, "VersionId": AWS_NEXT_VERSION}),
            ),
            (200, json!({})),
            (200, json!({"SecretString": ENV_KEY})),
        ]);
        let mut store = aws_test_store(&root.0, &endpoint);
        let mut keys = KeysFile::default();
        keys.encryption_keys
            .insert("development".into(), ENV_KEY.into());
        keys.signature_keys.insert("/".into(), SIGNING_KEY.into());
        store
            .create(&keys, "workspace", Some(AWS_REGION))
            .await
            .unwrap();
        assert!(
            store
                .create(&keys, "workspace", Some(AWS_REGION))
                .await
                .is_err()
        );
        let refs = read_references(&store.path).unwrap();
        assert_eq!(refs.provider_location, AWS_REGION);
        assert_eq!(
            refs.encryption_keys["development"],
            format!("{AWS_ENV_ARN}#{AWS_VERSION}")
        );
        let content = std::fs::read_to_string(&store.path).unwrap();
        assert!(!content.contains(ENV_KEY) && !content.contains(SIGNING_KEY));
        assert!(!root.0.join(".ramenv.keys").exists());
        let loaded = store.load().await.unwrap();
        assert_eq!(loaded.encryption_keys, keys.encryption_keys);
        assert_eq!(loaded.signature_keys, keys.signature_keys);

        keys.signature_keys.insert("/".into(), ENV_KEY.into());
        keys.encryption_keys.shift_remove("development");
        store
            .save(
                &keys,
                "workspace",
                &IndexMap::from([
                    (KeyId::Signature("/".into()), Change::Upsert),
                    (KeyId::Encryption("development".into()), Change::Remove),
                ]),
            )
            .await
            .unwrap();
        let refs = read_references(&store.path).unwrap();
        assert!(refs.encryption_keys.is_empty());
        assert_eq!(
            refs.signature_keys["/"],
            format!("{AWS_SIG_ARN}#{AWS_NEXT_VERSION}")
        );
        assert_eq!(store.load().await.unwrap().signature_keys["/"], ENV_KEY);

        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 8);
        assert_eq!(
            requests[0].1["Name"],
            secret_name("workspace", "encryption", "development")
        );
        assert_eq!(requests[2].1["VersionId"], AWS_VERSION);
        assert!(requests[5].0.ends_with("putsecretvalue"));
        assert_eq!(requests[5].1["SecretString"], ENV_KEY);
        assert!(requests[6].0.ends_with("deletesecret"));
        assert_eq!(requests[6].1["SecretId"], AWS_ENV_ARN);
        assert!(requests[6].1.get("ForceDeleteWithoutRecovery").is_none());
    }

    #[tokio::test]
    async fn aws_store_preserves_references_when_remote_write_fails() {
        let root = TempDir::new("aws-error");
        let (endpoint, server) = aws_server(vec![(
            400,
            serde_json::json!({
                "__type": "AccessDeniedException", "Message": "denied"
            }),
        )]);
        let mut store = aws_test_store(&root.0, &endpoint);
        let mut refs = models::KeysReferenceFile::new(AWS_REGION.into());
        refs.signature_keys
            .insert("/".into(), format!("{AWS_SIG_ARN}#{AWS_VERSION}"));
        write_references(&store.path, &refs, true).unwrap();
        let before = std::fs::read_to_string(&store.path).unwrap();
        let mut keys = KeysFile::default();
        keys.signature_keys.insert("/".into(), ENV_KEY.into());
        assert!(
            store
                .save(
                    &keys,
                    "workspace",
                    &IndexMap::from([(KeyId::Signature("/".into()), Change::Upsert),])
                )
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&store.path).unwrap(), before);
        assert_eq!(server.join().unwrap().len(), 1);
    }

    #[derive(Debug, Default)]
    struct GoogleSecretsMock {
        secrets: std::sync::Mutex<IndexMap<String, Vec<String>>>,
        fail_writes: std::sync::atomic::AtomicBool,
    }

    fn google_error(code: Code) -> google_cloud_gax::error::Error {
        google_cloud_gax::error::Error::service(
            google_cloud_gax::error::rpc::Status::default().set_code(code),
        )
    }

    fn google_response<T>(body: T) -> google_cloud_gax::response::Response<T> {
        google_cloud_gax::response::Response::from_parts(Default::default(), body)
    }

    impl google_cloud_secretmanager_v1::stub::SecretManagerService for GoogleSecretsMock {
        async fn create_secret(
            &self,
            req: google_cloud_secretmanager_v1::model::CreateSecretRequest,
            _: google_cloud_gax::options::RequestOptions,
        ) -> google_cloud_secretmanager_v1::Result<google_cloud_gax::response::Response<Secret>>
        {
            assert!(req.secret.as_ref().unwrap().replication.is_some());
            let name = format!("{}/secrets/{}", req.parent, req.secret_id);
            let mut secrets = self.secrets.lock().unwrap();
            if secrets.contains_key(&name) {
                return Err(google_error(Code::AlreadyExists));
            }
            secrets.insert(name.clone(), Vec::new());
            Ok(google_response(Secret::new().set_name(name)))
        }

        async fn add_secret_version(
            &self,
            req: google_cloud_secretmanager_v1::model::AddSecretVersionRequest,
            _: google_cloud_gax::options::RequestOptions,
        ) -> google_cloud_secretmanager_v1::Result<
            google_cloud_gax::response::Response<
                google_cloud_secretmanager_v1::model::SecretVersion,
            >,
        > {
            if self.fail_writes.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(google_error(Code::PermissionDenied));
            }
            let mut secrets = self.secrets.lock().unwrap();
            let versions = secrets.get_mut(&req.parent).unwrap();
            versions.push(String::from_utf8(req.payload.unwrap().data.to_vec()).unwrap());
            Ok(google_response(
                google_cloud_secretmanager_v1::model::SecretVersion::new().set_name(format!(
                    "{}/versions/{}",
                    req.parent,
                    versions.len()
                )),
            ))
        }

        async fn access_secret_version(
            &self,
            req: google_cloud_secretmanager_v1::model::AccessSecretVersionRequest,
            _: google_cloud_gax::options::RequestOptions,
        ) -> google_cloud_secretmanager_v1::Result<
            google_cloud_gax::response::Response<
                google_cloud_secretmanager_v1::model::AccessSecretVersionResponse,
            >,
        > {
            let (name, version) = req.name.rsplit_once("/versions/").unwrap();
            let version: usize = version.parse().unwrap();
            let secrets = self.secrets.lock().unwrap();
            let value = &secrets[name][version - 1];
            Ok(google_response(
                google_cloud_secretmanager_v1::model::AccessSecretVersionResponse::new()
                    .set_name(req.name.clone())
                    .set_payload(SecretPayload::new().set_data(value.clone().into_bytes())),
            ))
        }

        async fn delete_secret(
            &self,
            req: google_cloud_secretmanager_v1::model::DeleteSecretRequest,
            _: google_cloud_gax::options::RequestOptions,
        ) -> google_cloud_secretmanager_v1::Result<google_cloud_gax::response::Response<()>>
        {
            if self
                .secrets
                .lock()
                .unwrap()
                .shift_remove(&req.name)
                .is_none()
            {
                return Err(google_error(Code::NotFound));
            }
            Ok(google_response(()))
        }
    }

    fn google_test_store(root: &Path) -> (GoogleKeyStore, std::sync::Arc<GoogleSecretsMock>) {
        let mock = std::sync::Arc::new(GoogleSecretsMock::default());
        let store = GoogleKeyStore {
            path: root.join(".ramenv.keyrefs.toml"),
            client: SecretManagerService::from_stub::<GoogleSecretsMock>(mock.clone()),
        };
        (store, mock)
    }

    #[tokio::test]
    async fn google_store_creates_loads_updates_and_removes_versioned_keys() {
        let root = TempDir::new("google-store");
        let (mut store, mock) = google_test_store(&root.0);
        let mut keys = KeysFile::default();
        keys.encryption_keys
            .insert("development".into(), ENV_KEY.into());
        keys.signature_keys.insert("/".into(), SIGNING_KEY.into());
        store
            .create(&keys, "workspace", Some("test-project"))
            .await
            .unwrap();
        assert!(
            store
                .create(&keys, "workspace", Some("test-project"))
                .await
                .is_err()
        );
        let refs = read_references(&store.path).unwrap();
        assert_eq!(refs.provider_location, "projects/test-project");
        assert!(refs.encryption_keys["development"].ends_with("/versions/1"));
        let content = std::fs::read_to_string(&store.path).unwrap();
        assert!(!content.contains(ENV_KEY) && !content.contains(SIGNING_KEY));
        assert!(!root.0.join(".ramenv.keys").exists());
        let loaded = store.load().await.unwrap();
        assert_eq!(loaded.encryption_keys, keys.encryption_keys);
        assert_eq!(loaded.signature_keys, keys.signature_keys);
        let old_signing_ref = refs.signature_keys["/"].clone();

        keys.signature_keys.insert("/".into(), ENV_KEY.into());
        keys.encryption_keys.shift_remove("development");
        store
            .save(
                &keys,
                "workspace",
                &IndexMap::from([
                    (KeyId::Signature("/".into()), Change::Upsert),
                    (KeyId::Encryption("development".into()), Change::Remove),
                ]),
            )
            .await
            .unwrap();
        let refs = read_references(&store.path).unwrap();
        assert!(refs.encryption_keys.is_empty());
        assert!(refs.signature_keys["/"].ends_with("/versions/2"));
        assert_eq!(
            store
                .read_key(&old_signing_ref, "projects/test-project")
                .await
                .unwrap(),
            SIGNING_KEY
        );
        assert_eq!(store.load().await.unwrap().signature_keys["/"], ENV_KEY);
        assert_eq!(mock.secrets.lock().unwrap().len(), 1);
        // Repeated removal of a remotely missing key is idempotent.
        store
            .delete_key(
                "projects/test-project/secrets/missing/versions/1",
                "projects/test-project",
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn google_store_preserves_references_when_remote_write_fails() {
        let root = TempDir::new("google-error");
        let (mut store, mock) = google_test_store(&root.0);
        let mut keys = KeysFile::default();
        keys.signature_keys.insert("/".into(), SIGNING_KEY.into());
        store
            .create(&keys, "workspace", Some("test-project"))
            .await
            .unwrap();
        let before = std::fs::read_to_string(&store.path).unwrap();
        mock.fail_writes
            .store(true, std::sync::atomic::Ordering::Relaxed);
        keys.signature_keys.insert("/".into(), ENV_KEY.into());
        assert!(
            store
                .save(
                    &keys,
                    "workspace",
                    &IndexMap::from([(KeyId::Signature("/".into()), Change::Upsert),])
                )
                .await
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&store.path).unwrap(), before);
        assert_eq!(store.load().await.unwrap().signature_keys["/"], SIGNING_KEY);
    }

    #[tokio::test]
    async fn cloud_stores_reject_missing_files_and_invalid_locations_without_cloud_calls() {
        let aws_root = TempDir::new("aws-invalid");
        let google_root = TempDir::new("google-invalid");
        let mut aws = aws_test_store(&aws_root.0, "http://127.0.0.1:1");
        let (mut google, mock) = google_test_store(&google_root.0);
        assert!(aws.load().await.is_err());
        assert!(google.load().await.is_err());
        let keys = KeysFile::default();
        for location in [None, Some(""), Some("https://example.com")] {
            assert!(aws.create(&keys, "workspace", location).await.is_err());
            assert!(google.create(&keys, "workspace", location).await.is_err());
        }
        assert!(!aws.path.exists());
        assert!(!google.path.exists());
        assert!(mock.secrets.lock().unwrap().is_empty());
        std::fs::write(&aws.path, "invalid = [toml").unwrap();
        std::fs::write(&google.path, "invalid = [toml").unwrap();
        assert!(aws.load().await.is_err());
        assert!(google.load().await.is_err());
    }

    #[test]
    fn cloud_locations_and_versioned_references_are_validated() {
        assert_eq!(AwsKeyStore::region(" us-east-1 ").unwrap(), AWS_REGION);
        for invalid in ["", "https://example.com", "invalid", "US-EAST-1"] {
            assert!(AwsKeyStore::region(invalid).is_err());
        }
        let reference = format!("{AWS_ENV_ARN}#{AWS_VERSION}");
        assert_eq!(
            AwsKeyStore::secret_reference(&reference, AWS_REGION).unwrap(),
            (AWS_ENV_ARN, AWS_VERSION)
        );
        assert!(AwsKeyStore::secret_reference(&reference, "eu-west-1").is_err());
        for invalid in [
            AWS_ENV_ARN,
            "not-an-arn#version",
            "arn:aws:s3:us-east-1:123456789012:secret:name#version",
        ] {
            assert!(AwsKeyStore::secret_reference(invalid, AWS_REGION).is_err());
        }
        assert_eq!(
            GoogleKeyStore::project("test-project").unwrap(),
            "projects/test-project"
        );
        assert_eq!(
            GoogleKeyStore::project("projects/test-project").unwrap(),
            "projects/test-project"
        );
        for invalid in [
            "",
            "projects/",
            "projects/a/secrets/b",
            "https://example.com",
        ] {
            assert!(GoogleKeyStore::project(invalid).is_err());
        }
        let reference = "projects/test-project/secrets/key/versions/1";
        assert_eq!(
            GoogleKeyStore::secret_reference(reference, "projects/test-project").unwrap(),
            "projects/test-project/secrets/key"
        );
        assert!(GoogleKeyStore::secret_reference(reference, "projects/other-project").is_err());
        for invalid in [
            "projects/test-project/secrets/key",
            "projects/test-project/secrets/key/versions/latest",
            "projects/test-project/secrets/key/versions/0",
        ] {
            assert!(GoogleKeyStore::secret_reference(invalid, "projects/test-project").is_err());
        }
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
            crate::commands::remove_env_command(
                "development",
                &mut keys,
                std::slice::from_mut(&mut vault),
                &workspace
            )
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

    fn transaction_vaults(root: &Path) -> Vec<VaultRegistry> {
        ["first", "second", "third"]
            .iter()
            .map(|name| {
                let path = root.join(name);
                std::fs::create_dir(&path).unwrap();
                let mut vault = VaultRegistry::empty(&path, SIGNING_KEY);
                vault.set_env_vault(
                    "development",
                    IndexMap::from([(
                        "SECRET".into(),
                        crypto::encrypt_value(name, ENV_KEY).unwrap(),
                    )]),
                );
                vault.set_env_vault(
                    "production",
                    IndexMap::from([("KEEP".into(), "unchanged".into())]),
                );
                vault.create().unwrap();
                vault
            })
            .collect()
    }

    #[tokio::test]
    async fn workspace_operations_restore_earlier_files_after_later_vault_write_failure() {
        for rotate in [true, false] {
            let root = TempDir::new("workspace-vault-rollback");
            write_workspace(&root.0);
            write_keys(&root.0);
            let mut keys = KeyService::from_store(LocalKeyStore::new(&root.0))
                .await
                .unwrap();
            let workspace = WorkspaceRegistry::load(&root.0).unwrap();
            let mut vaults = transaction_vaults(&root.0);
            let originals: Vec<_> = vaults.iter().map(VaultService::all_env_vaults).collect();
            let keys_before = std::fs::read(root.0.join(".ramenv.keys")).unwrap();
            let third_before = std::fs::read(root.0.join("third/.ramenv.vault.toml")).unwrap();
            let broken_path = root.0.join("second/.ramenv.vault.toml");
            std::fs::remove_file(&broken_path).unwrap();
            std::fs::create_dir(&broken_path).unwrap();
            let result = if rotate {
                crate::commands::rotate_command("development", &mut keys, &mut vaults, &workspace)
                    .await
            } else {
                crate::commands::remove_env_command(
                    "development",
                    &mut keys,
                    &mut vaults,
                    &workspace,
                )
                .await
            };
            let diagnostic = format!("{:#}", result.unwrap_err());
            assert!(diagnostic.contains("failed to roll back vaults"));
            let persisted = VaultRegistry::load(&root.0.join("first"), SIGNING_KEY).unwrap();
            assert_eq!(persisted.all_env_vaults(), originals[0]);
            assert_eq!(
                std::fs::read(root.0.join("third/.ramenv.vault.toml")).unwrap(),
                third_before
            );
            assert_eq!(
                std::fs::read(root.0.join(".ramenv.keys")).unwrap(),
                keys_before
            );
            for (vault, original) in vaults.iter().zip(originals) {
                assert_eq!(vault.all_env_vaults(), original);
            }
        }
    }

    #[tokio::test]
    async fn workspace_operations_restore_all_persisted_vaults_after_key_write_failure() {
        for rotate in [true, false] {
            let root = TempDir::new("workspace-key-rollback");
            write_workspace(&root.0);
            write_keys(&root.0);
            let mut keys = KeyService::from_store(LocalKeyStore::new(&root.0))
                .await
                .unwrap();
            let workspace = WorkspaceRegistry::load(&root.0).unwrap();
            let mut vaults = transaction_vaults(&root.0);
            let originals: Vec<_> = vaults.iter().map(VaultService::all_env_vaults).collect();
            let keys_path = root.0.join(".ramenv.keys");
            std::fs::remove_file(&keys_path).unwrap();
            std::fs::create_dir(&keys_path).unwrap();
            let result = if rotate {
                crate::commands::rotate_command("development", &mut keys, &mut vaults, &workspace)
                    .await
            } else {
                crate::commands::remove_env_command(
                    "development",
                    &mut keys,
                    &mut vaults,
                    &workspace,
                )
                .await
            };
            assert!(format!("{:#}", result.unwrap_err()).contains("failed to roll back key"));
            assert_eq!(keys.env_key("development").unwrap(), ENV_KEY);
            for (name, original) in ["first", "second", "third"].iter().zip(originals) {
                let persisted = VaultRegistry::load(&root.0.join(name), SIGNING_KEY).unwrap();
                assert_eq!(persisted.all_env_vaults(), original);
            }
        }
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
            crate::commands::rotate_command(
                "development",
                &mut keys,
                std::slice::from_mut(&mut vault),
                &workspace
            )
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
