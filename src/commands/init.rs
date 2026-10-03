use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;
use inquire::Text;
use log::info;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::models::Provider;
use crate::services::{EncryptionKeyService, VaultService, WorkspaceService};
use crate::{InitTarget, models, services};

pub async fn init_command(
    current_working_path: &Path,
    init_target: Option<InitTarget>,
    provider: Option<Provider>,
) -> Result<()> {
    match init_target {
        Some(InitTarget::Workspace { ingredient }) => {
            init_workspace(current_working_path, ingredient).await?
        }
        Some(InitTarget::Service) => init_service(current_working_path).await?,
        None => {
            init_workspace(current_working_path, provider).await?;
            init_service(current_working_path).await?;
        }
    }

    info!("🍜 ramenv initialized successfully!");
    Ok(())
}

async fn init_workspace(current_working_path: &Path, provider: Option<Provider>) -> Result<()> {
    match init_gitignore(current_working_path)? {
        InitStatus::Updated => info!(".gitignore file updated with required files"),
        InitStatus::Skipped => info!("all required files are already in .gitignore"),
        _ => {}
    }

    match init_workspace_file(current_working_path, provider.clone())? {
        InitStatus::Created => info!(".ramenv.workspace.toml file created successfully"),
        InitStatus::Skipped => {
            info!(".ramenv.workspace.toml file already exists, skipping")
        }
        _ => {}
    }

    match init_keys_file(current_working_path).await? {
        InitStatus::Created => info!("keys file created successfully"),
        InitStatus::Skipped => info!("keys file already exists, skipping"),
        _ => {}
    }

    Ok(())
}

async fn init_service(current_working_path: &Path) -> Result<()> {
    let workspace_registry = services::WorkspaceRegistry::load(current_working_path)?;
    match init_vault_file(current_working_path, &workspace_registry).await? {
        InitStatus::Created => info!(".ramenv.vault.toml file created successfully"),
        InitStatus::Skipped => info!(".ramenv.vault.toml file already exists, skipping"),
        _ => {}
    }

    Ok(())
}

enum InitStatus {
    Created,
    Updated,
    Skipped,
}

const FILES_TO_INGORE: &[&str] = &[".env", ".ramenv.keys"];

fn init_gitignore(current_working_path: &Path) -> Result<InitStatus> {
    let gitignore_path = current_working_path.join(".gitignore");
    let mut already_ignored_files = Vec::new();

    if gitignore_path.exists() {
        let gitignore_file = OpenOptions::new()
            .read(true)
            .open(&gitignore_path)
            .context("Failed to open existing .gitignore file for reading")?;

        let reader = BufReader::new(gitignore_file);
        for line_result in reader.lines() {
            let line = line_result.context("Failed to read line from .gitignore")?;
            for &file in FILES_TO_INGORE {
                if line.contains(file) {
                    already_ignored_files.push(file.to_string());
                }
            }
        }
    }

    let missing_files: Vec<&str> = FILES_TO_INGORE
        .iter()
        .copied()
        .filter(|file| !already_ignored_files.iter().any(|ignored| ignored == file))
        .collect();

    if missing_files.is_empty() {
        return Ok(InitStatus::Skipped);
    }

    let mut gitignore_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&gitignore_path)
        .context("Failed to open .gitignore for appending")?;

    writeln!(gitignore_file, "\n#ramenv Configuration")
        .context("Failed to write header to .gitignore")?;
    for file in &missing_files {
        writeln!(gitignore_file, "{}", file)
            .with_context(|| format!("failed to write '{}' entry to .gitignore", file))?;
    }

    Ok(InitStatus::Updated)
}

async fn init_keys_file(current_working_path: &Path) -> Result<InitStatus> {
    let workspace_registry = services::WorkspaceRegistry::load(current_working_path)?;
    let key_file_name = match workspace_registry.get_provider() {
        Provider::Local => ".ramenv.keys",
        Provider::Azure => ".ramenv.keyrefs.toml",
    };
    let keys_path = current_working_path.join(key_file_name);
    if keys_path.exists() {
        Ok(InitStatus::Skipped)
    } else {
        let provider_url = match workspace_registry.get_provider() {
            Provider::Local => None,
            Provider::Azure => Some(
                Text::new("enter provider url for Azure:")
                    .prompt()
                    .context("failed to get the provider url")?,
            ),
        };
        match workspace_registry.get_provider() {
            Provider::Local => {
                let store = services::LocalKeyStore::new(current_working_path);
                create_keys(
                    store,
                    workspace_registry.get_workspace_name(),
                    provider_url.as_deref(),
                )
                .await?;
            }
            Provider::Azure => {
                let credential = crate::azure_auth::azure_credential().await?;
                let store = services::AzureKeyStore::new(current_working_path, credential);
                create_keys(
                    store,
                    workspace_registry.get_workspace_name(),
                    provider_url.as_deref(),
                )
                .await?;
            }
        }
        Ok(InitStatus::Created)
    }
}

async fn create_keys<S: services::KeyStore>(
    store: S,
    workspace_name: &str,
    provider_url: Option<&str>,
) -> Result<()> {
    let mut keys = services::KeyService::from_empty(store);
    keys.store_new_env_key("development");
    keys.store_new_env_key("production");
    keys.create(workspace_name, provider_url).await
}

async fn init_vault_file(
    current_working_path: &Path,
    workspace_registry: &services::WorkspaceRegistry,
) -> Result<InitStatus> {
    let vault_path = current_working_path.join(".ramenv.vault.toml");
    if vault_path.exists() {
        return Ok(InitStatus::Skipped);
    }

    let workspace_root = workspace_registry.get_workspace_root();
    let vault_name = current_working_path
        .strip_prefix(&workspace_root)?
        .to_str()
        .map(|s| if s.is_empty() { "/" } else { s })
        .unwrap_or("/");

    match workspace_registry.get_provider() {
        Provider::Local => {
            let store = services::LocalKeyStore::new(&workspace_root);
            create_vault(current_working_path, workspace_registry, vault_name, store).await?;
        }
        Provider::Azure => {
            let credential = crate::azure_auth::azure_credential().await?;
            let store = services::AzureKeyStore::new(&workspace_root, credential);
            create_vault(current_working_path, workspace_registry, vault_name, store).await?;
        }
    }

    Ok(InitStatus::Created)
}

async fn create_vault<S: services::KeyStore>(
    current_working_path: &Path,
    workspace_registry: &services::WorkspaceRegistry,
    vault_name: &str,
    store: S,
) -> Result<()> {
    let mut keys = services::KeyService::from_store(store).await?;
    keys.store_new_vault_signature_key(vault_name);
    keys.commit(workspace_registry.get_workspace_name()).await?;

    let mut vault =
        services::VaultRegistry::empty(current_working_path, keys.vault_signature_key(vault_name)?);
    vault.set_env_vault("development", IndexMap::new());
    vault.set_env_vault("production", IndexMap::new());
    vault.create()
}

fn init_workspace_file(
    current_working_path: &Path,
    provider: Option<Provider>,
) -> Result<InitStatus> {
    let workspace_path = current_working_path.join(".ramenv.workspace.toml");
    if (workspace_path).exists() {
        return Ok(InitStatus::Skipped);
    }

    let project_name = current_working_path
        .file_name()
        .map(|os_str| os_str.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown_project".to_string());

    let provider = provider.unwrap_or(Provider::Local);
    let workspace = models::WorkspaceFile::new("1".to_string(), project_name, provider);
    services::WorkspaceRegistry::create(current_working_path, workspace)?;

    Ok(InitStatus::Created)
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::crypto;

    struct TempDir(PathBuf);

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    impl TempDir {
        fn new() -> Self {
            let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("ramenv-init-unit-{}-{unique}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn gitignore_creates_updates_and_then_skips_entries() {
        let root = TempDir::new();
        assert!(matches!(
            init_gitignore(&root.0).unwrap(),
            InitStatus::Updated
        ));
        let content = std::fs::read_to_string(root.0.join(".gitignore")).unwrap();
        assert!(content.contains(".env"));
        assert!(content.contains(".ramenv.keys"));
        assert!(matches!(
            init_gitignore(&root.0).unwrap(),
            InitStatus::Skipped
        ));

        std::fs::write(root.0.join(".gitignore"), ".env\n").unwrap();
        assert!(matches!(
            init_gitignore(&root.0).unwrap(),
            InitStatus::Updated
        ));
        let content = std::fs::read_to_string(root.0.join(".gitignore")).unwrap();
        assert_eq!(content.lines().filter(|line| *line == ".env").count(), 1);
        assert_eq!(
            content
                .lines()
                .filter(|line| *line == ".ramenv.keys")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn key_and_workspace_initializers_create_then_skip_valid_files() {
        let root = TempDir::new();
        assert!(matches!(
            init_workspace_file(&root.0, None).unwrap(),
            InitStatus::Created
        ));
        let workspace: models::WorkspaceFile = toml::from_str(
            &std::fs::read_to_string(root.0.join(".ramenv.workspace.toml")).unwrap(),
        )
        .unwrap();
        assert_eq!(workspace.schema_version, "1");
        assert_eq!(
            workspace.workspace_name,
            root.0.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(workspace.ingredient, Provider::Local);
        assert!(matches!(
            init_workspace_file(&root.0, None).unwrap(),
            InitStatus::Skipped
        ));

        assert!(matches!(
            init_keys_file(&root.0).await.unwrap(),
            InitStatus::Created
        ));
        let keys: models::KeysFile =
            toml::from_str(&std::fs::read_to_string(root.0.join(".ramenv.keys")).unwrap()).unwrap();
        assert_eq!(keys.encryption_keys.len(), 2);
        assert!(matches!(
            init_keys_file(&root.0).await.unwrap(),
            InitStatus::Skipped
        ));
    }

    #[tokio::test]
    async fn workspace_init_uses_persisted_azure_provider_when_keys_already_exist() {
        let root = TempDir::new();
        init_workspace_file(&root.0, Some(Provider::Azure)).unwrap();
        std::fs::write(root.0.join(".ramenv.keyrefs.toml"), "existing references").unwrap();

        // No Azure prompt or local keys file: the saved workspace provider wins.
        init_command(
            &root.0,
            Some(InitTarget::Workspace { ingredient: None }),
            None,
        )
        .await
        .unwrap();
        assert!(!root.0.join(".ramenv.keys").exists());
        assert_eq!(
            std::fs::read_to_string(root.0.join(".ramenv.keyrefs.toml")).unwrap(),
            "existing references"
        );
    }

    #[tokio::test]
    async fn full_init_creates_signed_vault_and_is_idempotent() {
        let root = TempDir::new();
        init_command(&root.0, None, None).await.unwrap();
        let keys: models::KeysFile =
            toml::from_str(&std::fs::read_to_string(root.0.join(".ramenv.keys")).unwrap()).unwrap();
        let vault: models::VaultFile =
            toml::from_str(&std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap())
                .unwrap();
        assert_eq!(vault.environments.len(), 2);
        let canonical = serde_json::to_string(&models::CanonicalVault {
            environments: vault.environments.clone(),
        })
        .unwrap();
        crypto::verify_signature(
            &canonical,
            &vault.metadata.signature,
            &keys.signature_keys["/"],
        )
        .unwrap();

        let before = std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap();
        init_command(&root.0, None, None).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn service_init_fails_without_workspace_and_workspace_target_omits_vault() {
        let root = TempDir::new();
        assert!(
            init_command(&root.0, Some(InitTarget::Service), None)
                .await
                .is_err()
        );
        init_command(
            &root.0,
            Some(InitTarget::Workspace { ingredient: None }),
            None,
        )
        .await
        .unwrap();
        assert!(!root.0.join(".ramenv.vault.toml").exists());
    }
}
