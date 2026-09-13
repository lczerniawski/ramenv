use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;
use log::info;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::services::{EncryptionKeyService, WorkspaceService};
use crate::{InitTarget, crypto, models, services};

pub fn init_command(current_working_path: &Path, init_target: Option<InitTarget>) -> Result<()> {
    match init_target {
        Some(InitTarget::Workspace) => init_workspace(current_working_path)?,
        Some(InitTarget::Service) => init_service(current_working_path)?,
        None => {
            init_workspace(current_working_path)?;
            init_service(current_working_path)?;
        }
    }

    info!("🍜 ramenv initialized successfully!");
    Ok(())
}

fn init_workspace(current_working_path: &Path) -> Result<()> {
    match init_gitignore(current_working_path)? {
        InitStatus::Updated => info!(".gitignore file updated with required files"),
        InitStatus::Skipped => info!("all required files are already in .gitignore"),
        _ => {}
    }

    match init_keys_file(current_working_path)? {
        InitStatus::Created => info!(".ramenv.keys file created successfully"),
        InitStatus::Skipped => info!(".ramenv.keys file already exists, skipping"),
        _ => {}
    }

    match init_workspace_file(current_working_path)? {
        InitStatus::Created => info!(".ramenv.workspace.toml file created successfully"),
        InitStatus::Skipped => {
            info!(".ramenv.workspace.toml file already exists, skipping")
        }
        _ => {}
    }

    Ok(())
}

fn init_service(current_working_path: &Path) -> Result<()> {
    match init_vault_file(current_working_path)? {
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

fn init_keys_file(current_working_path: &Path) -> Result<InitStatus> {
    let keys_path = current_working_path.join(".ramenv.keys");
    if keys_path.exists() {
        return Ok(InitStatus::Skipped);
    }

    let mut keys = models::KeysFile::default();
    keys.keys
        .insert("development".to_string(), crypto::generate_master_key_hex());
    keys.keys
        .insert("production".to_string(), crypto::generate_master_key_hex());

    let serialized_keys =
        toml::to_string(&keys).context("failed to serialize .ramenv.keys file")?;
    std::fs::write(&keys_path, &serialized_keys).context("failed to write .ramenv.keys to disc")?;

    Ok(InitStatus::Created)
}

fn init_vault_file(current_working_path: &Path) -> Result<InitStatus> {
    let vault_path = current_working_path.join(".ramenv.vault.toml");
    if vault_path.exists() {
        return Ok(InitStatus::Skipped);
    }

    let mut vault = models::VaultFile::default();
    vault
        .environments
        .insert("development".to_string(), IndexMap::new());
    vault
        .environments
        .insert("production".to_string(), IndexMap::new());

    let workspace_registry = services::WorkspaceRegistry::new(current_working_path)?;
    let workspace_root = workspace_registry.get_workspace_root();
    let vault_name = current_working_path
        .strip_prefix(workspace_root)?
        .to_str()
        .map(|s| if s.is_empty() { "/" } else { s })
        .unwrap_or("/");

    let mut encryption_key_service =
        services::LocalEncryptionKeyService::new(&workspace_registry.get_workspace_root())?;
    encryption_key_service.store_new_vault_signature_key(vault_name);
    encryption_key_service.commit()?;

    let vault_signing_key = encryption_key_service.vault_signature_key(vault_name)?;
    let canonical_vault = models::CanonicalVault {
        environments: vault.environments.clone(),
    };
    let canonical_vault_str = serde_json::to_string(&canonical_vault)
        .context("failed to serialize vault for verification")?;
    let signature = crypto::generate_signature(&canonical_vault_str, vault_signing_key)?;
    let metadata = models::VaultMetadata {
        signature,
        signature_version: "1".to_string(),
        signed_at: chrono::Utc::now().to_rfc3339(),
    };
    vault.metadata = metadata;

    let serialized_vault = toml::to_string(&vault)?;
    std::fs::write(&vault_path, &serialized_vault)?;

    Ok(InitStatus::Created)
}

fn init_workspace_file(current_working_path: &Path) -> Result<InitStatus> {
    let workspace_path = current_working_path.join(".ramenv.workspace.toml");
    if (workspace_path).exists() {
        return Ok(InitStatus::Skipped);
    }

    let project_name = current_working_path
        .file_name()
        .map(|os_str| os_str.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown_project".to_string());

    let workspace = models::WorkspaceFile::new("1".to_string(), project_name);
    let serialized_workspace = toml::to_string(&workspace)?;
    std::fs::write(&workspace_path, &serialized_workspace)?;

    Ok(InitStatus::Created)
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

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

    #[test]
    fn key_and_workspace_initializers_create_then_skip_valid_files() {
        let root = TempDir::new();
        assert!(matches!(
            init_keys_file(&root.0).unwrap(),
            InitStatus::Created
        ));
        let keys: models::KeysFile =
            toml::from_str(&std::fs::read_to_string(root.0.join(".ramenv.keys")).unwrap()).unwrap();
        assert_eq!(keys.keys.len(), 2);
        assert!(matches!(
            init_keys_file(&root.0).unwrap(),
            InitStatus::Skipped
        ));

        assert!(matches!(
            init_workspace_file(&root.0).unwrap(),
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
        assert!(matches!(
            init_workspace_file(&root.0).unwrap(),
            InitStatus::Skipped
        ));
    }

    #[test]
    fn full_init_creates_signed_vault_and_is_idempotent() {
        let root = TempDir::new();
        init_command(&root.0, None).unwrap();
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
        crypto::verify_signature(&canonical, &vault.metadata.signature, &keys.signatures["/"])
            .unwrap();

        let before = std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap();
        init_command(&root.0, None).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.0.join(".ramenv.vault.toml")).unwrap(),
            before
        );
    }

    #[test]
    fn service_init_fails_without_workspace_and_workspace_target_omits_vault() {
        let root = TempDir::new();
        assert!(init_command(&root.0, Some(InitTarget::Service)).is_err());
        init_command(&root.0, Some(InitTarget::Workspace)).unwrap();
        assert!(!root.0.join(".ramenv.vault.toml").exists());
    }
}
