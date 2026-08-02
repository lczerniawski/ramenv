use anyhow::{Context, Ok, Result};
use indexmap::IndexMap;
use log::info;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use crate::{InitTarget, crypto, models};

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
