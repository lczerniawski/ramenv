use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use log::info;

use crate::{crypto, models};

pub fn init_command() -> anyhow::Result<()> {
    let current_working_path = std::env::current_dir().unwrap();

    let result = init_gitignore(&current_working_path)?;
    info!("{}", result);

    let result = init_config_file(&current_working_path)?;
    info!("{}", result);

    let result = init_keys_file(&current_working_path)?;
    info!("{}", result);

    let result = init_vault_file(&current_working_path)?;
    info!("{}", result);

    Ok(())
}

const FILES_TO_INGORE: &[&str] = &[".env", ".ramenv.keys"];

fn init_gitignore(current_working_path: &Path) -> Result<String, std::io::Error> {
    let gitignore_path = current_working_path.join(".gitignore");
    let mut already_ignored_files = Vec::new();
    if gitignore_path.exists() {
        let gitignore_file = OpenOptions::new().read(true).open(&gitignore_path)?;
        let reader = BufReader::new(gitignore_file);

        for line_result in reader.lines() {
            let line = line_result?;
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
        return Ok(String::from("All required files are already in .gitignore"));
    }

    let mut gitignore_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&gitignore_path)?;

    writeln!(gitignore_file, "\n#ramenv Configuration")?;
    for file in &missing_files {
        writeln!(gitignore_file, "{}", file)?;
    }

    Ok(String::from(".gitignore file updated with required files"))
}

fn init_config_file(current_working_path: &Path) -> anyhow::Result<String> {
    let main_config_path = current_working_path.join("ramenv.toml");
    if OpenOptions::new()
        .read(true)
        .open(&main_config_path)
        .is_ok()
    {
        return Ok(String::from("ramenv.toml file already exists, skipping"));
    }

    let project_name = current_working_path
        .file_name()
        .map(|os_str| os_str.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown_project".to_string());
    let config = models::ConfigFile::new("1.0.0".to_string(), project_name);
    let serialized_config = toml::to_string(&config)?;
    std::fs::write(&main_config_path, &serialized_config)?;

    Ok(String::from("ramenv.toml file created successfully"))
}

fn init_keys_file(current_working_path: &Path) -> anyhow::Result<String> {
    let keys_path = current_working_path.join(".ramenv.keys");
    if OpenOptions::new().read(true).open(&keys_path).is_ok() {
        return Ok(String::from(".ramenv.keys file already exists, skipping"));
    }

    let mut keys = models::KeysFile::new();
    keys.keys
        .insert("development".to_string(), crypto::generate_master_key_hex());
    keys.keys
        .insert("production".to_string(), crypto::generate_master_key_hex());
    let serialized_keys = toml::to_string(&keys)?;
    std::fs::write(&keys_path, &serialized_keys)?;

    Ok(String::from(".ramenv.keys file created successfully"))
}

fn init_vault_file(current_working_path: &Path) -> anyhow::Result<String> {
    let vault_path = current_working_path.join(".ramenv.vault.toml");
    if OpenOptions::new().read(true).open(&vault_path).is_ok() {
        return Ok(String::from(
            ".ramenv.vault.toml file already exists, skipping",
        ));
    }

    let mut vault_file = std::fs::File::create(&vault_path)?;
    writeln!(vault_file, "[development]")?;
    writeln!(vault_file)?;
    writeln!(vault_file, "[production]")?;

    Ok(String::from(".ramenv.vault.toml file created successfully"))
}
