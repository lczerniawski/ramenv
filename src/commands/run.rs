use std::process::{Command, exit};

use anyhow::{Context, Result};

use crate::services;
use crate::utils::{self};

pub fn run_command(
    env: &str,
    command_args: &[String],
    encryption_key_service: &impl services::EncryptionKeyService,
    vault_service: &impl services::VaultService,
) -> Result<()> {
    if command_args.is_empty() {
        anyhow::bail!("No command arguments provided to run");
    }

    let env_vault = vault_service.env_vault(env)?;
    let encryption_key = encryption_key_service.env_key(env)?;

    for (key, value) in env_vault {
        let plaintext = utils::get_plaintext(&value, encryption_key)?;
        unsafe {
            // The CLI is single threaded so it is safe to do it
            std::env::set_var(key.to_uppercase(), plaintext);
        }
    }

    let program = &command_args[0];
    let args = &command_args[1..];

    let mut child = Command::new(program)
        .args(args)
        .spawn()
        .context(format!("failed to start command: {}", program))?;

    let status = child
        .wait()
        .context("failed to wait for command execution")?;

    if let Some(code) = status.code() {
        exit(code);
    }

    Ok(())
}
