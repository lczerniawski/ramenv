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

#[cfg(test)]
mod tests {
    use indexmap::IndexMap;

    use super::*;
    use crate::commands::test_support::{Keys, Vault};

    #[test]
    fn rejects_empty_command_before_service_lookups() {
        assert!(run_command("dev", &[], &Keys::default(), &Vault::default()).is_err());
    }

    #[test]
    fn reports_missing_environment_state_and_bad_values() {
        let command = vec!["does-not-matter".to_string()];
        assert!(run_command("dev", &command, &Keys::with_env("dev"), &Vault::default()).is_err());
        assert!(
            run_command(
                "dev",
                &command,
                &Keys::default(),
                &Vault::with_env("dev", IndexMap::new())
            )
            .is_err()
        );
        assert!(
            run_command(
                "dev",
                &command,
                &Keys::with_env("dev"),
                &Vault::with_env("dev", IndexMap::from([("KEY".into(), "secret:bad".into())]))
            )
            .is_err()
        );
    }

    #[test]
    fn reports_failure_to_spawn_program() {
        let command = vec!["ramenv-binary-that-does-not-exist".to_string()];
        let result = run_command(
            "dev",
            &command,
            &Keys::with_env("dev"),
            &Vault::with_env("dev", IndexMap::new()),
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed to start command")
        );
    }
}
