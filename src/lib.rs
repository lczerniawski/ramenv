use std::path::Path;
use std::process::exit;

use anyhow::Ok;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use env_logger::Env;
use log::error;
use services::WorkspaceService;

use crate::models::Provider;
use crate::services::EncryptionKeyService;

mod commands;
pub mod crypto;
pub mod models;
mod services;
mod utils;
pub mod validation;

#[derive(Parser, Debug)]
#[command(
    name = "ramenv",
    version = "0.1.0",
    about = "Secure Environment Variable Manager"
)]
enum Cli {
    /// Display the menu of available ingredients (providers)
    Menu,
    /// Initialize ramenv (creates workspace + vault if no target specified)
    ///
    /// Single repo: `ramenv init` (creates all files in current dir)
    /// Monorepo: `ramenv init workspace` at root, then `ramenv init service` in each service
    Init {
        /// Target to initialize: workspace (keys + metadata) or service (vault only)
        #[command(subcommand)]
        target: Option<InitTarget>,
        #[arg(long, value_enum)]
        ingredient: Option<Provider>,
    },
    /// Move the existing secrets from the .env file into the vault file
    Onboard(OnboardArgs),
    /// Create a new environment
    CreateEnv(CreateEnvArgs),
    /// Remove an environment
    RemoveEnv(RemoveEnvArgs),
    /// Securely add or update a value directly inside the vault file
    Set(SetArgs),
    /// Delete a value from the vault
    Delete(DeleteArgs),
    /// Print the decrypted secrets to stdout (useful for debugging)
    List(ListArgs),
    /// Validate the encrypted variables against a schema to catch typos/missing keys
    Validate(ValidateArgs),
    /// Diff two environments and show the differences
    Diff(DiffArgs),
    /// Decrypt secrets in memory and execute an application process
    Run(RunArgs),
    /// Rotate the master encryption key and re-encrypt the file
    Rotate(RotateArgs),
}

#[derive(Subcommand, Debug)]
enum InitTarget {
    /// Initialize workspace (.ramenv.workspace.toml + .ramenv.keys)
    /// Use at monorepo root - keys are shared by all services
    Workspace {
        #[arg(long, value_enum)]
        ingredient: Option<Provider>,
    },
    /// Initialize service vault (.ramenv.vault.toml)
    /// Use in each service dir - stores service-specific encrypted secrets
    Service,
}

#[derive(Args, Debug)]
struct OnboardArgs {
    /// Environment from which to inject variables to the environment
    env: String,
}

#[derive(Args, Debug)]
struct CreateEnvArgs {
    /// Name of the environment to create
    env: String,
}

#[derive(Args, Debug)]
struct RemoveEnvArgs {
    /// Name of the environment to remove
    env: String,
}

#[derive(Args, Debug)]
struct SetArgs {
    /// Environment to set the variable in
    env: String,
    /// Name of the environment variable to set
    key: String,
    /// Set the value as plaintext (default: false)
    #[arg(long, default_value_t = false)]
    plaintext: bool,
}

#[derive(Args, Debug)]
struct DeleteArgs {
    /// Environment to delete the variable from
    env: String,
    /// Name of the environment variable to delete
    key: String,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Environment from which to inject variables to the environment
    env: String,
    /// Reveal the decrypted values of the secrets (default: false)
    #[arg(long, default_value_t = false)]
    reveal: bool,
}

#[derive(Args, Debug)]
struct ValidateArgs {
    /// Environment from which to inject variables to the environment
    env: Option<String>,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Environment to diff
    env1: String,
    /// Environment to diff
    env2: String,
    /// Reveal the decrypted values of the secrets (default: false)
    #[arg(long, default_value_t = false)]
    reveal: bool,
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Environment from which to inject variables to the environment
    env: String,
    /// Command to run after injecting variables
    command: Vec<String>,
}

#[derive(Args, Debug)]
struct RotateArgs {
    /// Environment to rotate
    env: String,
}

pub fn run_cli() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let current_working_path = std::env::current_dir().unwrap_or_else(|e| {
        error!("failed to get current working env {}", e);
        exit(1);
    });

    let cli = Cli::parse();
    let result = match cli {
        Cli::Menu => commands::menu_command(),
        Cli::Init { target, ingredient } => {
            commands::init_command(&current_working_path, target, ingredient)
        }
        Cli::Onboard(args) => {
            let (encryption_key_service, mut vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::on_board_command(
                &current_working_path,
                &args.env,
                &encryption_key_service,
                &mut vault_service,
            )
        }
        Cli::CreateEnv(args) => {
            let (mut encryption_key_service, mut vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::create_env_command(&args.env, &mut encryption_key_service, &mut vault_service)
        }
        Cli::RemoveEnv(args) => {
            let (mut encryption_key_service, mut vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::remove_env_command(&args.env, &mut encryption_key_service, &mut vault_service)
        }
        Cli::Set(args) => {
            let (encryption_key_service, mut vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::set_command(
                &args.env,
                &args.key,
                args.plaintext,
                &encryption_key_service,
                &mut vault_service,
            )
        }
        Cli::Delete(args) => {
            let (_, mut vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::delete_command(&args.env, &args.key, &mut vault_service)
        }
        Cli::List(args) => {
            let (encryption_key_service, vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::list_command(
                &args.env,
                args.reveal,
                &encryption_key_service,
                &vault_service,
            )
        }
        Cli::Validate(args) => {
            let (encryption_key_service, vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::validate_command(args.env, &encryption_key_service, &vault_service)
        }
        Cli::Diff(args) => {
            let (encryption_key_service, vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::diff_command(
                &args.env1,
                &args.env2,
                args.reveal,
                &encryption_key_service,
                &vault_service,
            )
        }
        Cli::Run(args) => {
            let (encryption_key_service, vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::run_command(
                &args.env,
                &args.command,
                &encryption_key_service,
                &vault_service,
            )
        }
        Cli::Rotate(args) => {
            let (mut encryption_key_service, mut vault_service) =
                initialize_services(&current_working_path).unwrap_or_else(|err| {
                    error!("failed to initialize ramenv: {}", err);
                    exit(1);
                });

            commands::rotate_command(&args.env, &mut encryption_key_service, &mut vault_service)
        }
    };

    if let Err(e) = result {
        error!("ramenv command failed with error:\n{:?}", e);
        exit(1);
    }
}

fn initialize_services(
    current_working_path: &Path,
) -> Result<(
    impl services::EncryptionKeyService,
    impl services::VaultService,
)> {
    let workspace_registry = services::WorkspaceRegistry::new(current_working_path)?;
    let encryption_key_service =
        services::LocalEncryptionKeyService::new(&workspace_registry.get_workspace_root())?;

    if let Some(vault_path) = current_working_path
        .strip_prefix(workspace_registry.get_workspace_root())?
        .to_str()
        .map(|s| if s.is_empty() { "/" } else { s })
    {
        let vault_signature_key = encryption_key_service.vault_signature_key(vault_path)?;
        let vault_registry =
            services::VaultRegistry::new(current_working_path, vault_signature_key)?;

        return Ok((encryption_key_service, vault_registry));
    }

    anyhow::bail!("failed to initialize vault registry");
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::services::{EncryptionKeyService, VaultService};

    struct TempDir(PathBuf);

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    impl TempDir {
        fn new() -> Self {
            let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("ramenv-lib-unit-{}-{unique}", std::process::id()));
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
    fn initializes_services_for_single_repository() {
        let root = TempDir::new();
        commands::init_command(&root.0, None, None).unwrap();
        let (keys, vault) = initialize_services(&root.0).unwrap();
        assert_eq!(keys.env_key("development").unwrap().len(), 64);
        assert!(vault.env_vault("development").is_ok());
    }

    #[test]
    fn initializes_services_for_nested_monorepo_vault() {
        let root = TempDir::new();
        commands::init_command(
            &root.0,
            Some(InitTarget::Workspace { ingredient: None }),
            None,
        )
        .unwrap();
        let service = root.0.join("services/api");
        std::fs::create_dir_all(&service).unwrap();
        commands::init_command(&service, Some(InitTarget::Service), None).unwrap();
        let (keys, vault) = initialize_services(&service).unwrap();
        assert!(keys.vault_signature_key("services/api").is_ok());
        assert!(vault.env_vault("production").is_ok());
    }

    #[test]
    fn service_initialization_rejects_missing_workspace() {
        let root = TempDir::new();
        assert!(initialize_services(&root.0).is_err());
    }
}
