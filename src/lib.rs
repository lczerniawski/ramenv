use std::path::Path;
use std::process::exit;

use anyhow::Context;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use env_logger::Env;
use log::error;
use services::WorkspaceService;
use std::io::IsTerminal;
use std::path::Component;

use crate::models::Provider;
use crate::services::EncryptionKeyService;

mod azure_auth;
mod commands;
pub mod crypto;
pub mod models;
mod services;
mod utils;
pub mod validation;

#[derive(Parser, Debug)]
#[command(
    name = "ramenv",
    version,
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
    /// Remove an environment from every registered vault in the workspace
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
    /// Rotate the shared encryption key and re-encrypt every registered workspace vault
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
    /// Confirm removal from all affected workspace vaults without prompting
    #[arg(short = 'y', long)]
    yes: bool,
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
    /// Confirm rotation across all affected workspace vaults without prompting
    #[arg(short = 'y', long)]
    yes: bool,
}

pub async fn run_cli() {
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
            commands::init_command(&current_working_path, target, ingredient).await
        }
        command => execute_runtime_command(command, &current_working_path).await,
    };

    if let Err(e) = result {
        error!("ramenv command failed with error:\n{:?}", e);
        exit(1);
    }
}

async fn execute_runtime_command(command: Cli, current_working_path: &Path) -> Result<()> {
    let workspace_registry = services::WorkspaceRegistry::load(current_working_path)?;
    let root = workspace_registry.get_workspace_root();

    match workspace_registry.get_provider() {
        models::Provider::Local => {
            let store = services::LocalKeyStore::new(&root);
            execute_with_store(command, current_working_path, workspace_registry, store).await
        }
        models::Provider::Azure => {
            let credential = azure_auth::azure_credential().await?;
            let store = services::AzureKeyStore::new(&root, credential);
            execute_with_store(command, current_working_path, workspace_registry, store).await
        }
        models::Provider::Aws => {
            let store = services::AwsKeyStore::new(&root).await;
            execute_with_store(command, current_working_path, workspace_registry, store).await
        }
        models::Provider::Google => {
            let store = services::GoogleKeyStore::new(&root).await?;
            execute_with_store(command, current_working_path, workspace_registry, store).await
        }
    }
}

async fn execute_with_store<S: services::KeyStore>(
    command: Cli,
    current_working_path: &Path,
    workspace_registry: services::WorkspaceRegistry,
    store: S,
) -> Result<()> {
    let mut key_service = services::KeyService::from_store(store).await?;
    let root = workspace_registry.get_workspace_root();
    if matches!(command, Cli::Rotate(_) | Cli::RemoveEnv(_)) {
        let mut vaults = load_workspace_vaults(&root, &key_service)?;
        let (action, environment, yes) = match &command {
            Cli::Rotate(args) => ("rotate", args.env.as_str(), args.yes),
            Cli::RemoveEnv(args) => ("remove-env", args.env.as_str(), args.yes),
            _ => unreachable!(),
        };
        key_service.env_key(environment)?;
        let affected: Vec<_> = key_service
            .vault_names()
            .zip(&vaults)
            .filter(|(_, vault)| services::VaultService::env_vault(*vault, environment).is_ok())
            .map(|(name, _)| name)
            .collect();
        confirm_workspace_change(
            action,
            environment,
            yes,
            vaults.len(),
            &affected,
            prompt_workspace_confirmation,
        )?;
        return match command {
            Cli::Rotate(args) => {
                commands::rotate_command(
                    &args.env,
                    &mut key_service,
                    &mut vaults,
                    &workspace_registry,
                )
                .await
            }
            Cli::RemoveEnv(args) => {
                commands::remove_env_command(
                    &args.env,
                    &mut key_service,
                    &mut vaults,
                    &workspace_registry,
                )
                .await
            }
            _ => unreachable!(),
        };
    }
    let vault_path = current_working_path
        .strip_prefix(&root)?
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid vault path"))?;
    let vault_path = if vault_path.is_empty() {
        "/"
    } else {
        vault_path
    };
    let vault_signature_key = key_service.vault_signature_key(vault_path)?;
    let mut vault_registry =
        services::VaultRegistry::load(current_working_path, vault_signature_key)?;

    match command {
        Cli::Onboard(args) => commands::on_board_command(
            current_working_path,
            &args.env,
            &key_service,
            &mut vault_registry,
        ),
        Cli::CreateEnv(args) => {
            commands::create_env_command(
                &args.env,
                &mut key_service,
                &mut vault_registry,
                &workspace_registry,
            )
            .await
        }
        Cli::Set(args) => commands::set_command(
            &args.env,
            &args.key,
            args.plaintext,
            &key_service,
            &mut vault_registry,
        ),
        Cli::Delete(args) => commands::delete_command(&args.env, &args.key, &mut vault_registry),
        Cli::List(args) => {
            commands::list_command(&args.env, args.reveal, &key_service, &vault_registry)
        }
        Cli::Validate(args) => commands::validate_command(args.env, &key_service, &vault_registry),
        Cli::Diff(args) => commands::diff_command(
            &args.env1,
            &args.env2,
            args.reveal,
            &key_service,
            &vault_registry,
        ),
        Cli::Run(args) => {
            commands::run_command(&args.env, &args.command, &key_service, &vault_registry)
        }
        Cli::Menu | Cli::Init { .. } | Cli::Rotate(_) | Cli::RemoveEnv(_) => {
            unreachable!("handled before loading the current vault")
        }
    }
}

fn confirm_workspace_change(
    action: &str,
    environment: &str,
    yes: bool,
    registered_count: usize,
    affected: &[&str],
    prompt: impl FnOnce(&str) -> Result<bool>,
) -> Result<()> {
    if yes || registered_count <= 1 || affected.is_empty() {
        return Ok(());
    }

    let scope = match action {
        "remove-env" => format!(
            "Remove environment '{environment}' from all {} affected workspace vault(s) and delete its shared encryption key?",
            affected.len()
        ),
        "rotate" => format!(
            "Rotate the shared encryption key for environment '{environment}' and re-encrypt all {} affected workspace vault(s)?",
            affected.len()
        ),
        _ => unreachable!("only workspace mutations require confirmation"),
    };
    println!("{scope}\nAffected vaults:");
    for name in affected {
        println!("  - {name}");
    }
    if !prompt("Proceed with this workspace-wide change?")? {
        anyhow::bail!("operation cancelled; no changes were made");
    }
    Ok(())
}

fn prompt_workspace_confirmation(message: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        anyhow::bail!(
            "workspace-wide changes require confirmation; rerun with --yes (or -y) for non-interactive use"
        );
    }
    Ok(inquire::Confirm::new(message)
        .with_default(false)
        .prompt()?)
}

fn load_workspace_vaults<S: services::KeyStore>(
    root: &Path,
    keys: &services::KeyService<S>,
) -> Result<Vec<services::VaultRegistry>> {
    let root = root
        .canonicalize()
        .context("failed to locate workspace root")?;
    keys.vault_names()
        .map(|name| {
            let path = if name == "/" {
                root.to_path_buf()
            } else {
                let relative = Path::new(name);
                if relative.as_os_str().is_empty()
                    || !relative
                        .components()
                        .all(|part| matches!(part, Component::Normal(_)))
                {
                    anyhow::bail!("invalid registered vault path: {name}");
                }
                root.join(relative)
            };
            let canonical = path
                .canonicalize()
                .with_context(|| format!("failed to locate registered vault {name}"))?;
            if !canonical.starts_with(&root)
                || !canonical
                    .join(".ramenv.vault.toml")
                    .canonicalize()
                    .with_context(|| format!("failed to locate vault file for {name}"))?
                    .starts_with(&root)
            {
                anyhow::bail!("registered vault {name} is outside the workspace");
            }
            services::VaultRegistry::load(&canonical, keys.vault_signature_key(name)?)
                .with_context(|| format!("failed to load registered vault {name}"))
        })
        .collect()
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
    fn workspace_confirmation_requires_acceptance_and_propagates_prompt_errors() {
        for action in ["rotate", "remove-env"] {
            let affected = ["services/api", "services/web"];
            let accepted =
                confirm_workspace_change(action, "development", false, 3, &affected, |message| {
                    assert_eq!(message, "Proceed with this workspace-wide change?");
                    Ok(true)
                });
            assert!(accepted.is_ok());
            let declined =
                confirm_workspace_change(action, "development", false, 3, &affected, |_| Ok(false));
            assert_eq!(
                declined.unwrap_err().to_string(),
                "operation cancelled; no changes were made"
            );
            let interrupted =
                confirm_workspace_change(action, "development", false, 3, &affected, |_| {
                    anyhow::bail!("prompt interrupted")
                });
            assert_eq!(interrupted.unwrap_err().to_string(), "prompt interrupted");
        }
    }

    #[test]
    fn workspace_confirmation_is_skipped_only_for_explicit_consent_or_no_shared_scope() {
        for action in ["rotate", "remove-env"] {
            for (yes, registered, affected) in [
                (true, 3, vec!["services/api", "services/web"]),
                (false, 1, vec!["/"]),
                (false, 3, vec![]),
            ] {
                confirm_workspace_change(action, "development", yes, registered, &affected, |_| {
                    panic!("unexpected confirmation for yes={yes}, registered={registered}")
                })
                .unwrap();
            }
        }
    }

    #[test]
    fn workspace_mutations_accept_long_and_short_consent_flags() {
        for command in ["rotate", "remove-env"] {
            for flag in [None, Some("--yes"), Some("-y")] {
                let mut args = vec!["ramenv", command, "development"];
                if let Some(flag) = flag {
                    args.push(flag);
                }
                let parsed = Cli::try_parse_from(args).unwrap();
                let (environment, yes) = match parsed {
                    Cli::Rotate(args) => (args.env, args.yes),
                    Cli::RemoveEnv(args) => (args.env, args.yes),
                    _ => unreachable!(),
                };
                assert_eq!(environment, "development");
                assert_eq!(yes, flag.is_some());
            }
        }
    }

    #[tokio::test]
    async fn executes_runtime_command_for_single_repository() {
        let root = TempDir::new();
        commands::init_command(&root.0, None, None).await.unwrap();

        execute_runtime_command(
            Cli::List(ListArgs {
                env: "development".into(),
                reveal: false,
            }),
            &root.0,
        )
        .await
        .unwrap();

        let workspace = services::WorkspaceRegistry::load(&root.0).unwrap();
        let keys = services::KeyService::from_store(services::LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        let vault =
            services::VaultRegistry::load(&root.0, keys.vault_signature_key("/").unwrap()).unwrap();
        assert_eq!(keys.env_key("development").unwrap().len(), 64);
        assert!(vault.env_vault("development").is_ok());
        assert!(workspace.get_workspace_root().is_absolute());
    }

    #[tokio::test]
    async fn executes_runtime_command_for_nested_monorepo_vault() {
        let root = TempDir::new();
        commands::init_command(
            &root.0,
            Some(InitTarget::Workspace { ingredient: None }),
            None,
        )
        .await
        .unwrap();
        let service = root.0.join("services/api");
        std::fs::create_dir_all(&service).unwrap();
        commands::init_command(&service, Some(InitTarget::Service), None)
            .await
            .unwrap();

        execute_runtime_command(
            Cli::List(ListArgs {
                env: "production".into(),
                reveal: false,
            }),
            &service,
        )
        .await
        .unwrap();

        let workspace = services::WorkspaceRegistry::load(&service).unwrap();
        let keys = services::KeyService::from_store(services::LocalKeyStore::new(&root.0))
            .await
            .unwrap();
        let vault = services::VaultRegistry::load(
            &service,
            keys.vault_signature_key("services/api").unwrap(),
        )
        .unwrap();
        assert!(vault.env_vault("production").is_ok());
        assert!(workspace.get_workspace_root().is_absolute());
    }

    #[tokio::test]
    async fn runtime_command_rejects_missing_workspace() {
        let root = TempDir::new();
        assert!(
            execute_runtime_command(
                Cli::List(ListArgs {
                    env: "development".into(),
                    reveal: false,
                }),
                &root.0,
            )
            .await
            .is_err()
        );
    }
}
