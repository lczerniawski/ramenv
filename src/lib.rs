use std::process::exit;

use clap::{Args, Parser};
use env_logger::Env;
use log::error;

// TODO Key Provider to be installed as a plugin from cargo the same way it is done for pi agent harness
// TODO menu -> list of providers, ingredient -> type of provider

mod commands;
pub mod crypto;
pub mod models;
mod services;
pub mod validation;

#[derive(Parser, Debug)]
#[command(
    name = "ramenv",
    version = "0.1.0",
    about = "Secure Environment Variable Manager"
)]
enum Cli {
    /// Initialize a new encrypted vault file in the repository
    Init,
    /// Move the existing secrets from the .env file into the encrypted vault file
    Onboard(OnboardArgs),
    /// Create a new environment
    CreateEnv(CreateEnvArgs),
    /// Securely add or update a secret directly inside the encrypted file
    Set(SetArgs),
    /// Print the decrypted secrets to stdout (useful for debugging)
    List(ListArgs),
    /// Validate the encrypted variables against a schema to catch typos/missing keys
    Validate(ValidateArgs),
    /// Diff two environments and show the differences
    Diff(DiffArgs),
    /// Decrypt secrets in memory and execute an application process
    Run(RunArgs),
    /// Rotate the master encryption key and re-encrypt the file
    Rotate,
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
struct SetArgs {
    /// Environment to set the variable in
    env: String,
    /// Name of the environment variable to set
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
        Cli::Init => commands::init_command(&current_working_path),
        Cli::Onboard(args) => {
            let encryption_key_service = services::LocalEncryptionKeyService::new(
                &current_working_path,
            )
            .unwrap_or_else(|err| {
                error!("failed to initilize encryption key service: {}", err);
                exit(1);
            });
            let mut vault_registry = services::VaultRegistry::new(&current_working_path)
                .unwrap_or_else(|err| {
                    error!("failed to initialize vault registry: {}", err);
                    exit(1);
                });

            commands::on_board_command(
                &current_working_path,
                &args.env,
                &encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::CreateEnv(args) => {
            let mut encryption_key_service = services::LocalEncryptionKeyService::new(
                &current_working_path,
            )
            .unwrap_or_else(|err| {
                error!("failed to initilize encryption key service: {}", err);
                exit(1);
            });
            let mut vault_registry = services::VaultRegistry::new(&current_working_path)
                .unwrap_or_else(|err| {
                    error!("failed to initialize vault registry: {}", err);
                    exit(1);
                });

            commands::create_env_command(
                &args.env,
                &mut encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::Set(args) => {
            let encryption_key_service = services::LocalEncryptionKeyService::new(
                &current_working_path,
            )
            .unwrap_or_else(|err| {
                error!("failed to initilize encryption key service: {}", err);
                exit(1);
            });
            let mut vault_registry = services::VaultRegistry::new(&current_working_path)
                .unwrap_or_else(|err| {
                    error!("failed to initialize vault registry: {}", err);
                    exit(1);
                });

            commands::set_command(
                &args.env,
                &args.key,
                &encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::List(args) => {
            let encryption_key_service = services::LocalEncryptionKeyService::new(
                &current_working_path,
            )
            .unwrap_or_else(|err| {
                error!("failed to initilize encryption key service: {}", err);
                exit(1);
            });
            let vault_registry = services::VaultRegistry::new(&current_working_path)
                .unwrap_or_else(|err| {
                    error!("failed to initialize vault registry: {}", err);
                    exit(1);
                });

            commands::list_command(
                &args.env,
                args.reveal,
                &encryption_key_service,
                &vault_registry,
            )
        }
        Cli::Validate(args) => {
            let encryption_key_service = services::LocalEncryptionKeyService::new(
                &current_working_path,
            )
            .unwrap_or_else(|err| {
                error!("failed to initilize encryption key service: {}", err);
                exit(1);
            });
            let vault_registry = services::VaultRegistry::new(&current_working_path)
                .unwrap_or_else(|err| {
                    error!("failed to initialize vault registry: {}", err);
                    exit(1);
                });

            commands::validate_command(args.env, &encryption_key_service, &vault_registry)
        }
        Cli::Diff(args) => {
            let encryption_key_service = services::LocalEncryptionKeyService::new(
                &current_working_path,
            )
            .unwrap_or_else(|err| {
                error!("failed to initilize encryption key service: {}", err);
                exit(1);
            });
            let vault_registry = services::VaultRegistry::new(&current_working_path)
                .unwrap_or_else(|err| {
                    error!("failed to initialize vault registry: {}", err);
                    exit(1);
                });

            commands::diff_command(
                &args.env1,
                &args.env2,
                args.reveal,
                &encryption_key_service,
                &vault_registry,
            )
        }
        Cli::Run(_) => todo!(),
        Cli::Rotate => todo!(),
    };

    if let Err(e) = result {
        error!("ramenv command failed with error:\n{:?}", e);
        exit(1);
    }
}
