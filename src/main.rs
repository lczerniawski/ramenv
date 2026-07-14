use std::process::exit;

use clap::{Args, Parser};
use env_logger::Env;
use log::error;

// TODO Key Provider to be installed as a plugin from cargo the same way it is done for pi agent harness
// TODO menu -> list of providers, ingredient -> type of provider

mod commands;
mod crypto;
mod models;
mod services;

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
    OnBoard(OnBoardArgs),
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
struct OnBoardArgs {
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
    env: String,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Environment to diff
    env1: String,
    /// Environment to diff against
    env2: String,
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Environment from which to inject variables to the environment
    env: String,
}

fn main() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let current_working_path = std::env::current_dir().unwrap_or_else(|e| {
        error!("failed to get current working env {}", e);
        exit(1);
    });

    let cli = Cli::parse();
    let result = match cli {
        Cli::Init => commands::init_command(&current_working_path),
        Cli::OnBoard(args) => {
            let encryption_key_service =
                services::LocalEncryptionKeyService::new(&current_working_path);
            let mut vault_registry = services::VaultRegistry::new(&current_working_path);

            commands::on_board_command(
                &current_working_path,
                &args.env,
                &encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::CreateEnv(args) => {
            let mut encryption_key_service =
                services::LocalEncryptionKeyService::new(&current_working_path);
            let mut vault_registry = services::VaultRegistry::new(&current_working_path);

            commands::create_env_command(
                &args.env,
                &mut encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::Set(args) => {
            let encryption_key_service =
                services::LocalEncryptionKeyService::new(&current_working_path);
            let mut vault_registry = services::VaultRegistry::new(&current_working_path);

            commands::set_command(
                &args.env,
                &args.key,
                &encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::List(args) => {
            let encryption_key_service =
                services::LocalEncryptionKeyService::new(&current_working_path);
            let vault_registry = services::VaultRegistry::new(&current_working_path);

            commands::list_command(
                &args.env,
                args.reveal,
                &encryption_key_service,
                &vault_registry,
            )
        }
        Cli::Validate(_) => todo!(),
        Cli::Diff(_) => todo!(),
        Cli::Run(_) => todo!(),
        Cli::Rotate => todo!(),
    };

    if let Err(e) = result {
        error!("ramenv command failed with error:\n{:?}", e);
        exit(1);
    }
}
