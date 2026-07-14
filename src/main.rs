use std::process::exit;

use clap::{Args, Parser};
use env_logger::Env;
use log::error;

// TODO Key Provider to be installed as a plugin from cargo the same way it is done for pi agent harness

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
    Get(GetArgs),
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
    /// Name of the environment variable to set
    #[arg(short, long)]
    key: String,
    /// Value of the environment variable to set
    #[arg(short, long)]
    value: String,
    /// Environment to set the variable in
    #[arg(short, long)]
    env: String,
}

#[derive(Args, Debug)]
struct GetArgs {
    /// Environment from which to inject variables to the environment
    env: String,
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

            commands::onboard_command(
                &current_working_path,
                &args.env,
                &encryption_key_service,
                &mut vault_registry,
            )
        }
        Cli::Set(_) => todo!(),
        Cli::Get(_) => todo!(),
        Cli::Validate(_) => todo!(),
        Cli::Diff(_) => todo!(),
        Cli::Run(_) => todo!(),
        Cli::Rotate => todo!(),
        Cli::CreateEnv(_) => todo!(),
    };

    if let Err(e) = result {
        error!("ramenv command failed with error:\n{:?}", e);
        exit(1);
    }
}
