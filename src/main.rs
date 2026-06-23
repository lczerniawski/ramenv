use clap::{Args, Parser};
use env_logger::Env;
use log::error;

mod commands;

#[derive(Parser, Debug)]
#[command(
    name = "vext",
    version = "1.0",
    about = "Secure Environment Variable Manager"
)]
enum Cli {
    /// Initialize a new secure local vault and setup git ignore
    Init,
    /// Set an environment variable in the vault and save it to the local .env file
    Set(SetArgs),
    /// Diff two environments and show the differences
    Diff(DiffArgs),
    /// Save back the local .env file into the vault
    Save(SaveArgs),
    /// Load environment variables from the vault into the local .env file
    Load(LoadArgs),
    /// Inject environment variables from the vault into the local environment, without swapping
    Inject(InjectArgs),
    // TODO How to add new develoepr
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
struct DiffArgs {
    /// Environment to diff
    env1: String,
    /// Environment to diff against
    env2: String,
}

#[derive(Args, Debug)]
struct SaveArgs {
    /// Environment to save
    #[arg(short, long)]
    env: String,
}

#[derive(Args, Debug)]
struct LoadArgs {
    /// Environment to load
    #[arg(short, long)]
    env: String,
}

#[derive(Args, Debug)]
struct InjectArgs {
    /// Environment from which to inject variables to the environment
    env: String,
}

fn main() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let cli = Cli::parse();
    match cli {
        Cli::Init => commands::init_command()
            .unwrap_or_else(|e| error!("vext command failed with error: {}", e)),
        Cli::Set(_) => {}
        Cli::Diff(_) => {}
        Cli::Save(_) => {}
        Cli::Load(_) => {}
        Cli::Inject(_) => {}
    }
}
