use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use indexmap::IndexMap;
use ramenv::{
    crypto,
    models::{CanonicalVault, KeysFile, VaultFile, VaultMetadata, WorkspaceFile},
};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SIGNATURE_KEY_HEX: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let thread_id = format!("{:?}", std::thread::current().id());
        let clean_thread_id = thread_id
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();

        path.push(format!(
            "ramenv-run-{suffix}-{clean_thread_id}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create workspace");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ramenv"))
}

fn env_printer_bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_env_printer"))
}

fn run_execute(workspace: &Path, environment: &str, command_args: &[&str]) -> Output {
    let mut command = Command::new(bin_path());
    command.current_dir(workspace);
    command.args(["run", environment, "--"]);
    command.args(command_args);
    command.output().expect("run ramenv run")
}

fn write_workspace_file(workspace: &Path) {
    let workspace_file = WorkspaceFile::new("1".to_string(), "test-workspace".to_string());
    std::fs::write(
        workspace.join(".ramenv.workspace.toml"),
        toml::to_string(&workspace_file).expect("serialize workspace"),
    )
    .expect("write workspace file");
}

fn write_keys_file(workspace: &Path, keys: &[(&str, &str)]) {
    let mut signatures = IndexMap::new();
    signatures.insert("/".to_string(), SIGNATURE_KEY_HEX.to_string());

    let keys = KeysFile {
        keys: keys
            .iter()
            .map(|(environment, key)| ((*environment).to_string(), (*key).to_string()))
            .collect(),
        signatures,
    };

    std::fs::write(
        workspace.join(".ramenv.keys"),
        toml::to_string(&keys).expect("serialize keys"),
    )
    .expect("write keys file");
}

fn write_vault_file(workspace: &Path, environments: &[(&str, Vec<(&str, String)>)]) {
    let environments = environments
        .iter()
        .map(|(environment, entries)| {
            let values = entries
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone()))
                .collect::<IndexMap<_, _>>();
            ((*environment).to_string(), values)
        })
        .collect::<IndexMap<_, _>>();

    // Create canonical vault for signing
    let canonical_vault = CanonicalVault {
        environments: environments.clone(),
    };
    let canonical_vault_str =
        serde_json::to_string(&canonical_vault).expect("serialize canonical vault");
    let signature = crypto::generate_signature(&canonical_vault_str, SIGNATURE_KEY_HEX)
        .expect("generate signature");

    let metadata = VaultMetadata {
        signature,
        signature_version: "1".to_string(),
        signed_at: chrono::Utc::now().to_rfc3339(),
    };

    let vault = VaultFile {
        validation: IndexMap::new(),
        environments,
        metadata,
    };

    std::fs::write(
        workspace.join(".ramenv.vault.toml"),
        toml::to_string(&vault).expect("serialize vault"),
    )
    .expect("write vault file");
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn run_command_injects_decrypted_variables_into_subprocess() {
    let workspace = Workspace::new();

    let encrypted_secret = crypto::encrypt_value("super-secret-token", KEY_HEX).expect("encrypt");

    write_workspace_file(workspace.path());
    write_keys_file(workspace.path(), &[("development", KEY_HEX)]);
    write_vault_file(
        workspace.path(),
        &[(
            "development",
            vec![
                ("DATABASE_URL", "postgres://localhost:5432".to_string()),
                ("API_KEY", encrypted_secret),
            ],
        )],
    );

    let printer_bin = env_printer_bin_path();
    let printer_str = printer_bin.to_str().unwrap();

    let output = run_execute(
        workspace.path(),
        "development",
        &[printer_str, "DATABASE_URL", "API_KEY"],
    );

    assert!(
        output.status.success(),
        "Command failed: {:?}",
        stderr(&output)
    );

    let stdout_content = stdout(&output);
    assert!(
        stdout_content.contains("DATABASE_URL=postgres://localhost:5432"),
        "Missing or wrong DATABASE_URL in stdout: {stdout_content}"
    );
    assert!(
        stdout_content.contains("API_KEY=super-secret-token"),
        "Missing or wrong API_KEY in stdout: {stdout_content}"
    );
}

#[test]
fn run_command_fails_gracefully_when_binary_args_are_empty() {
    let workspace = Workspace::new();
    write_workspace_file(workspace.path());
    write_keys_file(workspace.path(), &[("production", KEY_HEX)]);
    write_vault_file(workspace.path(), &[("production", vec![])]);

    let output = run_execute(workspace.path(), "production", &[]);

    assert!(
        !output.status.success(),
        "Expected execution error on empty arguments"
    );
    assert!(
        stderr(&output).contains("No command arguments provided to run"),
        "Unexpected error output: {}",
        stderr(&output)
    );
}
