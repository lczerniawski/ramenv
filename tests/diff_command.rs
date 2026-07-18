use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use indexmap::IndexMap;
use ramenv::{
    crypto,
    models::{KeysFile, VaultFile},
};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

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
            "ramenv-validate-{suffix}-{clean_thread_id}-{}",
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

fn run_diff(workspace: &Path, env1: &str, env2: &str, reveal: bool) -> Output {
    let mut command = Command::new(bin_path());
    command.current_dir(workspace);
    command.args(["diff", env1, env2]);
    if reveal {
        command.arg("--reveal");
    }
    command.output().expect("run ramenv diff")
}

fn write_keys_file(workspace: &Path, keys: &[(&str, &str)]) {
    let keys = KeysFile {
        keys: keys
            .iter()
            .map(|(environment, key)| ((*environment).to_string(), (*key).to_string()))
            .collect(),
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

    let vault = VaultFile {
        name: "ramenv".to_string(),
        version: "1.0.0".to_string(),
        validation: IndexMap::new(), // Diff command doesn't evaluate schema rules
        environments,
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

fn run_diff_case(
    env1: &str,
    env2: &str,
    reveal: bool,
    keys: Vec<(&str, &str)>,
    vaults: Vec<(&str, Vec<(&str, String)>)>,
    expect_success: bool,
    expected_fragment: Option<&str>,
) {
    let workspace = Workspace::new();
    write_keys_file(workspace.path(), &keys);
    write_vault_file(workspace.path(), &vaults);

    let output = run_diff(workspace.path(), env1, env2, reveal);

    if expect_success {
        assert!(output.status.success(), "expected success, got {output:?}");
        let stdout = stdout(&output);
        if let Some(fragment) = expected_fragment {
            assert!(
                stdout.contains(fragment),
                "expected stdout containing `{fragment}`, got `{stdout}`"
            );
        }
    } else {
        assert!(!output.status.success(), "expected failure, got {output:?}");
        let stderr = stderr(&output);
        if let Some(fragment) = expected_fragment {
            assert!(
                stderr.contains(fragment),
                "expected stderr containing `{fragment}`, got `{stderr}`"
            );
        }
    }
}

// --- Test Cases ---

#[test]
fn diff_command_empty_table_when_identical() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![
            ("development", vec![("API_KEY", "same-value".to_string())]),
            ("production", vec![("API_KEY", "same-value".to_string())]),
        ],
        true,
        Some("KEY"), // Still contains the table header but no diff rows
    );
}

#[test]
fn diff_command_detects_different_values_and_masks_them_by_default() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![
            (
                "development",
                vec![("SECRET_TOKEN", "dev-secret".to_string())],
            ),
            (
                "production",
                vec![("SECRET_TOKEN", "prod-secret".to_string())],
            ),
        ],
        true,
        Some("DIFFERENT"),
    );
}

#[test]
fn diff_command_reveals_secrets_with_flag() {
    run_diff_case(
        "development",
        "production",
        true,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![
            (
                "development",
                vec![("API_URL", "https://dev.local".to_string())],
            ),
            (
                "production",
                vec![("API_URL", "https://prod.live".to_string())],
            ),
        ],
        true,
        Some("https://dev.local"),
    );
}

#[test]
fn diff_command_handles_encrypted_secrets_correctly() {
    let encrypted_dev = crypto::encrypt_value("super-secret-dev", KEY_HEX).expect("encrypt");
    let encrypted_prod = crypto::encrypt_value("super-secret-prod", KEY_HEX).expect("encrypt");

    run_diff_case(
        "development",
        "production",
        true,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![
            ("development", vec![("DB_PASS", encrypted_dev)]),
            ("production", vec![("DB_PASS", encrypted_prod)]),
        ],
        true,
        Some("super-secret-dev"),
    );
}

#[test]
fn diff_command_reports_missing_in_env2() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![
            ("development", vec![("DEV_ONLY", "value".to_string())]),
            ("production", vec![]),
        ],
        true,
        Some("NOT FOUND IN production"),
    );
}

#[test]
fn diff_command_reports_missing_in_env1() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![
            ("development", vec![]),
            ("production", vec![("PROD_ONLY", "value".to_string())]),
        ],
        true,
        Some("NOT FOUND IN development"),
    );
}

#[test]
fn diff_command_errors_when_env1_key_is_missing() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("production", KEY_HEX)],
        vec![
            ("development", vec![("KEY", "val".to_string())]),
            ("production", vec![("KEY", "val".to_string())]),
        ],
        false,
        Some("key for development environment does not exist"),
    );
}

#[test]
fn diff_command_errors_when_env2_key_is_missing() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX)],
        vec![
            ("development", vec![("KEY", "val".to_string())]),
            ("production", vec![("KEY", "val".to_string())]),
        ],
        false,
        Some("key for production environment does not exist"),
    );
}

#[test]
fn diff_command_errors_when_env1_vault_is_missing() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![("production", vec![("KEY", "val".to_string())])],
        false,
        Some("vault for development environment does not exist"),
    );
}

#[test]
fn diff_command_errors_when_env2_vault_is_missing() {
    run_diff_case(
        "development",
        "production",
        false,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![("development", vec![("KEY", "val".to_string())])],
        false,
        Some("vault for production environment does not exist"),
    );
}
