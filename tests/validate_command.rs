use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use indexmap::IndexMap;
use ramenv::{
    crypto,
    models::{KeysFile, VaultFile},
    validation::{RuleType, ValidationRule},
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

fn run_validate(workspace: &Path, environment: Option<&str>) -> Output {
    let mut command = Command::new(bin_path());
    command.current_dir(workspace);
    if let Some(env) = environment {
        command.args(["validate", env]);
    } else {
        command.arg("validate");
    }
    command.output().expect("run ramenv validate")
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

fn write_vault_file(
    workspace: &Path,
    validations: &[(&str, ValidationRule)],
    environments: &[(&str, Vec<(&str, String)>)],
) {
    let validation = validations
        .iter()
        .map(|(key, rule)| ((*key).to_string(), rule.clone()))
        .collect::<IndexMap<_, _>>();

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
        validation,
        environments,
    };

    std::fs::write(
        workspace.join(".ramenv.vault.toml"),
        toml::to_string(&vault).expect("serialize vault"),
    )
    .expect("write vault file");
}

fn assert_success(output: &Output) {
    assert!(output.status.success(), "expected success, got {output:?}");
}

fn assert_failure(output: &Output) {
    assert!(!output.status.success(), "expected failure, got {output:?}");
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1, got {output:?}"
    );
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run_validate_case(
    environment: Option<&str>,
    keys: Vec<(&str, &str)>,
    validations: Vec<(&str, ValidationRule)>,
    vaults: Vec<(&str, Vec<(&str, String)>)>,
    expect_success: bool,
    stderr_fragment: Option<&str>,
) {
    let workspace = Workspace::new();
    write_keys_file(workspace.path(), &keys);
    write_vault_file(workspace.path(), &validations, &vaults);

    let output = run_validate(workspace.path(), environment);

    if expect_success {
        assert_success(&output);
    } else {
        assert_failure(&output);
    }

    let stderr = stderr(&output);
    match stderr_fragment {
        Some(fragment) => assert!(
            stderr.contains(fragment),
            "expected stderr containing `{fragment}`, got `{stderr}`"
        ),
        None => assert!(stderr.is_empty(), "unexpected stderr `{stderr}`"),
    }
}

#[test]
fn validate_command_succeeds_for_selected_env() {
    let secret = crypto::encrypt_value("secret-value", KEY_HEX).expect("encrypt");
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(4),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![
            ("development", vec![("API_KEY", secret.clone())]),
            ("production", vec![("API_KEY", secret)]),
        ],
        true,
        None,
    );
}

#[test]
fn validate_command_succeeds_for_all_envs() {
    let secret = crypto::encrypt_value("secret-value", KEY_HEX).expect("encrypt");
    run_validate_case(
        None,
        vec![("development", KEY_HEX), ("production", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(4),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![
            ("development", vec![("API_KEY", secret.clone())]),
            ("production", vec![("API_KEY", secret)]),
        ],
        true,
        None,
    );
}

#[test]
fn validate_command_decrypts_encrypted_secret() {
    let encrypted_secret = crypto::encrypt_value("super-secret", KEY_HEX).expect("encrypt");
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(4),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", encrypted_secret)])],
        true,
        None,
    );
}

#[test]
fn validate_command_uses_plain_value_when_no_secret_prefix() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(4),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", "plain-value".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_missing_required_key() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "REQUIRED_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: None,
                },
                true,
            ),
        )],
        vec![("development", vec![])],
        false,
        Some("Key 'REQUIRED_KEY' is required but not present in the vault"),
    );
}

#[test]
fn validate_command_logs_short_string() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(4),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", "abc".to_string())])],
        false,
        Some("[development] Key 'API_KEY' is too short (min: 4)"),
    );
}

#[test]
fn validate_command_accepts_string_at_min_length() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(4),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", "abcd".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_string_above_max_length() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: Some(4),
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", "abcde".to_string())])],
        false,
        Some("[development] Key 'API_KEY' is too long (max: 4)"),
    );
}

#[test]
fn validate_command_accepts_string_at_max_length() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: Some(4),
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", "abcd".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_integer_failure() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "PORT",
            ValidationRule::new(
                RuleType::Integer {
                    min_value: None,
                    max_value: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("PORT", "not-an-integer".to_string())])],
        false,
        Some("[development] Key 'PORT must be an integer, got: 'not-an-integer'"),
    );
}

#[test]
fn validate_command_accepts_integer_at_min_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "PORT",
            ValidationRule::new(
                RuleType::Integer {
                    min_value: Some(10),
                    max_value: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("PORT", "10".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_integer_below_min_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "PORT",
            ValidationRule::new(
                RuleType::Integer {
                    min_value: Some(10),
                    max_value: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("PORT", "9".to_string())])],
        false,
        Some("[development] Key 'PORT' value 9 is too small (min: 10)"),
    );
}

#[test]
fn validate_command_accepts_integer_at_max_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "PORT",
            ValidationRule::new(
                RuleType::Integer {
                    min_value: None,
                    max_value: Some(10),
                },
                true,
            ),
        )],
        vec![("development", vec![("PORT", "10".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_integer_above_max_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "PORT",
            ValidationRule::new(
                RuleType::Integer {
                    min_value: None,
                    max_value: Some(10),
                },
                true,
            ),
        )],
        vec![("development", vec![("PORT", "11".to_string())])],
        false,
        Some("[development] Key 'PORT' value 11 is too large (max: 10)"),
    );
}

#[test]
fn validate_command_logs_float_failure() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "RATE",
            ValidationRule::new(
                RuleType::Float {
                    min_value: None,
                    max_value: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("RATE", "not-a-float".to_string())])],
        false,
        Some("[development] Key 'RATE' must be a float, got: 'not-a-float'"),
    );
}

#[test]
fn validate_command_accepts_float_at_min_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "RATE",
            ValidationRule::new(
                RuleType::Float {
                    min_value: Some(1.5),
                    max_value: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("RATE", "1.5".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_float_below_min_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "RATE",
            ValidationRule::new(
                RuleType::Float {
                    min_value: Some(1.5),
                    max_value: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("RATE", "1.4".to_string())])],
        false,
        Some("[development] Key 'RATE' value 1.4 is too small (min: 1.5)"),
    );
}

#[test]
fn validate_command_accepts_float_at_max_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "RATE",
            ValidationRule::new(
                RuleType::Float {
                    min_value: None,
                    max_value: Some(2.5),
                },
                true,
            ),
        )],
        vec![("development", vec![("RATE", "2.5".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_float_above_max_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "RATE",
            ValidationRule::new(
                RuleType::Float {
                    min_value: None,
                    max_value: Some(2.5),
                },
                true,
            ),
        )],
        vec![("development", vec![("RATE", "2.6".to_string())])],
        false,
        Some("[development] Key 'RATE' value 2.6 is too large (max: 2.5)"),
    );
}

#[test]
fn validate_command_logs_boolean_failure() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("FLAG", ValidationRule::new(RuleType::Boolean, true))],
        vec![("development", vec![("FLAG", "not-bool".to_string())])],
        false,
        Some("[development] Key 'FLAG' must be a boolean (true/false), got: 'not-bool'"),
    );
}

#[test]
fn validate_command_accepts_boolean_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("FLAG", ValidationRule::new(RuleType::Boolean, true))],
        vec![("development", vec![("FLAG", "true".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_port_failure_when_0() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("PORT", ValidationRule::new(RuleType::Port, true))],
        vec![("development", vec![("PORT", "0".to_string())])],
        false,
        Some("[development] Key 'PORT' port cannot be 0"),
    );
}

#[test]
fn validate_command_logs_port_failure_when_above_65535() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("PORT", ValidationRule::new(RuleType::Port, true))],
        vec![("development", vec![("PORT", "65536".to_string())])],
        false,
        Some("[development] Key 'PORT' must be a valid port number (0-65535), got: '65536'"),
    );
}

#[test]
fn validate_command_accepts_port_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("PORT", ValidationRule::new(RuleType::Port, true))],
        vec![("development", vec![("PORT", "8080".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_uri_failure() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("SITE_URL", ValidationRule::new(RuleType::Uri, true))],
        vec![("development", vec![("SITE_URL", "not-a-url".to_string())])],
        false,
        Some("[development] Key 'SITE_URL' must be a valid URI/URL, got: 'not-a-url'"),
    );
}

#[test]
fn validate_command_accepts_uri_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("SITE_URL", ValidationRule::new(RuleType::Uri, true))],
        vec![(
            "development",
            vec![("SITE_URL", "https://example.com".to_string())],
        )],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_ip_failure() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("HOST", ValidationRule::new(RuleType::IP, true))],
        vec![("development", vec![("HOST", "not-an-ip".to_string())])],
        false,
        Some("[development] Key 'HOST' must be a valid IP address, got: 'not-an-ip'"),
    );
}

#[test]
fn validate_command_accepts_ip_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("HOST", ValidationRule::new(RuleType::IP, true))],
        vec![("development", vec![("HOST", "127.0.0.1".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_email_failure() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("EMAIL", ValidationRule::new(RuleType::Email, true))],
        vec![(
            "development",
            vec![("EMAIL", "missing-at-symbol".to_string())],
        )],
        false,
        Some("[development] Key 'EMAIL' must be a valid email address, got: 'missing-at-symbol'"),
    );
}

#[test]
fn validate_command_accepts_email_value() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![("EMAIL", ValidationRule::new(RuleType::Email, true))],
        vec![(
            "development",
            vec![("EMAIL", "user@example.com".to_string())],
        )],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_regex_mismatch() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "CODE",
            ValidationRule::new(
                RuleType::Regex {
                    pattern: r"^[A-Z]{4}$".to_string(),
                },
                true,
            ),
        )],
        vec![("development", vec![("CODE", "123".to_string())])],
        false,
        Some("[development] Key 'CODE' does not match the required pattern, got: '123'"),
    );
}

#[test]
fn validate_command_accepts_regex_match() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "CODE",
            ValidationRule::new(
                RuleType::Regex {
                    pattern: r"^[A-Z]{4}$".to_string(),
                },
                true,
            ),
        )],
        vec![("development", vec![("CODE", "ABCD".to_string())])],
        true,
        None,
    );
}

#[test]
fn validate_command_logs_invalid_regex_pattern() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "CODE",
            ValidationRule::new(
                RuleType::Regex {
                    pattern: "[".to_string(),
                },
                true,
            ),
        )],
        vec![("development", vec![("CODE", "anything".to_string())])],
        false,
        Some("[development] Key 'CODE' has an invalid regex pattern: '['"),
    );
}

#[test]
fn validate_command_errors_when_selected_env_key_is_missing() {
    run_validate_case(
        Some("development"),
        vec![],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: None,
                },
                true,
            ),
        )],
        vec![("development", vec![("API_KEY", "value".to_string())])],
        false,
        Some("key for development environment does not exist"),
    );
}

#[test]
fn validate_command_errors_when_selected_env_vault_is_missing() {
    run_validate_case(
        Some("development"),
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: None,
                },
                true,
            ),
        )],
        vec![],
        false,
        Some("vault for development environment does not exist"),
    );
}

#[test]
fn validate_command_errors_when_all_envs_missing_a_key() {
    run_validate_case(
        None,
        vec![("development", KEY_HEX)],
        vec![(
            "API_KEY",
            ValidationRule::new(
                RuleType::String {
                    min_len: Some(3),
                    max_len: None,
                },
                true,
            ),
        )],
        vec![
            ("development", vec![("API_KEY", "shared".to_string())]),
            ("production", vec![("API_KEY", "shared".to_string())]),
        ],
        false,
        Some("key for production environment does not exist"),
    );
}

#[test]
fn validate_command_reports_missing_cli_files() {
    let workspace = Workspace::new();
    let output = run_validate(workspace.path(), Some("development"));
    assert_failure(&output);
    assert!(
        stderr(&output).contains("Keys file does not exist"),
        "missing keys file stderr: {}",
        stderr(&output)
    );

    write_keys_file(workspace.path(), &[("development", KEY_HEX)]);
    let output = run_validate(workspace.path(), Some("development"));
    assert_failure(&output);
    assert!(
        stderr(&output).contains("Vault file does not exist"),
        "missing vault file stderr: {}",
        stderr(&output)
    );
}
