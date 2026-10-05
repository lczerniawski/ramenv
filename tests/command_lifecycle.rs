use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use indexmap::IndexMap;
use ramenv::{
    crypto,
    models::{CanonicalVault, KeysFile, Provider, VaultFile, VaultMetadata, WorkspaceFile},
    validation::{RuleType, ValidationRule},
};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SIGNING_KEY: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

struct Workspace(PathBuf);

static NEXT_WORKSPACE_ID: AtomicU64 = AtomicU64::new(0);

impl Workspace {
    fn new() -> Self {
        let unique = NEXT_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("ramenv-lifecycle-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ramenv"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed: {}",
        stderr(output)
    );
}

fn write_fixture(root: &Path, entries: IndexMap<String, String>) {
    std::fs::write(
        root.join(".ramenv.workspace.toml"),
        toml::to_string(&WorkspaceFile::new(
            "1".into(),
            "test".into(),
            Provider::Local,
        ))
        .unwrap(),
    )
    .unwrap();

    let keys = KeysFile {
        encryption_keys: IndexMap::from([("development".into(), KEY.into())]),
        signature_keys: IndexMap::from([("/".into(), SIGNING_KEY.into())]),
    };
    std::fs::write(root.join(".ramenv.keys"), toml::to_string(&keys).unwrap()).unwrap();

    let environments = IndexMap::from([("development".into(), entries)]);
    let canonical = serde_json::to_string(&CanonicalVault {
        environments: environments.clone(),
    })
    .unwrap();
    let validation = IndexMap::from([
        (
            "API_KEY".into(),
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: None,
                },
                true,
            ),
        ),
        (
            "PLAIN".into(),
            ValidationRule::new(
                RuleType::String {
                    min_len: None,
                    max_len: None,
                },
                true,
            ),
        ),
    ]);
    let vault = VaultFile {
        validation,
        environments,
        metadata: VaultMetadata {
            signature: crypto::generate_signature(&canonical, SIGNING_KEY).unwrap(),
            signature_version: "1".into(),
            signed_at: "2026-01-01T00:00:00Z".into(),
        },
    };
    std::fs::write(
        root.join(".ramenv.vault.toml"),
        toml::to_string(&vault).unwrap(),
    )
    .unwrap();
}

fn read_keys(root: &Path) -> KeysFile {
    toml::from_str(&std::fs::read_to_string(root.join(".ramenv.keys")).unwrap()).unwrap()
}

fn read_vault(root: &Path) -> VaultFile {
    toml::from_str(&std::fs::read_to_string(root.join(".ramenv.vault.toml")).unwrap()).unwrap()
}

fn assert_valid_signature(vault: &VaultFile, signing_key: &str) {
    let canonical = serde_json::to_string(&CanonicalVault {
        environments: vault.environments.clone(),
    })
    .unwrap();
    crypto::verify_signature(&canonical, &vault.metadata.signature, signing_key).unwrap();
}

#[test]
fn init_creates_a_complete_valid_workspace_and_is_idempotent() {
    let workspace = Workspace::new();
    assert_success(&run(&workspace.0, &["init"]));

    let gitignore = std::fs::read_to_string(workspace.0.join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|line| line == ".env"));
    assert!(gitignore.lines().any(|line| line == ".ramenv.keys"));
    let keys = read_keys(&workspace.0);
    assert_eq!(keys.encryption_keys.len(), 2);
    assert_eq!(keys.encryption_keys["development"].len(), 64);
    assert_eq!(keys.encryption_keys["production"].len(), 64);
    let workspace_file: WorkspaceFile = toml::from_str(
        &std::fs::read_to_string(workspace.0.join(".ramenv.workspace.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(workspace_file.schema_version, "1");
    assert_eq!(
        workspace_file.workspace_name,
        workspace.0.file_name().unwrap().to_string_lossy()
    );
    let vault = read_vault(&workspace.0);
    assert_eq!(vault.environments.len(), 2);
    assert_valid_signature(&vault, &keys.signature_keys["/"]);

    let original_keys = std::fs::read_to_string(workspace.0.join(".ramenv.keys")).unwrap();
    assert_success(&run(&workspace.0, &["init"]));
    assert_eq!(
        std::fs::read_to_string(workspace.0.join(".ramenv.keys")).unwrap(),
        original_keys
    );
    let gitignore_after = std::fs::read_to_string(workspace.0.join(".gitignore")).unwrap();
    assert_eq!(gitignore_after.matches(".ramenv.keys").count(), 1);
}

#[test]
fn workspace_and_service_init_support_a_nested_monorepo() {
    let workspace = Workspace::new();
    assert_success(&run(&workspace.0, &["init", "workspace"]));
    assert!(!workspace.0.join(".ramenv.vault.toml").exists());

    let service = workspace.0.join("services").join("api");
    std::fs::create_dir_all(&service).unwrap();
    assert_success(&run(&service, &["init", "service"]));
    assert!(service.join(".ramenv.vault.toml").exists());
    let keys = read_keys(&workspace.0);
    assert!(
        keys.signature_keys.contains_key("services/api"),
        "unexpected vault names: {:?}",
        keys.signature_keys.keys().collect::<Vec<_>>()
    );
    assert_valid_signature(&read_vault(&service), &keys.signature_keys["services/api"]);

    // Runtime lookup and workspace-wide loading must agree with the persisted name.
    assert_success(&run(&service, &["list", "development"]));
    assert_success(&run(&service, &["create-env", "staging"]));
    assert_success(&run(&workspace.0, &["rotate", "staging", "--yes"]));
    assert_valid_signature(&read_vault(&service), &keys.signature_keys["services/api"]);
    assert_success(&run(&workspace.0, &["remove-env", "staging", "--yes"]));
    assert!(
        !read_keys(&workspace.0)
            .encryption_keys
            .contains_key("staging")
    );
    assert!(!read_vault(&service).environments.contains_key("staging"));
}

#[test]
fn create_and_remove_env_update_both_files_and_reject_duplicates() {
    let workspace = Workspace::new();
    assert_success(&run(&workspace.0, &["init"]));
    assert_success(&run(&workspace.0, &["create-env", "staging"]));
    assert_eq!(read_keys(&workspace.0).encryption_keys["staging"].len(), 64);
    assert!(read_vault(&workspace.0).environments["staging"].is_empty());

    let duplicate = run(&workspace.0, &["create-env", "staging"]);
    assert!(!duplicate.status.success());
    assert!(stderr(&duplicate).contains("already exists"));

    assert_success(&run(&workspace.0, &["remove-env", "staging"]));
    assert!(
        !read_keys(&workspace.0)
            .encryption_keys
            .contains_key("staging")
    );
    assert!(
        !read_vault(&workspace.0)
            .environments
            .contains_key("staging")
    );
    let missing = run(&workspace.0, &["remove-env", "staging"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("does not exist"));
}

#[test]
fn list_masks_by_default_and_reveals_plaintext_on_request() {
    let workspace = Workspace::new();
    let encrypted = crypto::encrypt_value("super-secret-token", KEY).unwrap();
    write_fixture(
        &workspace.0,
        IndexMap::from([
            ("API_KEY".into(), encrypted),
            ("PLAIN".into(), "visible-value".into()),
        ]),
    );

    let masked = run(&workspace.0, &["list", "development"]);
    assert_success(&masked);
    let masked_stdout = stdout(&masked);
    assert!(masked_stdout.contains("supe••••oken"));
    assert!(masked_stdout.contains("visi••••alue"));
    assert!(!masked_stdout.contains("super-secret-token"));

    let revealed = run(&workspace.0, &["list", "development", "--reveal"]);
    assert_success(&revealed);
    assert!(stdout(&revealed).contains("super-secret-token"));
    assert!(stdout(&revealed).contains("visible-value"));
}

#[test]
fn delete_removes_the_value_and_its_validation_rule() {
    let workspace = Workspace::new();
    write_fixture(
        &workspace.0,
        IndexMap::from([
            ("API_KEY".into(), "value".into()),
            ("PLAIN".into(), "kept".into()),
        ]),
    );
    assert_success(&run(&workspace.0, &["delete", "development", "API_KEY"]));
    let vault = read_vault(&workspace.0);
    assert!(!vault.environments["development"].contains_key("API_KEY"));
    assert!(!vault.validation.contains_key("API_KEY"));
    assert_eq!(vault.environments["development"]["PLAIN"], "kept");
    assert_valid_signature(&vault, SIGNING_KEY);

    let missing = run(&workspace.0, &["delete", "development", "API_KEY"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("not found"));
}

#[test]
fn deleting_a_key_preserves_validation_in_other_environments() {
    let workspace = Workspace::new();
    write_fixture(
        &workspace.0,
        IndexMap::from([
            ("API_KEY".into(), "true".into()),
            ("PLAIN".into(), "kept".into()),
        ]),
    );
    let mut vault = read_vault(&workspace.0);
    vault.environments.insert(
        "production".into(),
        IndexMap::from([
            ("API_KEY".into(), "invalid-boolean".into()),
            ("PLAIN".into(), "kept".into()),
        ]),
    );
    vault.validation["API_KEY"] = ValidationRule::new(RuleType::Boolean, true);
    let mut keys = read_keys(&workspace.0);
    keys.encryption_keys.insert("production".into(), KEY.into());
    std::fs::write(
        workspace.0.join(".ramenv.keys"),
        toml::to_string(&keys).unwrap(),
    )
    .unwrap();
    let canonical = serde_json::to_string(&CanonicalVault {
        environments: vault.environments.clone(),
    })
    .unwrap();
    vault.metadata.signature = crypto::generate_signature(&canonical, SIGNING_KEY).unwrap();
    std::fs::write(
        workspace.0.join(".ramenv.vault.toml"),
        toml::to_string(&vault).unwrap(),
    )
    .unwrap();

    assert_success(&run(&workspace.0, &["delete", "development", "API_KEY"]));
    let after = read_vault(&workspace.0);
    assert!(!after.environments["development"].contains_key("API_KEY"));
    assert_eq!(
        after.environments["production"]["API_KEY"],
        "invalid-boolean"
    );
    assert!(matches!(
        after.validation["API_KEY"].rule_type,
        RuleType::Boolean
    ));
    assert_valid_signature(&after, SIGNING_KEY);
    let validation = run(&workspace.0, &["validate", "production"]);
    assert_eq!(validation.status.code(), Some(1));
    assert!(stderr(&validation).contains("Key 'API_KEY' must be a boolean"));
}

#[test]
fn rotate_reencrypts_secrets_but_preserves_plain_values() {
    let workspace = Workspace::new();
    let encrypted = crypto::encrypt_value("super-secret-token", KEY).unwrap();
    write_fixture(
        &workspace.0,
        IndexMap::from([
            ("API_KEY".into(), encrypted.clone()),
            ("PLAIN".into(), "unchanged".into()),
        ]),
    );

    assert_success(&run(&workspace.0, &["rotate", "development"]));
    let new_key = read_keys(&workspace.0).encryption_keys["development"].clone();
    let vault = read_vault(&workspace.0);
    let rotated = &vault.environments["development"]["API_KEY"];
    assert_ne!(new_key, KEY);
    assert_ne!(rotated, &encrypted);
    assert_eq!(
        crypto::decrypt_value(rotated, &new_key).unwrap(),
        "super-secret-token"
    );
    assert!(crypto::decrypt_value(rotated, KEY).is_err());
    assert_eq!(vault.environments["development"]["PLAIN"], "unchanged");
    assert_valid_signature(&vault, SIGNING_KEY);
}

#[test]
fn onboard_without_dotenv_is_a_successful_noop() {
    let workspace = Workspace::new();
    write_fixture(
        &workspace.0,
        IndexMap::from([("API_KEY".into(), "unchanged".into())]),
    );
    let before = std::fs::read_to_string(workspace.0.join(".ramenv.vault.toml")).unwrap();

    assert_success(&run(&workspace.0, &["onboard", "development"]));
    assert_eq!(
        std::fs::read_to_string(workspace.0.join(".ramenv.vault.toml")).unwrap(),
        before
    );
}

#[test]
fn commands_report_missing_or_tampered_workspace_state() {
    let workspace = Workspace::new();
    let missing = run(&workspace.0, &["list", "development"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("no ramenv workspace found"));

    write_fixture(
        &workspace.0,
        IndexMap::from([("API_KEY".into(), "value".into())]),
    );
    let mut vault = read_vault(&workspace.0);
    vault
        .environments
        .get_mut("development")
        .unwrap()
        .insert("TAMPERED".into(), "yes".into());
    std::fs::write(
        workspace.0.join(".ramenv.vault.toml"),
        toml::to_string(&vault).unwrap(),
    )
    .unwrap();
    let tampered = run(&workspace.0, &["list", "development"]);
    assert!(!tampered.status.success());
    assert!(stderr(&tampered).contains("failed to verify vault signature"));
}
