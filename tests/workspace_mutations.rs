use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use indexmap::IndexMap;
use ramenv::{
    crypto,
    models::{CanonicalVault, KeysFile, VaultFile},
    validation::{RuleType, ValidationRule},
};

const SERVICES: [&str; 3] = ["services/api", "services/web", "services/worker"];
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ramenv-workspace-mutations-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        let workspace = Self(path);
        success(&run(&workspace.0, "init", &["workspace"]));
        for name in SERVICES {
            let service = workspace.0.join(name);
            std::fs::create_dir_all(&service).unwrap();
            success(&run(&service, "init", &["service"]));
        }
        let keys = read_keys(&workspace.0);
        for (index, name) in SERVICES.iter().enumerate() {
            let service = workspace.0.join(name);
            let mut vault = read_vault(&service);
            vault.validation.insert(
                "SECRET".into(),
                ValidationRule::new(
                    RuleType::String {
                        min_len: Some(1),
                        max_len: None,
                    },
                    true,
                ),
            );
            if index == 2 {
                vault.environments.shift_remove("development");
            } else {
                vault.environments.insert(
                    "development".into(),
                    IndexMap::from([
                        (
                            "SECRET".into(),
                            crypto::encrypt_value(
                                &format!("secret-{index}"),
                                &keys.encryption_keys["development"],
                            )
                            .unwrap(),
                        ),
                        ("PLAIN".into(), "unchanged".into()),
                    ]),
                );
            }
            vault.environments.insert(
                "production".into(),
                IndexMap::from([(
                    "SECRET".into(),
                    crypto::encrypt_value("production-secret", &keys.encryption_keys["production"])
                        .unwrap(),
                )]),
            );
            write_signed(&service, &mut vault, &keys.signature_keys[*name]);
        }
        workspace
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(cwd: &Path, command: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ramenv"))
        .current_dir(cwd)
        .arg(command)
        .args(args)
        .output()
        .unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn read_keys(root: &Path) -> KeysFile {
    toml::from_str(&std::fs::read_to_string(root.join(".ramenv.keys")).unwrap()).unwrap()
}

fn read_vault(service: &Path) -> VaultFile {
    toml::from_str(&std::fs::read_to_string(service.join(".ramenv.vault.toml")).unwrap()).unwrap()
}

fn canonical(vault: &VaultFile) -> String {
    serde_json::to_string(&CanonicalVault {
        environments: vault.environments.clone(),
    })
    .unwrap()
}

fn write_signed(service: &Path, vault: &mut VaultFile, key: &str) {
    vault.metadata.signature = crypto::generate_signature(&canonical(vault), key).unwrap();
    std::fs::write(
        service.join(".ramenv.vault.toml"),
        toml::to_string(vault).unwrap(),
    )
    .unwrap();
}

fn assert_signature(vault: &VaultFile, key: &str) {
    crypto::verify_signature(&canonical(vault), &vault.metadata.signature, key).unwrap();
}

#[test]
fn rotate_from_root_or_service_reencrypts_every_affected_vault() {
    for from_root in [false, true] {
        let workspace = Workspace::new();
        let before_keys = read_keys(&workspace.0);
        let before: Vec<_> = SERVICES
            .iter()
            .map(|name| read_vault(&workspace.0.join(name)))
            .collect();
        let worker_path = workspace.0.join(SERVICES[2]).join(".ramenv.vault.toml");
        let worker_before = std::fs::read(&worker_path).unwrap();
        let cwd = if from_root {
            workspace.0.clone()
        } else {
            workspace.0.join(SERVICES[0])
        };
        let consent = if from_root { "--yes" } else { "-y" };
        let output = run(&cwd, "rotate", &["development", consent]);
        success(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("2 workspace vault(s)"));
        let after_keys = read_keys(&workspace.0);
        assert_ne!(
            after_keys.encryption_keys["development"],
            before_keys.encryption_keys["development"]
        );
        assert_eq!(
            after_keys.encryption_keys["production"],
            before_keys.encryption_keys["production"]
        );
        assert_eq!(after_keys.signature_keys, before_keys.signature_keys);
        for (index, name) in SERVICES.iter().enumerate().take(2) {
            let service = workspace.0.join(name);
            let after = read_vault(&service);
            assert_signature(&after, &after_keys.signature_keys[*name]);
            let ciphertext = &after.environments["development"]["SECRET"];
            assert_ne!(
                ciphertext,
                &before[index].environments["development"]["SECRET"]
            );
            assert_eq!(
                crypto::decrypt_value(ciphertext, &after_keys.encryption_keys["development"])
                    .unwrap(),
                format!("secret-{index}")
            );
            assert!(
                crypto::decrypt_value(ciphertext, &before_keys.encryption_keys["development"])
                    .is_err()
            );
            assert_eq!(after.environments["development"]["PLAIN"], "unchanged");
            assert_eq!(
                after.environments["production"],
                before[index].environments["production"]
            );
            assert_eq!(
                toml::to_string(&after.validation).unwrap(),
                toml::to_string(&before[index].validation).unwrap()
            );
            success(&run(&service, "list", &["development", "--reveal"]));
        }
        assert_eq!(std::fs::read(worker_path).unwrap(), worker_before);
    }
}

#[test]
fn remove_from_root_or_service_removes_environment_everywhere() {
    // A service need not contain the target environment to initiate a workspace operation.
    for cwd_name in ["", SERVICES[0], SERVICES[2]] {
        let workspace = Workspace::new();
        let before_keys = read_keys(&workspace.0);
        let before: Vec<_> = SERVICES
            .iter()
            .map(|name| read_vault(&workspace.0.join(name)))
            .collect();
        let worker_path = workspace.0.join(SERVICES[2]).join(".ramenv.vault.toml");
        let worker_before = std::fs::read(&worker_path).unwrap();
        let consent = if cwd_name.is_empty() { "--yes" } else { "-y" };
        let output = run(
            &workspace.0.join(cwd_name),
            "remove-env",
            &["development", consent],
        );
        success(&output);
        assert!(String::from_utf8_lossy(&output.stderr).contains("2 workspace vault(s)"));
        let after_keys = read_keys(&workspace.0);
        assert!(!after_keys.encryption_keys.contains_key("development"));
        assert_eq!(
            after_keys.encryption_keys["production"],
            before_keys.encryption_keys["production"]
        );
        assert_eq!(after_keys.signature_keys, before_keys.signature_keys);
        for (index, name) in SERVICES.iter().enumerate() {
            let service = workspace.0.join(name);
            let after = read_vault(&service);
            assert!(!after.environments.contains_key("development"));
            assert_eq!(
                after.environments["production"],
                before[index].environments["production"]
            );
            assert_eq!(
                toml::to_string(&after.validation).unwrap(),
                toml::to_string(&before[index].validation).unwrap()
            );
            assert_signature(&after, &after_keys.signature_keys[*name]);
            success(&run(&service, "list", &["production", "--reveal"]));
        }
        assert_eq!(std::fs::read(worker_path).unwrap(), worker_before);
    }
}

fn snapshot_files(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    std::iter::once(root.join(".ramenv.keys"))
        .chain(
            SERVICES
                .iter()
                .map(|name| root.join(name).join(".ramenv.vault.toml")),
        )
        .map(|path| {
            let bytes = std::fs::read(&path).ok();
            (path, bytes)
        })
        .collect()
}

fn assert_unchanged(snapshot: Vec<(PathBuf, Option<Vec<u8>>)>) {
    for (path, original) in snapshot {
        assert_eq!(
            std::fs::read(&path).ok(),
            original,
            "changed {}",
            path.display()
        );
    }
}

#[test]
fn noninteractive_workspace_changes_require_explicit_consent_without_writing() {
    for command in ["rotate", "remove-env"] {
        for cwd_name in ["", SERVICES[0], SERVICES[2]] {
            let workspace = Workspace::new();
            let snapshot = snapshot_files(&workspace.0);
            let output = run(&workspace.0.join(cwd_name), command, &["development"]);
            assert_eq!(output.status.code(), Some(1));
            let scope = String::from_utf8_lossy(&output.stdout);
            assert!(scope.contains("environment 'development'"));
            assert!(scope.contains("all 2 affected workspace vault(s)"));
            assert!(scope.contains("Affected vaults:"));
            assert!(scope.contains(SERVICES[0]));
            assert!(scope.contains(SERVICES[1]));
            assert!(!scope.contains(SERVICES[2]));
            assert!(scope.contains("shared encryption key"));
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            assert!(diagnostic.contains("require confirmation"));
            assert!(diagnostic.contains("--yes (or -y)"));
            assert_unchanged(snapshot);
        }
    }
}

#[test]
fn monorepo_requires_consent_even_if_only_one_vault_has_the_environment() {
    for command in ["rotate", "remove-env"] {
        let workspace = Workspace::new();
        let keys = read_keys(&workspace.0);
        let service = workspace.0.join(SERVICES[0]);
        let mut vault = read_vault(&service);
        vault.environments.shift_remove("development");
        write_signed(&service, &mut vault, &keys.signature_keys[SERVICES[0]]);
        let snapshot = snapshot_files(&workspace.0);
        let output = run(&service, command, &["development"]);
        assert_eq!(output.status.code(), Some(1));
        let scope = String::from_utf8_lossy(&output.stdout);
        assert!(scope.contains("all 1 affected workspace vault(s)"));
        assert!(scope.contains(SERVICES[1]));
        assert!(!scope.contains(SERVICES[0]));
        assert!(!scope.contains(SERVICES[2]));
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains("require confirmation"));
        assert_unchanged(snapshot);
    }
}

#[test]
fn workspace_changes_fail_before_writing_if_any_registered_vault_is_invalid() {
    for command in ["rotate", "remove-env"] {
        for damage in ["missing", "bad-toml", "bad-signature", "tampered"] {
            let workspace = Workspace::new();
            let service = workspace.0.join(SERVICES[1]);
            let path = service.join(".ramenv.vault.toml");
            match damage {
                "missing" => std::fs::remove_file(&path).unwrap(),
                "bad-toml" => std::fs::write(&path, "invalid = [").unwrap(),
                _ => {
                    let mut vault = read_vault(&service);
                    if damage == "bad-signature" {
                        vault.metadata.signature = "a€".into();
                    } else {
                        vault.environments["development"].insert("TAMPERED".into(), "yes".into());
                    }
                    std::fs::write(&path, toml::to_string(&vault).unwrap()).unwrap();
                }
            }
            let snapshot = snapshot_files(&workspace.0);
            let output = run(
                &workspace.0.join(SERVICES[0]),
                command,
                &["development", "--yes"],
            );
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains(SERVICES[1]));
            assert_unchanged(snapshot);
        }
    }
}

#[test]
fn corrupt_sibling_ciphertext_aborts_rotation_before_writing() {
    let workspace = Workspace::new();
    let keys = read_keys(&workspace.0);
    let service = workspace.0.join(SERVICES[1]);
    let mut vault = read_vault(&service);
    vault.environments["development"].insert("SECRET".into(), "secret:a€".into());
    write_signed(&service, &mut vault, &keys.signature_keys[SERVICES[1]]);
    let snapshot = snapshot_files(&workspace.0);
    let output = run(&workspace.0, "rotate", &["development", "--yes"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to decode encrypted data"));
    assert_unchanged(snapshot);
}

#[test]
fn registered_paths_cannot_escape_the_workspace() {
    for name in ["../outside", "/outside", ""] {
        let workspace = Workspace::new();
        let mut keys = read_keys(&workspace.0);
        keys.signature_keys
            .insert(name.into(), keys.signature_keys[SERVICES[0]].clone());
        std::fs::write(
            workspace.0.join(".ramenv.keys"),
            toml::to_string(&keys).unwrap(),
        )
        .unwrap();
        let snapshot = snapshot_files(&workspace.0);
        let output = run(&workspace.0, "rotate", &["development", "--yes"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid registered vault path"));
        assert_unchanged(snapshot);
    }
}

#[cfg(unix)]
#[test]
fn registered_symlinks_cannot_modify_vaults_outside_the_workspace() {
    for link_file in [false, true] {
        let workspace = Workspace::new();
        let outside = Workspace::new();
        let external_service = outside.0.join(SERVICES[0]);
        let external_vault = external_service.join(".ramenv.vault.toml");
        let external_before = std::fs::read(&external_vault).unwrap();
        let service = workspace.0.join(SERVICES[1]);
        if link_file {
            let path = service.join(".ramenv.vault.toml");
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&external_vault, path).unwrap();
        } else {
            std::fs::remove_dir_all(&service).unwrap();
            std::os::unix::fs::symlink(&external_service, &service).unwrap();
        }
        let snapshot = snapshot_files(&workspace.0);
        let output = run(&workspace.0, "remove-env", &["development", "--yes"]);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("outside the workspace"));
        assert_unchanged(snapshot);
        assert_eq!(std::fs::read(external_vault).unwrap(), external_before);
    }
}

#[test]
fn validation_rules_remain_manually_editable_without_resigning() {
    let workspace = Workspace::new();
    let service = workspace.0.join(SERVICES[0]);
    let mut vault = read_vault(&service);
    vault.validation["SECRET"].rule_type = RuleType::String {
        min_len: Some(2),
        max_len: Some(100),
    };
    std::fs::write(
        service.join(".ramenv.vault.toml"),
        toml::to_string(&vault).unwrap(),
    )
    .unwrap();
    success(&run(&service, "validate", &["development"]));
    success(&run(&workspace.0, "rotate", &["development", "--yes"]));
}
