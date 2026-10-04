use anyhow::Result;
use indexmap::IndexMap;
use log::info;

use crate::{
    crypto, services,
    utils::{self, StringExt},
};

pub async fn rotate_command(
    env: &str,
    encryption_key_service: &mut impl services::EncryptionKeyService,
    vaults: &mut [impl services::VaultService],
    workspace_service: &impl services::WorkspaceService,
) -> Result<()> {
    let encryption_key = encryption_key_service.env_key(env)?.to_owned();
    let originals = super::workspace_change::snapshots(env, vaults);
    if originals.is_empty() {
        anyhow::bail!("vault for {} environment does not exist", env);
    }
    let new_encryption_key = crypto::generate_master_key_hex();
    let mut replacements = Vec::new();

    // Decrypt and prepare every affected vault before changing any state.
    for (index, environments) in &originals {
        let mut new_vault = IndexMap::new();
        for (key, value) in &environments[env] {
            let rotated = if value.is_secret() {
                let plaintext = utils::get_plaintext(value, &encryption_key)?;
                crypto::encrypt_value(&plaintext, &new_encryption_key)?
            } else {
                value.clone()
            };
            new_vault.insert(key.clone(), rotated);
        }
        replacements.push((*index, new_vault));
    }
    for (index, replacement) in replacements {
        vaults[index].set_env_vault(env, replacement);
    }
    super::workspace_change::commit_change(
        env,
        Some(new_encryption_key),
        encryption_key_service,
        vaults,
        &originals,
        workspace_service,
    )
    .await?;

    info!(
        "🔄 successfully rotated shared encryption key for environment: {} in {} workspace vault(s)",
        env,
        originals.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{KEY, Keys, Vault, Workspace};

    fn secret_vault(value: &str) -> Vault {
        Vault::with_env(
            "dev",
            IndexMap::from([
                ("SECRET".into(), crypto::encrypt_value(value, KEY).unwrap()),
                ("PLAIN".into(), "plain value".into()),
            ]),
        )
    }

    #[tokio::test]
    async fn rotates_only_encrypted_values_and_commits() {
        let mut keys = Keys::with_env("dev");
        let mut vaults = [secret_vault("secret value")];
        let original = vaults[0].environments["dev"]["SECRET"].clone();
        rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap();
        let new_key = &keys.values["dev"];
        assert_ne!(new_key, KEY);
        assert_ne!(vaults[0].environments["dev"]["SECRET"], original);
        assert_eq!(
            crypto::decrypt_value(&vaults[0].environments["dev"]["SECRET"], new_key).unwrap(),
            "secret value"
        );
        assert_eq!(vaults[0].environments["dev"]["PLAIN"], "plain value");
        assert_eq!(vaults[0].commits.get(), 1);
        assert_eq!(keys.commits.get(), 1);
    }

    #[tokio::test]
    async fn rotates_all_affected_vaults_and_skips_unrelated_environments() {
        let mut keys = Keys::with_env("dev");
        let mut vaults = [
            secret_vault("first"),
            secret_vault("second"),
            Vault::with_env("prod", IndexMap::new()),
        ];
        vaults[0].environments.insert(
            "prod".into(),
            IndexMap::from([("KEEP".into(), "unchanged".into())]),
        );
        rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap();
        for (vault, expected) in vaults.iter().zip(["first", "second"]) {
            assert_eq!(
                crypto::decrypt_value(&vault.environments["dev"]["SECRET"], &keys.values["dev"])
                    .unwrap(),
                expected
            );
            assert_eq!(vault.commits.get(), 1);
        }
        assert_eq!(vaults[0].environments["prod"]["KEEP"], "unchanged");
        assert_eq!(vaults[2].commits.get(), 0);
        assert_eq!(keys.commits.get(), 1);
    }

    #[tokio::test]
    async fn rejects_missing_state_or_corrupt_ciphertext() {
        let mut keys = Keys::default();
        let mut vaults = [secret_vault("value")];
        assert!(
            rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
                .await
                .is_err()
        );
        let mut keys = Keys::with_env("dev");
        let mut vaults = [Vault::default()];
        assert!(
            rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
                .await
                .is_err()
        );

        let mut vaults = [
            secret_vault("first"),
            Vault::with_env(
                "dev",
                IndexMap::from([("SECRET".into(), "secret:a€".into())]),
            ),
        ];
        let originals: Vec<_> = vaults
            .iter()
            .map(|vault| vault.environments.clone())
            .collect();
        assert!(
            rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
                .await
                .is_err()
        );
        for (vault, original) in vaults.iter().zip(originals) {
            assert_eq!(vault.environments, original);
            assert_eq!(vault.commits.get(), 0);
        }
        assert_eq!(keys.values["dev"], KEY);
        assert_eq!(keys.commits.get(), 0);
    }

    #[tokio::test]
    async fn rolls_back_earlier_vaults_when_a_later_commit_fails() {
        let mut keys = Keys::with_env("dev");
        let mut vaults = [
            secret_vault("first"),
            Vault {
                fail_commit_at: Some(1),
                ..secret_vault("second")
            },
            secret_vault("third"),
        ];
        let originals: Vec<_> = vaults
            .iter()
            .map(|vault| vault.environments.clone())
            .collect();
        let error = rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "vault commit failed");
        for (vault, original) in vaults.iter().zip(originals) {
            assert_eq!(vault.environments, original);
        }
        assert_eq!(vaults[0].commits.get(), 2);
        assert_eq!(vaults[1].commits.get(), 2);
        assert_eq!(vaults[2].commits.get(), 0);
        assert_eq!(keys.commits.get(), 0);
        assert_eq!(keys.values["dev"], KEY);
    }

    #[tokio::test]
    async fn rolls_back_all_vaults_and_key_store_when_key_commit_fails() {
        let mut keys = Keys {
            fail_commit_at: Some(1),
            ..Keys::with_env("dev")
        };
        let mut vaults = [secret_vault("first"), secret_vault("second")];
        let originals: Vec<_> = vaults
            .iter()
            .map(|vault| vault.environments.clone())
            .collect();
        let error = rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "key commit failed");
        for (vault, original) in vaults.iter().zip(originals) {
            assert_eq!(vault.environments, original);
            assert_eq!(vault.commits.get(), 2);
        }
        assert_eq!(keys.values["dev"], KEY);
        assert_eq!(keys.commits.get(), 2);
    }

    #[tokio::test]
    async fn reports_rollback_failures_and_still_restores_other_vaults() {
        let mut keys = Keys {
            fail_commit: true,
            ..Keys::with_env("dev")
        };
        let mut vaults = [
            Vault {
                fail_commit_at: Some(2),
                ..secret_vault("first")
            },
            secret_vault("second"),
        ];
        let originals: Vec<_> = vaults
            .iter()
            .map(|vault| vault.environments.clone())
            .collect();
        let error = rotate_command("dev", &mut keys, &mut vaults, &Workspace::default())
            .await
            .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("failed to roll back key"));
        assert!(diagnostic.contains("failed to roll back vaults"));
        assert!(diagnostic.contains("key commit failed"));
        for (vault, original) in vaults.iter().zip(originals) {
            assert_eq!(vault.environments, original);
            assert_eq!(vault.commits.get(), 2);
        }
    }
}
