use clap::ValueEnum;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::validation::ValidationRule;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysFile {
    pub encryption_keys: IndexMap<String, String>,
    pub signature_keys: IndexMap<String, String>,
}

impl Default for KeysFile {
    fn default() -> Self {
        Self {
            encryption_keys: IndexMap::new(),
            signature_keys: IndexMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysReferenceFile {
    pub encryption_keys: IndexMap<String, String>,
    pub signature_keys: IndexMap<String, String>,
    pub provider_url: String,
}

impl KeysReferenceFile {
    pub fn new(provider_url: String) -> Self {
        Self {
            encryption_keys: IndexMap::new(),
            signature_keys: IndexMap::new(),
            provider_url,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub validation: IndexMap<String, ValidationRule>,
    pub environments: IndexMap<String, IndexMap<String, String>>,
    pub metadata: VaultMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub signature: String,
    pub signature_version: String,
    pub signed_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CanonicalVault {
    pub environments: IndexMap<String, IndexMap<String, String>>,
}

impl Default for VaultFile {
    fn default() -> Self {
        Self {
            validation: IndexMap::new(),
            environments: IndexMap::new(),
            metadata: VaultMetadata::default(),
        }
    }
}

impl Default for VaultMetadata {
    fn default() -> Self {
        Self {
            signature: "".to_string(),
            signature_version: "".to_string(),
            signed_at: "".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceFile {
    pub workspace_name: String,
    pub schema_version: String,
    pub ingredient: Provider,
}

impl WorkspaceFile {
    pub fn new(schema_version: String, project_name: String, provider: Provider) -> Self {
        Self {
            workspace_name: project_name,
            schema_version,
            ingredient: provider,
        }
    }
}

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Local,
    Azure,
    // Google,
    // Aws,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_empty_and_serializable() {
        let keys = KeysFile::default();
        assert!(keys.encryption_keys.is_empty());
        assert!(keys.signature_keys.is_empty());

        let vault = VaultFile::default();
        assert!(vault.validation.is_empty());
        assert!(vault.environments.is_empty());
        assert_eq!(vault.metadata.signature, "");
        assert_eq!(vault.metadata.signature_version, "");
        assert_eq!(vault.metadata.signed_at, "");
        toml::to_string(&keys).unwrap();
        toml::to_string(&vault).unwrap();
    }

    #[test]
    fn workspace_constructor_preserves_arguments() {
        let workspace = WorkspaceFile::new("2".into(), "payments".into(), Provider::Local);
        assert_eq!(workspace.schema_version, "2");
        assert_eq!(workspace.workspace_name, "payments");
    }

    #[test]
    fn validation_required_defaults_to_true_when_deserializing() {
        let vault: VaultFile = toml::from_str(
            r#"
environments = {}

[validation.API_KEY]
type = "string"

[metadata]
signature = "sig"
signature_version = "1"
signed_at = "now"
"#,
        )
        .unwrap();
        assert!(vault.validation["API_KEY"].required);
    }
}
