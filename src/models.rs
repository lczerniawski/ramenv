use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::validation::ValidationRule;

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysFile {
    pub keys: IndexMap<String, String>,
}

impl Default for KeysFile {
    fn default() -> Self {
        Self {
            keys: IndexMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub validation: IndexMap<String, ValidationRule>,
    pub environments: IndexMap<String, IndexMap<String, String>>,
}

impl Default for VaultFile {
    fn default() -> Self {
        Self {
            validation: IndexMap::new(),
            environments: IndexMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceFile {
    pub workspace_name: String,
    pub schema_version: String,
}

impl WorkspaceFile {
    pub fn new(schema_version: String, project_name: String) -> Self {
        Self {
            workspace_name: project_name,
            schema_version,
        }
    }
}
