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
    pub name: String,
    pub version: String,
    pub validation: IndexMap<String, ValidationRule>,
    pub environments: IndexMap<String, IndexMap<String, String>>,
}

impl VaultFile {
    pub fn new(version: String, project_name: String) -> Self {
        Self {
            name: project_name,
            version,
            validation: IndexMap::new(),
            environments: IndexMap::new(),
        }
    }
}
