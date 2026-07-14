use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    name: String,
    version: String,
}

impl ConfigFile {
    pub fn new(version: String, project_name: String) -> Self {
        Self {
            name: project_name,
            version,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysFile {
    pub keys: HashMap<String, String>,
}

impl KeysFile {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    #[serde(flatten)]
    pub environemnts: HashMap<String, HashMap<String, String>>,
}

impl VaultFile {
    pub fn new() -> Self {
        Self {
            environemnts: HashMap::new(),
        }
    }
}
