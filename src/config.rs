use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::model::Source;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Cache TTL in hours (default: 24)
    pub cache_ttl_hours: u64,

    /// Sources to scan by default
    pub default_sources: Vec<Source>,

    /// Skip vulnerability checking by default
    pub skip_vuln_check: bool,

    /// Default output format ("table" or "json")
    pub default_format: String,

    /// Check for outdated packages
    pub check_outdated: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cache_ttl_hours: 24,
            default_sources: vec![
                Source::Vscode,
                Source::Chrome,
                Source::Edge,
                Source::Firefox,
                Source::Npm,
                Source::Homebrew,
            ],
            skip_vuln_check: false,
            default_format: "table".to_string(),
            check_outdated: true,
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Self::config_path();

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();

        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }

    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("extenscan")
            .join("config.toml")
    }

    pub fn generate_default_config() -> String {
        let config = Config::default();
        toml::to_string_pretty(&config).unwrap_or_default()
    }
}
