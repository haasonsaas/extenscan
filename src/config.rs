//! Configuration file handling.
//!
//! This module provides loading and saving of extenscan configuration
//! from a TOML file.
//!
//! # Configuration Location
//!
//! The configuration file is stored at:
//! - Linux: `~/.config/extenscan/config.toml`
//! - macOS: `~/Library/Application Support/extenscan/config.toml`
//! - Windows: `%APPDATA%\extenscan\config.toml`
//!
//! # Example Configuration
//!
//! ```toml
//! cache_ttl_hours = 24
//! skip_vuln_check = false
//! default_format = "table"
//! check_outdated = true
//! default_sources = ["vscode", "chrome", "npm"]
//! ```

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::model::Source;

/// Application configuration.
///
/// This struct represents all configurable options for extenscan.
/// It can be loaded from a TOML file or created with default values.
///
/// # Example
///
/// ```no_run
/// use extenscan::Config;
///
/// // Load from file (or use defaults if file doesn't exist)
/// let config = Config::load().unwrap();
///
/// println!("Cache TTL: {} hours", config.cache_ttl_hours);
/// println!("Check outdated: {}", config.check_outdated);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// How long to cache API responses, in hours.
    ///
    /// Default: 24 hours
    pub cache_ttl_hours: u64,

    /// Which sources to scan by default when no `--source` flag is provided.
    ///
    /// Default: all sources
    pub default_sources: Vec<Source>,

    /// Whether to skip vulnerability checking by default.
    ///
    /// Default: false (vulnerability checking is enabled)
    pub skip_vuln_check: bool,

    /// Default output format when no `--format` flag is provided.
    ///
    /// Valid values: "table", "json"
    /// Default: "table"
    pub default_format: String,

    /// Whether to check for outdated packages by default.
    ///
    /// Default: true
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
    /// Loads configuration from the config file.
    ///
    /// If the config file doesn't exist, returns default configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the config file exists but cannot be read or parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use extenscan::Config;
    ///
    /// let config = Config::load()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn load() -> Result<Self> {
        let path = Self::config_path();

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Saves the configuration to the config file.
    ///
    /// Creates the parent directory if it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use extenscan::Config;
    ///
    /// let mut config = Config::default();
    /// config.cache_ttl_hours = 48;
    /// config.save()?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
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

    /// Returns the path to the configuration file.
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Config;
    ///
    /// let path = Config::config_path();
    /// println!("Config file: {}", path.display());
    /// ```
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("extenscan")
            .join("config.toml")
    }

    /// Generates a string containing the default configuration.
    ///
    /// This is useful for showing users what the default config looks like.
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Config;
    ///
    /// let default_config = Config::generate_default_config();
    /// println!("{}", default_config);
    /// ```
    pub fn generate_default_config() -> String {
        let config = Config::default();
        toml::to_string_pretty(&config).unwrap_or_default()
    }
}
