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
//!
//! [ignore]
//! packages = ["lodash", "underscore"]
//! vulnerabilities = ["CVE-2021-12345"]
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
    /// Valid values: "table", "json", "sarif"
    /// Default: "table"
    pub default_format: String,

    /// Whether to check for outdated packages by default.
    ///
    /// Default: true
    pub check_outdated: bool,

    /// Ignore list configuration for suppressing known issues.
    #[serde(default)]
    pub ignore: IgnoreConfig,
}

/// Configuration for ignoring specific packages or vulnerabilities.
///
/// Use this to suppress known false positives or accepted risks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnoreConfig {
    /// Package IDs to exclude from scanning.
    ///
    /// Packages matching these IDs will not appear in results.
    /// Supports glob patterns (e.g., "lodash*", "@types/*").
    pub packages: Vec<String>,

    /// Vulnerability IDs to ignore (e.g., "CVE-2021-12345", "GHSA-xxxx").
    ///
    /// These vulnerabilities will not be reported even if found.
    pub vulnerabilities: Vec<String>,

    /// Package IDs to exclude from outdated checks.
    ///
    /// Useful for packages intentionally pinned to older versions.
    pub outdated: Vec<String>,
}

impl IgnoreConfig {
    /// Check if a package should be ignored.
    pub fn should_ignore_package(&self, package_id: &str) -> bool {
        self.packages.iter().any(|pattern| {
            if pattern.contains('*') {
                glob_match(pattern, package_id)
            } else {
                pattern == package_id
            }
        })
    }

    /// Check if a vulnerability should be ignored.
    pub fn should_ignore_vulnerability(&self, vuln_id: &str) -> bool {
        self.vulnerabilities.iter().any(|id| id == vuln_id)
    }

    /// Check if outdated check should be skipped for a package.
    pub fn should_ignore_outdated(&self, package_id: &str) -> bool {
        self.outdated.iter().any(|pattern| {
            if pattern.contains('*') {
                glob_match(pattern, package_id)
            } else {
                pattern == package_id
            }
        })
    }
}

/// Simple glob matching (supports * as wildcard).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        return pattern == text;
    }

    let mut remaining = text;

    // Check prefix (before first *)
    if !parts[0].is_empty() {
        if !remaining.starts_with(parts[0]) {
            return false;
        }
        remaining = &remaining[parts[0].len()..];
    }

    // Check suffix (after last *)
    let last_part = parts[parts.len() - 1];
    if !last_part.is_empty() {
        if !remaining.ends_with(last_part) {
            return false;
        }
        remaining = &remaining[..remaining.len() - last_part.len()];
    }

    // Check middle parts
    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = remaining.find(part) {
            remaining = &remaining[pos + part.len()..];
        } else {
            return false;
        }
    }

    true
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
            ignore: IgnoreConfig::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("lodash", "lodash"));
        assert!(!glob_match("lodash", "underscore"));
    }

    #[test]
    fn test_glob_match_prefix() {
        assert!(glob_match("lodash*", "lodash"));
        assert!(glob_match("lodash*", "lodash.debounce"));
        assert!(glob_match("lodash*", "lodash-es"));
        assert!(!glob_match("lodash*", "underscore"));
    }

    #[test]
    fn test_glob_match_suffix() {
        assert!(glob_match("*-cli", "typescript-cli"));
        assert!(glob_match("*-cli", "eslint-cli"));
        assert!(!glob_match("*-cli", "typescript"));
    }

    #[test]
    fn test_glob_match_contains() {
        assert!(glob_match("*lodash*", "lodash"));
        assert!(glob_match("*lodash*", "my-lodash-plugin"));
        assert!(!glob_match("*lodash*", "underscore"));
    }

    #[test]
    fn test_glob_match_scoped() {
        assert!(glob_match("@types/*", "@types/node"));
        assert!(glob_match("@types/*", "@types/react"));
        assert!(!glob_match("@types/*", "@babel/core"));
    }

    #[test]
    fn test_ignore_config_packages() {
        let config = IgnoreConfig {
            packages: vec!["lodash".to_string(), "@types/*".to_string()],
            vulnerabilities: vec![],
            outdated: vec![],
        };

        assert!(config.should_ignore_package("lodash"));
        assert!(config.should_ignore_package("@types/node"));
        assert!(config.should_ignore_package("@types/react"));
        assert!(!config.should_ignore_package("underscore"));
        assert!(!config.should_ignore_package("@babel/core"));
    }

    #[test]
    fn test_ignore_config_vulnerabilities() {
        let config = IgnoreConfig {
            packages: vec![],
            vulnerabilities: vec!["CVE-2021-12345".to_string(), "GHSA-xxxx".to_string()],
            outdated: vec![],
        };

        assert!(config.should_ignore_vulnerability("CVE-2021-12345"));
        assert!(config.should_ignore_vulnerability("GHSA-xxxx"));
        assert!(!config.should_ignore_vulnerability("CVE-2022-99999"));
    }

    #[test]
    fn test_ignore_config_outdated() {
        let config = IgnoreConfig {
            packages: vec![],
            vulnerabilities: vec![],
            outdated: vec!["typescript".to_string()],
        };

        assert!(config.should_ignore_outdated("typescript"));
        assert!(!config.should_ignore_outdated("eslint"));
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();

        assert_eq!(config.cache_ttl_hours, 24);
        assert_eq!(config.default_format, "table");
        assert!(config.check_outdated);
        assert!(!config.skip_vuln_check);
        assert_eq!(config.default_sources.len(), 6);
        assert!(config.ignore.packages.is_empty());
    }
}
