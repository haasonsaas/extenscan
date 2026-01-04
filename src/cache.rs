//! File-based caching for API responses.
//!
//! This module provides a simple file-based cache with TTL (time-to-live)
//! support. It's used to cache vulnerability lookups and version checks
//! to reduce API calls.
//!
//! # Cache Location
//!
//! The cache is stored in platform-specific directories:
//! - Linux: `~/.cache/extenscan/`
//! - macOS: `~/Library/Caches/extenscan/`
//! - Windows: `%LOCALAPPDATA%\extenscan\cache\`
//!
//! # Example
//!
//! ```no_run
//! use extenscan::Cache;
//!
//! let cache = Cache::new();
//!
//! // Store a value
//! cache.set("my_key", &"cached value".to_string()).unwrap();
//!
//! // Retrieve it later (within TTL)
//! let value: Option<String> = cache.get("my_key");
//! assert_eq!(value, Some("cached value".to_string()));
//! ```

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::platform::cache_dir;

/// Default cache TTL in hours.
const CACHE_TTL_HOURS: u64 = 24;

/// A file-based cache with TTL support.
///
/// Values are stored as JSON files in the cache directory. Each entry
/// expires after the configured TTL period.
pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
}

impl Cache {
    /// Creates a new cache with the default 24-hour TTL.
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Cache;
    ///
    /// let cache = Cache::new();
    /// ```
    pub fn new() -> Self {
        Self {
            dir: cache_dir(),
            ttl: Duration::from_secs(CACHE_TTL_HOURS * 3600),
        }
    }

    /// Creates a new cache with a custom TTL.
    ///
    /// # Arguments
    ///
    /// * `hours` - The TTL in hours
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Cache;
    ///
    /// // Cache that expires after 1 hour
    /// let cache = Cache::with_ttl_hours(1);
    /// ```
    pub fn with_ttl_hours(hours: u64) -> Self {
        Self {
            dir: cache_dir(),
            ttl: Duration::from_secs(hours * 3600),
        }
    }

    /// Ensures the cache directory exists.
    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)?;
        }
        Ok(())
    }

    /// Converts a cache key to a safe filename.
    fn cache_path(&self, key: &str) -> PathBuf {
        let safe_key: String = key
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{}.json", safe_key))
    }

    /// Retrieves a value from the cache.
    ///
    /// Returns `None` if the key doesn't exist or has expired.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to deserialize the cached value into
    ///
    /// # Example
    ///
    /// ```no_run
    /// use extenscan::Cache;
    ///
    /// let cache = Cache::new();
    /// let value: Option<String> = cache.get("my_key");
    /// ```
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        let path = self.cache_path(key);

        if !path.exists() {
            return None;
        }

        // Check if cache is expired
        if let Ok(metadata) = fs::metadata(&path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                    if elapsed > self.ttl {
                        // Cache expired, remove it
                        let _ = fs::remove_file(&path);
                        return None;
                    }
                }
            }
        }

        // Read and deserialize
        let content = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Stores a value in the cache.
    ///
    /// The value is serialized to JSON and written to a file.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key
    /// * `value` - The value to cache (must be serializable)
    ///
    /// # Errors
    ///
    /// Returns an error if the cache directory cannot be created or
    /// the file cannot be written.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use extenscan::Cache;
    ///
    /// let cache = Cache::new();
    /// cache.set("version_lodash", &"4.17.21".to_string()).unwrap();
    /// ```
    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.ensure_dir()?;
        let path = self.cache_path(key);
        let content = serde_json::to_string(value)?;
        fs::write(&path, content)?;
        Ok(())
    }

    /// Clears all cached entries.
    ///
    /// This removes all JSON files from the cache directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache directory cannot be read.
    pub fn clear(&self) -> Result<()> {
        if self.dir.exists() {
            for entry in fs::read_dir(&self.dir)?.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(())
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}
