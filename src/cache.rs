use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use crate::platform::cache_dir;

const CACHE_TTL_HOURS: u64 = 24;

pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            dir: cache_dir(),
            ttl: Duration::from_secs(CACHE_TTL_HOURS * 3600),
        }
    }

    pub fn with_ttl_hours(hours: u64) -> Self {
        Self {
            dir: cache_dir(),
            ttl: Duration::from_secs(hours * 3600),
        }
    }

    fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)?;
        }
        Ok(())
    }

    fn cache_path(&self, key: &str) -> PathBuf {
        // Create a safe filename from the key
        let safe_key: String = key
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        self.dir.join(format!("{}.json", safe_key))
    }

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

    pub fn set<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        self.ensure_dir()?;
        let path = self.cache_path(key);
        let content = serde_json::to_string(value)?;
        fs::write(&path, content)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        if self.dir.exists() {
            for entry in fs::read_dir(&self.dir)? {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.extension().map(|e| e == "json").unwrap_or(false) {
                        let _ = fs::remove_file(path);
                    }
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
