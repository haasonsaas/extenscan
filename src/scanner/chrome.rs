use crate::model::{Package, PackageMetadata, Platform, Source};
use crate::platform::chrome_extensions_dir;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::fs;

pub struct ChromeScanner;

#[derive(Deserialize)]
struct ChromeManifest {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    #[serde(default)]
    author: Option<String>,
    homepage_url: Option<String>,
}

#[async_trait]
impl super::Scanner for ChromeScanner {
    fn name(&self) -> &'static str {
        "Chrome Extensions"
    }

    fn source(&self) -> Source {
        Source::Chrome
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match chrome_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        scan_chromium_extensions(&extensions_dir, Source::Chrome)
    }
}

pub fn scan_chromium_extensions(
    extensions_dir: &std::path::Path,
    source: Source,
) -> Result<Vec<Package>> {
    let mut packages = Vec::new();

    let entries = fs::read_dir(extensions_dir)
        .with_context(|| format!("Failed to read extensions directory: {:?}", extensions_dir))?;

    for entry in entries.flatten() {
        let ext_path = entry.path();
        if !ext_path.is_dir() {
            continue;
        }

        let extension_id = entry.file_name().to_string_lossy().to_string();

        // Each extension has version subdirectories
        let version_dirs: Vec<_> = fs::read_dir(&ext_path)
            .ok()
            .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).collect())
            .unwrap_or_default();

        // Get the latest version (last in sorted order)
        let latest_version_dir = version_dirs.into_iter().max_by_key(|e| e.file_name());

        let version_path = match latest_version_dir {
            Some(dir) => dir.path(),
            None => continue,
        };

        let manifest_path = version_path.join("manifest.json");
        if !manifest_path.exists() {
            continue;
        }

        let content = match fs::read_to_string(&manifest_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let manifest: ChromeManifest = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let name = manifest.name.unwrap_or_else(|| extension_id.clone());

        // Handle Chrome's __MSG_xxx__ localized names
        let name = if name.starts_with("__MSG_") {
            // Try to get localized name from _locales
            get_localized_name(&version_path, &name).unwrap_or(extension_id.clone())
        } else {
            name
        };

        let version = manifest.version.unwrap_or_else(|| "0.0.0".to_string());

        let metadata = PackageMetadata {
            description: manifest.description.and_then(|d| {
                if d.starts_with("__MSG_") {
                    None
                } else {
                    Some(d)
                }
            }),
            publisher: manifest.author,
            homepage: manifest.homepage_url,
            repository: None,
            license: None,
        };

        let package = Package::new(&extension_id, name, version, source)
            .with_path(version_path)
            .with_metadata(metadata);

        packages.push(package);
    }

    Ok(packages)
}

fn get_localized_name(version_path: &std::path::Path, msg_key: &str) -> Option<String> {
    let key = msg_key.trim_start_matches("__MSG_").trim_end_matches("__");

    let locales_dir = version_path.join("_locales");

    // Try common locales
    for locale in &["en", "en_US", "en_GB"] {
        let messages_path = locales_dir.join(locale).join("messages.json");
        if let Ok(content) = fs::read_to_string(&messages_path) {
            if let Ok(messages) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(msg) = messages
                    .get(key)
                    .or_else(|| messages.get(key.to_lowercase()))
                {
                    if let Some(message) = msg.get("message").and_then(|m| m.as_str()) {
                        return Some(message.to_string());
                    }
                }
            }
        }
    }

    None
}
