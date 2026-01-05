use crate::checker::extension_risk::analyze_extension;
use crate::model::{Package, PackageMetadata, Platform, Source};
use crate::platform::firefox_profiles_dir;
use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub struct FirefoxScanner;

#[derive(Deserialize)]
struct FirefoxAddon {
    id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    #[serde(alias = "creator")]
    author: Option<AuthorField>,
    #[serde(alias = "homepageURL")]
    homepage_url: Option<String>,
    // Permission fields from extensions.json
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default, alias = "optionalPermissions")]
    optional_permissions: Vec<String>,
    // User permissions (granted by user)
    #[serde(default, alias = "userPermissions")]
    user_permissions: Option<UserPermissions>,
}

#[derive(Deserialize, Default)]
struct UserPermissions {
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    origins: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthorField {
    String(String),
    Object { name: String },
}

impl AuthorField {
    fn name(&self) -> &str {
        match self {
            AuthorField::String(s) => s,
            AuthorField::Object { name } => name,
        }
    }
}

#[derive(Deserialize)]
struct AddonsJson {
    addons: Vec<FirefoxAddon>,
}

#[async_trait]
impl super::Scanner for FirefoxScanner {
    fn name(&self) -> &'static str {
        "Firefox Add-ons"
    }

    fn source(&self) -> Source {
        Source::Firefox
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let profiles_dir = match firefox_profiles_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        let mut packages = Vec::new();

        // Find all profile directories (*.default*, *.default-release, etc.)
        let entries = fs::read_dir(&profiles_dir)?;

        for entry in entries.flatten() {
            let profile_path = entry.path();
            if !profile_path.is_dir() {
                continue;
            }

            // Check for addons.json (newer Firefox) or extensions.json
            let addons_from_profile = scan_firefox_profile(&profile_path)?;

            for addon in addons_from_profile {
                // Avoid duplicates across profiles
                if !packages.iter().any(|p: &Package| p.id == addon.id) {
                    packages.push(addon);
                }
            }
        }

        Ok(packages)
    }
}

fn scan_firefox_profile(profile_path: &Path) -> Result<Vec<Package>> {
    let mut packages = Vec::new();

    // Try extensions.json first (more comprehensive)
    let extensions_json_path = profile_path.join("extensions.json");
    if extensions_json_path.exists() {
        if let Ok(content) = fs::read_to_string(&extensions_json_path) {
            if let Ok(data) = serde_json::from_str::<AddonsJson>(&content) {
                for addon in data.addons {
                    if let Some(package) = parse_firefox_addon(addon) {
                        packages.push(package);
                    }
                }
            }
        }
    }

    // Also check the extensions directory for XPI files
    let extensions_dir = profile_path.join("extensions");
    if extensions_dir.exists() {
        if let Ok(entries) = fs::read_dir(&extensions_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let filename = entry.file_name().to_string_lossy().to_string();

                // XPI files are named {extension-id}.xpi
                if filename.ends_with(".xpi") {
                    let id = filename.trim_end_matches(".xpi").to_string();
                    if !packages.iter().any(|p| p.id == id) {
                        let package =
                            Package::new(&id, &id, "unknown", Source::Firefox).with_path(path);
                        packages.push(package);
                    }
                }
            }
        }
    }

    Ok(packages)
}

fn parse_firefox_addon(addon: FirefoxAddon) -> Option<Package> {
    let id = addon.id?;

    // Skip built-in/system addons
    if id.ends_with("@mozilla.org") || id.ends_with("@shield.mozilla.org") {
        return None;
    }

    let name = addon.name.unwrap_or_else(|| id.clone());
    let version = addon.version.unwrap_or_else(|| "unknown".to_string());

    let metadata = PackageMetadata {
        description: addon.description,
        publisher: addon.author.map(|a| a.name().to_string()),
        homepage: addon.homepage_url,
        repository: None,
        license: None,
    };

    // Collect permissions for risk analysis
    let mut all_permissions = addon.permissions.clone();
    let mut host_permissions = Vec::new();

    // Add user-granted permissions
    if let Some(ref user_perms) = addon.user_permissions {
        all_permissions.extend(user_perms.permissions.clone());
        host_permissions.extend(user_perms.origins.clone());
    }

    // Separate API permissions from host permissions
    let (api_perms, host_perms): (Vec<_>, Vec<_>) = all_permissions
        .iter()
        .partition(|p| !p.contains("://") && !p.starts_with("<"));

    host_permissions.extend(host_perms.into_iter().cloned());

    // Perform risk analysis
    let risk_report = analyze_extension(
        &api_perms.into_iter().cloned().collect::<Vec<_>>(),
        &addon.optional_permissions,
        &host_permissions,
        None, // Firefox extensions.json doesn't include CSP
    );

    Some(
        Package::new(id, name, version, Source::Firefox)
            .with_metadata(metadata)
            .with_extension_risk(risk_report),
    )
}
