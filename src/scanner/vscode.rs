use crate::model::{Package, PackageMetadata, Platform, Source};
use crate::platform::vscode_extensions_dir;
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::fs;

pub struct VscodeScanner;

#[derive(Deserialize)]
struct VscodePackageJson {
    name: Option<String>,
    #[serde(alias = "displayName")]
    display_name: Option<String>,
    version: Option<String>,
    publisher: Option<String>,
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<RepositoryField>,
    license: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RepositoryField {
    String(String),
    Object { url: String },
}

impl RepositoryField {
    fn url(&self) -> &str {
        match self {
            RepositoryField::String(s) => s,
            RepositoryField::Object { url } => url,
        }
    }
}

#[async_trait]
impl super::Scanner for VscodeScanner {
    fn name(&self) -> &'static str {
        "VSCode Extensions"
    }

    fn source(&self) -> Source {
        Source::Vscode
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match vscode_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        let mut packages = Vec::new();

        let entries = fs::read_dir(&extensions_dir).with_context(|| {
            format!(
                "Failed to read VSCode extensions directory: {:?}",
                extensions_dir
            )
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let package_json_path = path.join("package.json");
            if !package_json_path.exists() {
                continue;
            }

            let content = match fs::read_to_string(&package_json_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let pkg_json: VscodePackageJson = match serde_json::from_str(&content) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let name = pkg_json
                .display_name
                .or(pkg_json.name.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            let version = pkg_json.version.unwrap_or_else(|| "0.0.0".to_string());

            let id =
                if let (Some(publisher), Some(pkg_name)) = (&pkg_json.publisher, &pkg_json.name) {
                    format!("{}.{}", publisher, pkg_name)
                } else {
                    entry.file_name().to_string_lossy().to_string()
                };

            let metadata = PackageMetadata {
                description: pkg_json.description,
                publisher: pkg_json.publisher,
                homepage: pkg_json.homepage,
                repository: pkg_json.repository.map(|r| r.url().to_string()),
                license: pkg_json.license,
            };

            let package = Package::new(id, name, version, Source::Vscode)
                .with_path(path)
                .with_metadata(metadata);

            packages.push(package);
        }

        Ok(packages)
    }
}
