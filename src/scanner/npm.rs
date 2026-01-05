use crate::model::{Package, PackageMetadata, Platform, Source};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct NpmScanner;

#[derive(Deserialize)]
struct NpmListOutput {
    dependencies: Option<HashMap<String, NpmPackage>>,
}

#[derive(Deserialize)]
struct NpmPackage {
    version: Option<String>,
    resolved: Option<String>,
}

/// Package.json structure for reading installed package metadata
#[derive(Deserialize)]
struct PackageJson {
    description: Option<String>,
    author: Option<AuthorField>,
    license: Option<String>,
    repository: Option<RepositoryField>,
    homepage: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AuthorField {
    String(String),
    Object {
        name: Option<String>,
        email: Option<String>,
    },
}

impl fmt::Display for AuthorField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorField::String(s) => write!(f, "{}", s),
            AuthorField::Object { name, email } => match (name, email) {
                (Some(n), Some(e)) => write!(f, "{} <{}>", n, e),
                (Some(n), None) => write!(f, "{}", n),
                (None, Some(e)) => write!(f, "{}", e),
                (None, None) => Ok(()),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RepositoryField {
    String(String),
    Object { url: Option<String> },
}

impl RepositoryField {
    fn url(&self) -> Option<String> {
        match self {
            RepositoryField::String(s) => Some(s.clone()),
            RepositoryField::Object { url } => url.clone(),
        }
    }
}

#[async_trait]
impl super::Scanner for NpmScanner {
    fn name(&self) -> &'static str {
        "NPM Global Packages"
    }

    fn source(&self) -> Source {
        Source::Npm
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        // Check if npm is available
        let npm_cmd = if cfg!(target_os = "windows") {
            "npm.cmd"
        } else {
            "npm"
        };

        // Get global prefix for reading package.json files
        let prefix = get_npm_prefix(npm_cmd);

        let output = Command::new(npm_cmd)
            .args(["list", "-g", "--json", "--depth=0"])
            .output()
            .context("Failed to execute npm. Is npm installed?")?;

        if !output.status.success() {
            // npm list returns exit code 1 if there are peer dep issues, but still outputs valid JSON
            // Only fail if there's no output at all
            if output.stdout.is_empty() {
                return Ok(Vec::new());
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let npm_list: NpmListOutput =
            serde_json::from_str(&stdout).context("Failed to parse npm list output")?;

        let mut packages = Vec::new();

        if let Some(deps) = npm_list.dependencies {
            for (name, pkg) in deps {
                // Skip npm itself
                if name == "npm" {
                    continue;
                }

                let version = pkg.version.unwrap_or_else(|| "unknown".to_string());

                // Try to read package.json for more metadata
                let pkg_metadata = prefix.as_ref().and_then(|p| read_package_json(p, &name));

                let metadata = if let Some(pkg_json) = pkg_metadata {
                    PackageMetadata {
                        description: pkg_json.description,
                        publisher: pkg_json
                            .author
                            .map(|a| a.to_string())
                            .filter(|s| !s.is_empty()),
                        homepage: pkg_json
                            .homepage
                            .or_else(|| Some(format!("https://www.npmjs.com/package/{}", name))),
                        repository: pkg_json.repository.and_then(|r| r.url()).or(pkg.resolved),
                        license: pkg_json.license,
                    }
                } else {
                    PackageMetadata {
                        description: None,
                        publisher: None,
                        homepage: Some(format!("https://www.npmjs.com/package/{}", name)),
                        repository: pkg.resolved,
                        license: None,
                    }
                };

                let mut package =
                    Package::new(&name, &name, version, Source::Npm).with_metadata(metadata);

                // Set install path if we have prefix
                if let Some(ref p) = prefix {
                    package.install_path = Some(p.join("lib/node_modules").join(&name));
                }

                packages.push(package);
            }
        }

        Ok(packages)
    }
}

fn get_npm_prefix(npm_cmd: &str) -> Option<PathBuf> {
    let output = Command::new(npm_cmd)
        .args(["config", "get", "prefix"])
        .output()
        .ok()?;

    if output.status.success() {
        let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Some(PathBuf::from(prefix))
    } else {
        None
    }
}

fn read_package_json(prefix: &Path, package_name: &str) -> Option<PackageJson> {
    let pkg_json_path = prefix
        .join("lib/node_modules")
        .join(package_name)
        .join("package.json");

    let content = std::fs::read_to_string(&pkg_json_path).ok()?;
    serde_json::from_str(&content).ok()
}
