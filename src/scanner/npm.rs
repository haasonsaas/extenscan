use crate::model::{Package, PackageMetadata, Platform, Source};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
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
        let npm_cmd = if cfg!(target_os = "windows") { "npm.cmd" } else { "npm" };

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
        let npm_list: NpmListOutput = serde_json::from_str(&stdout)
            .context("Failed to parse npm list output")?;

        let mut packages = Vec::new();

        if let Some(deps) = npm_list.dependencies {
            for (name, pkg) in deps {
                // Skip npm itself
                if name == "npm" {
                    continue;
                }

                let version = pkg.version.unwrap_or_else(|| "unknown".to_string());

                let metadata = PackageMetadata {
                    description: None,
                    publisher: None,
                    homepage: Some(format!("https://www.npmjs.com/package/{}", name)),
                    repository: pkg.resolved,
                    license: None,
                };

                let package = Package::new(&name, &name, version, Source::Npm)
                    .with_metadata(metadata);

                packages.push(package);
            }
        }

        Ok(packages)
    }
}
