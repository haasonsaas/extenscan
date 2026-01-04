use crate::model::{Package, PackageMetadata, Platform, Source};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use std::process::Command;

pub struct HomebrewScanner;

#[derive(Deserialize)]
struct BrewFormula {
    name: String,
    full_name: Option<String>,
    version: Option<String>,
    desc: Option<String>,
    homepage: Option<String>,
    license: Option<String>,
    installed: Vec<InstalledVersion>,
}

#[derive(Deserialize)]
struct InstalledVersion {
    version: String,
}

#[derive(Deserialize)]
struct BrewCask {
    token: String,
    name: Vec<String>,
    version: Option<String>,
    desc: Option<String>,
    homepage: Option<String>,
}

#[async_trait]
impl super::Scanner for HomebrewScanner {
    fn name(&self) -> &'static str {
        "Homebrew Packages"
    }

    fn source(&self) -> Source {
        Source::Homebrew
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let mut packages = Vec::new();

        // Scan formulae
        if let Ok(formulae) = scan_formulae() {
            packages.extend(formulae);
        }

        // Scan casks (macOS only)
        if cfg!(target_os = "macos") {
            if let Ok(casks) = scan_casks() {
                packages.extend(casks);
            }
        }

        Ok(packages)
    }
}

fn scan_formulae() -> Result<Vec<Package>> {
    let output = Command::new("brew")
        .args(["info", "--json=v2", "--installed"])
        .output()
        .context("Failed to execute brew. Is Homebrew installed?")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    #[derive(Deserialize)]
    struct BrewInfo {
        formulae: Vec<BrewFormula>,
    }

    let brew_info: BrewInfo = serde_json::from_str(&stdout)
        .context("Failed to parse brew info output")?;

    let mut packages = Vec::new();

    for formula in brew_info.formulae {
        let version = formula.installed
            .first()
            .map(|v| v.version.clone())
            .or(formula.version)
            .unwrap_or_else(|| "unknown".to_string());

        let metadata = PackageMetadata {
            description: formula.desc,
            publisher: None,
            homepage: formula.homepage,
            repository: None,
            license: formula.license,
        };

        let id = formula.full_name.unwrap_or_else(|| formula.name.clone());

        let package = Package::new(&id, &formula.name, version, Source::Homebrew)
            .with_metadata(metadata);

        packages.push(package);
    }

    Ok(packages)
}

fn scan_casks() -> Result<Vec<Package>> {
    let output = Command::new("brew")
        .args(["info", "--json=v2", "--cask", "--installed"])
        .output()
        .context("Failed to execute brew cask info")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    #[derive(Deserialize)]
    struct BrewCaskInfo {
        casks: Vec<BrewCask>,
    }

    let brew_info: BrewCaskInfo = serde_json::from_str(&stdout)
        .context("Failed to parse brew cask info output")?;

    let mut packages = Vec::new();

    for cask in brew_info.casks {
        let name = cask.name.first()
            .cloned()
            .unwrap_or_else(|| cask.token.clone());

        let version = cask.version.unwrap_or_else(|| "unknown".to_string());

        let metadata = PackageMetadata {
            description: cask.desc,
            publisher: None,
            homepage: cask.homepage,
            repository: None,
            license: None,
        };

        let package = Package::new(&cask.token, name, version, Source::Homebrew)
            .with_metadata(metadata);

        packages.push(package);
    }

    Ok(packages)
}
