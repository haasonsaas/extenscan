use crate::cache::Cache;
use crate::model::{OutdatedInfo, Package, Source};
use anyhow::Result;
use serde::Deserialize;

pub struct VersionChecker {
    client: reqwest::Client,
    cache: Cache,
}

impl VersionChecker {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            cache: Cache::new(),
        }
    }

    pub fn with_cache(cache: Cache) -> Self {
        Self {
            client: reqwest::Client::new(),
            cache,
        }
    }

    pub async fn check_outdated(&self, packages: &[Package]) -> Result<Vec<OutdatedInfo>> {
        let mut outdated = Vec::new();

        for package in packages {
            if let Some(info) = self.check_package(package).await {
                outdated.push(info);
            }
        }

        Ok(outdated)
    }

    async fn check_package(&self, package: &Package) -> Option<OutdatedInfo> {
        let latest = match package.source {
            Source::Npm => self.get_npm_latest(&package.name).await,
            Source::Homebrew => self.get_homebrew_latest(&package.name).await,
            // Browser extensions and VSCode - would need marketplace APIs
            // Skip for now as they're more complex
            _ => None,
        };

        let latest = latest?;

        // Compare versions
        if is_newer(&latest, &package.version) {
            Some(OutdatedInfo {
                package_id: package.id.clone(),
                current_version: package.version.clone(),
                latest_version: latest,
            })
        } else {
            None
        }
    }

    async fn get_npm_latest(&self, name: &str) -> Option<String> {
        let cache_key = format!("npm_version_{}", name);

        // Check cache first
        if let Some(version) = self.cache.get::<String>(&cache_key) {
            return Some(version);
        }

        #[derive(Deserialize)]
        struct NpmPackageInfo {
            #[serde(rename = "dist-tags")]
            dist_tags: Option<DistTags>,
        }

        #[derive(Deserialize)]
        struct DistTags {
            latest: Option<String>,
        }

        let url = format!("https://registry.npmjs.org/{}", name);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;

        let info: NpmPackageInfo = response.json().await.ok()?;
        let version = info.dist_tags?.latest?;

        // Cache the result
        let _ = self.cache.set(&cache_key, &version);

        Some(version)
    }

    async fn get_homebrew_latest(&self, name: &str) -> Option<String> {
        let cache_key = format!("brew_version_{}", name);

        // Check cache first
        if let Some(version) = self.cache.get::<String>(&cache_key) {
            return Some(version);
        }

        #[derive(Deserialize)]
        struct BrewFormula {
            versions: BrewVersions,
        }

        #[derive(Deserialize)]
        struct BrewVersions {
            stable: Option<String>,
        }

        let url = format!("https://formulae.brew.sh/api/formula/{}.json", name);

        let response = self.client.get(&url).send().await.ok()?;

        if !response.status().is_success() {
            return None;
        }

        let info: BrewFormula = response.json().await.ok()?;
        let version = info.versions.stable?;

        // Cache the result
        let _ = self.cache.set(&cache_key, &version);

        Some(version)
    }
}

impl Default for VersionChecker {
    fn default() -> Self {
        Self::new()
    }
}

fn is_newer(latest: &str, current: &str) -> bool {
    // Try semver comparison first
    if let (Ok(latest_ver), Ok(current_ver)) = (
        semver::Version::parse(latest.trim_start_matches('v')),
        semver::Version::parse(current.trim_start_matches('v')),
    ) {
        return latest_ver > current_ver;
    }

    // Fall back to string comparison for non-semver versions
    // This handles cases like "unknown" or weird version strings
    if current == "unknown" {
        return false;
    }

    latest != current
}
