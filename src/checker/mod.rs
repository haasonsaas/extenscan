mod osv;
mod version;

pub use osv::OsvChecker;
pub use version::VersionChecker;

use crate::model::{Package, Vulnerability};
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait VulnerabilityChecker: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self, packages: &[Package]) -> Result<Vec<Vulnerability>>;
}

pub fn default_checker() -> OsvChecker {
    OsvChecker::new()
}

pub fn default_version_checker() -> VersionChecker {
    VersionChecker::new()
}
