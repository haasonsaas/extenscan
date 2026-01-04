mod vscode;
mod chrome;
mod edge;
mod firefox;
mod npm;
mod homebrew;

pub use vscode::VscodeScanner;
pub use chrome::ChromeScanner;
pub use edge::EdgeScanner;
pub use firefox::FirefoxScanner;
pub use npm::NpmScanner;
pub use homebrew::HomebrewScanner;

use crate::model::{Package, Platform, Source};
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn source(&self) -> Source;
    fn supported_platforms(&self) -> &[Platform];

    fn is_supported(&self) -> bool {
        let current = Platform::current();
        self.supported_platforms().contains(&current)
    }

    async fn scan(&self) -> Result<Vec<Package>>;
}

pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(VscodeScanner),
        Box::new(ChromeScanner),
        Box::new(EdgeScanner),
        Box::new(FirefoxScanner),
        Box::new(NpmScanner),
        Box::new(HomebrewScanner),
    ]
}

pub fn get_scanner(source: Source) -> Box<dyn Scanner> {
    match source {
        Source::Vscode => Box::new(VscodeScanner),
        Source::Chrome => Box::new(ChromeScanner),
        Source::Edge => Box::new(EdgeScanner),
        Source::Firefox => Box::new(FirefoxScanner),
        Source::Npm => Box::new(NpmScanner),
        Source::Homebrew => Box::new(HomebrewScanner),
    }
}
