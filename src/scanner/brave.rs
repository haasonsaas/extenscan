use crate::model::{Package, Platform, Source};
use crate::platform::brave_extensions_dir;
use anyhow::Result;
use async_trait::async_trait;

use super::chrome::scan_chromium_extensions;

pub struct BraveScanner;

#[async_trait]
impl super::Scanner for BraveScanner {
    fn name(&self) -> &'static str {
        "Brave Extensions"
    }

    fn source(&self) -> Source {
        Source::Brave
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match brave_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        scan_chromium_extensions(&extensions_dir, Source::Brave)
    }
}
