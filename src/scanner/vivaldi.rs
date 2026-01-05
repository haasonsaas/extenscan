use crate::model::{Package, Platform, Source};
use crate::platform::vivaldi_extensions_dir;
use anyhow::Result;
use async_trait::async_trait;

use super::chrome::scan_chromium_extensions;

pub struct VivaldiScanner;

#[async_trait]
impl super::Scanner for VivaldiScanner {
    fn name(&self) -> &'static str {
        "Vivaldi Extensions"
    }

    fn source(&self) -> Source {
        Source::Vivaldi
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match vivaldi_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        scan_chromium_extensions(&extensions_dir, Source::Vivaldi)
    }
}
