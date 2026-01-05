use crate::model::{Package, Platform, Source};
use crate::platform::opera_extensions_dir;
use anyhow::Result;
use async_trait::async_trait;

use super::chrome::scan_chromium_extensions;

pub struct OperaScanner;

#[async_trait]
impl super::Scanner for OperaScanner {
    fn name(&self) -> &'static str {
        "Opera Extensions"
    }

    fn source(&self) -> Source {
        Source::Opera
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match opera_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        scan_chromium_extensions(&extensions_dir, Source::Opera)
    }
}
