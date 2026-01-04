use crate::model::{Package, Platform, Source};
use crate::platform::edge_extensions_dir;
use anyhow::Result;
use async_trait::async_trait;

pub struct EdgeScanner;

#[async_trait]
impl super::Scanner for EdgeScanner {
    fn name(&self) -> &'static str {
        "Edge Extensions"
    }

    fn source(&self) -> Source {
        Source::Edge
    }

    fn supported_platforms(&self) -> &[Platform] {
        &[Platform::Linux, Platform::MacOS, Platform::Windows]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match edge_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        // Edge uses the same Chromium extension format
        super::chrome::scan_chromium_extensions(&extensions_dir, Source::Edge)
    }
}
