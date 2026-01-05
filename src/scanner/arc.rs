use crate::model::{Package, Platform, Source};
use crate::platform::arc_extensions_dir;
use anyhow::Result;
use async_trait::async_trait;

use super::chrome::scan_chromium_extensions;

pub struct ArcScanner;

#[async_trait]
impl super::Scanner for ArcScanner {
    fn name(&self) -> &'static str {
        "Arc Extensions"
    }

    fn source(&self) -> Source {
        Source::Arc
    }

    fn supported_platforms(&self) -> &[Platform] {
        // Arc is macOS-only
        &[Platform::MacOS]
    }

    async fn scan(&self) -> Result<Vec<Package>> {
        let extensions_dir = match arc_extensions_dir() {
            Some(dir) => dir,
            None => return Ok(Vec::new()),
        };

        scan_chromium_extensions(&extensions_dir, Source::Arc)
    }
}
