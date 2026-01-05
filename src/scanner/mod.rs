//! Package and extension scanners.
//!
//! This module provides the [`Scanner`] trait and implementations for
//! discovering installed packages from various sources.
//!
//! # Available Scanners
//!
//! | Scanner | Source | Platforms |
//! |---------|--------|-----------|
//! | [`VscodeScanner`] | VSCode extensions | All |
//! | [`ChromeScanner`] | Chrome extensions | All |
//! | [`EdgeScanner`] | Edge extensions | All |
//! | [`FirefoxScanner`] | Firefox add-ons | All |
//! | [`BraveScanner`] | Brave extensions | All |
//! | [`ArcScanner`] | Arc extensions | macOS |
//! | [`OperaScanner`] | Opera extensions | All |
//! | [`VivaldiScanner`] | Vivaldi extensions | All |
//! | [`ChromiumScanner`] | Chromium extensions | All |
//! | [`NpmScanner`] | NPM global packages | All |
//! | [`HomebrewScanner`] | Homebrew packages | Linux, macOS |
//!
//! # Example
//!
//! ```no_run
//! use extenscan::scanner::{all_scanners, Scanner};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     for scanner in all_scanners() {
//!         if scanner.is_supported() {
//!             println!("Scanning {}...", scanner.name());
//!             let packages = scanner.scan().await?;
//!             println!("Found {} packages", packages.len());
//!         }
//!     }
//!     Ok(())
//! }
//! ```

mod arc;
mod brave;
pub(crate) mod chrome;
mod chromium;
mod edge;
mod firefox;
mod homebrew;
mod npm;
mod opera;
mod vivaldi;
mod vscode;

pub use arc::ArcScanner;
pub use brave::BraveScanner;
pub use chrome::ChromeScanner;
pub use chromium::ChromiumScanner;
pub use edge::EdgeScanner;
pub use firefox::FirefoxScanner;
pub use homebrew::HomebrewScanner;
pub use npm::NpmScanner;
pub use opera::OperaScanner;
pub use vivaldi::VivaldiScanner;
pub use vscode::VscodeScanner;

use crate::model::{Package, Platform, Source};
use anyhow::Result;
use async_trait::async_trait;

/// Trait for scanning installed packages from a specific source.
///
/// Implementors of this trait can discover packages installed on the system
/// from a particular package manager or extension store.
///
/// # Example
///
/// ```no_run
/// use extenscan::scanner::{NpmScanner, Scanner};
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let scanner = NpmScanner;
///
///     if scanner.is_supported() {
///         let packages = scanner.scan().await?;
///         for pkg in packages {
///             println!("{}: {}", pkg.name, pkg.version);
///         }
///     }
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Returns the human-readable name of this scanner.
    fn name(&self) -> &'static str;

    /// Returns the source type this scanner handles.
    fn source(&self) -> Source;

    /// Returns the platforms this scanner supports.
    fn supported_platforms(&self) -> &[Platform];

    /// Returns true if this scanner is supported on the current platform.
    ///
    /// This is a convenience method that checks if the current platform
    /// is in the list returned by [`supported_platforms`](Self::supported_platforms).
    fn is_supported(&self) -> bool {
        let current = Platform::current();
        self.supported_platforms().contains(&current)
    }

    /// Scans for installed packages and returns them.
    ///
    /// # Errors
    ///
    /// Returns an error if the scan fails (e.g., directory not found,
    /// permission denied, or external command fails).
    async fn scan(&self) -> Result<Vec<Package>>;
}

/// Returns a list of all available scanners.
///
/// This includes scanners for all supported sources. Use [`Scanner::is_supported`]
/// to check if a scanner works on the current platform.
///
/// # Example
///
/// ```
/// use extenscan::scanner::all_scanners;
///
/// let scanners = all_scanners();
/// assert_eq!(scanners.len(), 11); // All browser + package manager scanners
/// ```
pub fn all_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(VscodeScanner),
        Box::new(ChromeScanner),
        Box::new(EdgeScanner),
        Box::new(FirefoxScanner),
        Box::new(BraveScanner),
        Box::new(ArcScanner),
        Box::new(OperaScanner),
        Box::new(VivaldiScanner),
        Box::new(ChromiumScanner),
        Box::new(NpmScanner),
        Box::new(HomebrewScanner),
    ]
}

/// Returns the scanner for a specific source.
///
/// # Arguments
///
/// * `source` - The source to get a scanner for
///
/// # Example
///
/// ```
/// use extenscan::{Source, scanner::get_scanner};
///
/// let scanner = get_scanner(Source::Npm);
/// assert_eq!(scanner.name(), "NPM Global Packages");
/// ```
pub fn get_scanner(source: Source) -> Box<dyn Scanner> {
    match source {
        Source::Vscode => Box::new(VscodeScanner),
        Source::Chrome => Box::new(ChromeScanner),
        Source::Edge => Box::new(EdgeScanner),
        Source::Firefox => Box::new(FirefoxScanner),
        Source::Brave => Box::new(BraveScanner),
        Source::Arc => Box::new(ArcScanner),
        Source::Opera => Box::new(OperaScanner),
        Source::Vivaldi => Box::new(VivaldiScanner),
        Source::Chromium => Box::new(ChromiumScanner),
        Source::Npm => Box::new(NpmScanner),
        Source::Homebrew => Box::new(HomebrewScanner),
    }
}
