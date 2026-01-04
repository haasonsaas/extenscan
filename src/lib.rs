//! # extenscan
//!
//! A cross-platform library for scanning installed extensions and packages from multiple sources,
//! checking for security vulnerabilities, outdated versions, and generating inventory reports.
//!
//! ## Features
//!
//! - **Multi-source scanning**: VSCode, Chrome, Edge, Firefox, NPM, Homebrew
//! - **Vulnerability detection**: Integration with OSV.dev API
//! - **Outdated package detection**: Checks package registries for latest versions
//! - **Cross-platform**: Works on Linux, macOS, and Windows
//!
//! ## Example
//!
//! ```no_run
//! use extenscan::{scanner::all_scanners, Scanner, ScanResult};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut all_packages = Vec::new();
//!
//!     for scanner in all_scanners() {
//!         if scanner.is_supported() {
//!             let packages = scanner.scan().await?;
//!             all_packages.extend(packages);
//!         }
//!     }
//!
//!     let result = ScanResult::new(all_packages);
//!     println!("Found {} packages", result.packages.len());
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The library is organized into several modules:
//!
//! - [`scanner`] - Traits and implementations for scanning different package sources
//! - [`checker`] - Vulnerability and version checking against external APIs
//! - [`model`] - Core data types for packages, vulnerabilities, and scan results
//! - [`cache`] - File-based caching for API responses
//! - [`config`] - Configuration file handling
//! - [`output`] - Formatting scan results for display
//! - [`platform`] - Cross-platform path resolution

pub mod cache;
pub mod checker;
pub mod config;
pub mod model;
pub mod output;
pub mod platform;
pub mod scanner;

pub use cache::Cache;
pub use config::Config;
pub use model::{Package, Platform, ScanResult, Source, Vulnerability};
pub use scanner::Scanner;
