//! Core data types for packages, vulnerabilities, and scan results.
//!
//! This module contains the fundamental types used throughout extenscan:
//!
//! - [`Package`] - A discovered package or extension
//! - [`Source`] - The origin of a package (NPM, Chrome, etc.)
//! - [`Platform`] - Operating system platform
//! - [`Vulnerability`] - A security vulnerability
//! - [`ScanResult`] - Complete scan results
//!
//! # Example
//!
//! ```
//! use extenscan::{Package, Source, ScanResult};
//!
//! let package = Package::new("lodash", "lodash", "4.17.21", Source::Npm);
//! let result = ScanResult::new(vec![package]);
//!
//! println!("Scanned {} packages", result.packages.len());
//! ```

mod package;
mod vulnerability;

pub use package::*;
pub use vulnerability::*;
