//! Package and source type definitions.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The origin source of a scanned package or extension.
///
/// Each variant represents a different package manager or extension store
/// that extenscan can scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Visual Studio Code / VSCodium extensions
    Vscode,
    /// Google Chrome browser extensions
    Chrome,
    /// Microsoft Edge browser extensions
    Edge,
    /// Mozilla Firefox browser add-ons
    Firefox,
    /// NPM global packages
    Npm,
    /// Homebrew formulae and casks
    Homebrew,
}

impl Source {
    /// Returns the lowercase identifier string for this source.
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Source;
    ///
    /// assert_eq!(Source::Npm.as_str(), "npm");
    /// assert_eq!(Source::Vscode.as_str(), "vscode");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::Vscode => "vscode",
            Source::Chrome => "chrome",
            Source::Edge => "edge",
            Source::Firefox => "firefox",
            Source::Npm => "npm",
            Source::Homebrew => "homebrew",
        }
    }

    /// Returns a human-readable display name for this source.
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Source;
    ///
    /// assert_eq!(Source::Npm.display_name(), "NPM");
    /// assert_eq!(Source::Vscode.display_name(), "VSCode");
    /// ```
    pub fn display_name(&self) -> &'static str {
        match self {
            Source::Vscode => "VSCode",
            Source::Chrome => "Chrome",
            Source::Edge => "Edge",
            Source::Firefox => "Firefox",
            Source::Npm => "NPM",
            Source::Homebrew => "Homebrew",
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// The operating system platform.
///
/// Used to determine platform-specific paths and scanner availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Linux operating system
    Linux,
    /// macOS operating system
    MacOS,
    /// Windows operating system
    Windows,
}

impl Platform {
    /// Returns the current platform at compile time.
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::Platform;
    ///
    /// let current = Platform::current();
    /// // Returns Linux, MacOS, or Windows depending on compilation target
    /// ```
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(target_os = "macos")]
        return Platform::MacOS;
        #[cfg(target_os = "windows")]
        return Platform::Windows;
    }
}

/// Optional metadata associated with a package.
///
/// Not all fields are populated for every package; availability depends
/// on what information the source provides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// A brief description of the package's purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The publisher or author of the package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,

    /// URL to the package's homepage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,

    /// URL to the package's source repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,

    /// The package's license identifier (e.g., "MIT", "Apache-2.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

/// A scanned package or extension.
///
/// Represents a single installed package discovered by a scanner,
/// including its identity, version, source, and optional metadata.
///
/// # Example
///
/// ```
/// use extenscan::{Package, Source};
///
/// let pkg = Package::new("lodash", "lodash", "4.17.21", Source::Npm);
/// assert_eq!(pkg.name, "lodash");
/// assert_eq!(pkg.source, Source::Npm);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    /// Unique identifier for the package within its source.
    ///
    /// Format varies by source:
    /// - VSCode: `publisher.extension-name`
    /// - Chrome/Edge: Extension ID (hash)
    /// - NPM: Package name (e.g., `@scope/name`)
    /// - Homebrew: Formula name
    pub id: String,

    /// Human-readable display name.
    pub name: String,

    /// Installed version string.
    pub version: String,

    /// The source this package was discovered from.
    pub source: Source,

    /// Local filesystem path where the package is installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_path: Option<PathBuf>,

    /// Additional metadata about the package.
    #[serde(flatten)]
    pub metadata: PackageMetadata,
}

impl Package {
    /// Creates a new package with the given identity and source.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier within the source
    /// * `name` - Human-readable display name
    /// * `version` - Version string
    /// * `source` - The package source
    ///
    /// # Example
    ///
    /// ```
    /// use extenscan::{Package, Source};
    ///
    /// let pkg = Package::new("express", "express", "4.18.2", Source::Npm);
    /// ```
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        source: Source,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            source,
            install_path: None,
            metadata: PackageMetadata::default(),
        }
    }

    /// Sets the installation path for this package.
    ///
    /// This is a builder-style method that returns `self` for chaining.
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.install_path = Some(path);
        self
    }

    /// Sets the metadata for this package.
    ///
    /// This is a builder-style method that returns `self` for chaining.
    pub fn with_metadata(mut self, metadata: PackageMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}
