use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Vscode,
    Chrome,
    Edge,
    Firefox,
    Npm,
    Homebrew,
}

impl Source {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
}

impl Platform {
    pub fn current() -> Self {
        #[cfg(target_os = "linux")]
        return Platform::Linux;
        #[cfg(target_os = "macos")]
        return Platform::MacOS;
        #[cfg(target_os = "windows")]
        return Platform::Windows;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

impl Default for PackageMetadata {
    fn default() -> Self {
        Self {
            description: None,
            publisher: None,
            homepage: None,
            repository: None,
            license: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source: Source,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_path: Option<PathBuf>,
    #[serde(flatten)]
    pub metadata: PackageMetadata,
}

impl Package {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: impl Into<String>, source: Source) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            source,
            install_path: None,
            metadata: PackageMetadata::default(),
        }
    }

    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.install_path = Some(path);
        self
    }

    pub fn with_metadata(mut self, metadata: PackageMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}
