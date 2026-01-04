//! Cross-platform path resolution.
//!
//! This module provides functions for finding platform-specific paths
//! where extensions and packages are installed.
//!
//! All functions return `Option<PathBuf>` - returning `None` if the
//! directory doesn't exist or can't be determined.

use crate::model::Platform;
use std::path::PathBuf;

/// Returns the path to VSCode extensions directory.
///
/// Location: `~/.vscode/extensions/` on all platforms.
///
/// Returns `None` if the directory doesn't exist.
pub fn vscode_extensions_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let path = home.join(".vscode").join("extensions");
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

/// Returns the path to Chrome extensions directory.
///
/// Platform-specific locations:
/// - Linux: `~/.config/google-chrome/Default/Extensions/`
/// - macOS: `~/Library/Application Support/Google/Chrome/Default/Extensions/`
/// - Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\`
///
/// Returns `None` if the directory doesn't exist.
pub fn chrome_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config
                .join("google-chrome")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::MacOS => {
            let home = dirs::home_dir()?;
            let path = home
                .join("Library")
                .join("Application Support")
                .join("Google")
                .join("Chrome")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::Windows => {
            let local = dirs::data_local_dir()?;
            let path = local
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
    }
}

/// Returns the path to Edge extensions directory.
///
/// Platform-specific locations:
/// - Linux: `~/.config/microsoft-edge/Default/Extensions/`
/// - macOS: `~/Library/Application Support/Microsoft Edge/Default/Extensions/`
/// - Windows: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\`
///
/// Returns `None` if the directory doesn't exist.
pub fn edge_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config
                .join("microsoft-edge")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::MacOS => {
            let home = dirs::home_dir()?;
            let path = home
                .join("Library")
                .join("Application Support")
                .join("Microsoft Edge")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::Windows => {
            let local = dirs::data_local_dir()?;
            let path = local
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
    }
}

/// Returns the path to Firefox profiles directory.
///
/// Platform-specific locations:
/// - Linux: `~/.mozilla/firefox/`
/// - macOS: `~/Library/Application Support/Firefox/Profiles/`
/// - Windows: `%APPDATA%\Mozilla\Firefox\Profiles\`
///
/// Returns `None` if the directory doesn't exist.
pub fn firefox_profiles_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let home = dirs::home_dir()?;
            let path = home.join(".mozilla").join("firefox");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::MacOS => {
            let home = dirs::home_dir()?;
            let path = home
                .join("Library")
                .join("Application Support")
                .join("Firefox")
                .join("Profiles");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::Windows => {
            let roaming = dirs::data_dir()?;
            let path = roaming.join("Mozilla").join("Firefox").join("Profiles");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
    }
}

/// Returns the cache directory for extenscan.
///
/// Platform-specific locations:
/// - Linux: `~/.cache/extenscan/`
/// - macOS: `~/Library/Caches/extenscan/`
/// - Windows: `%LOCALAPPDATA%\extenscan\cache\`
///
/// Falls back to `/tmp/extenscan/` if no cache directory can be determined.
pub fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("extenscan")
}
