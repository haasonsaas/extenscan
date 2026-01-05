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

/// Returns the path to Brave extensions directory.
///
/// Platform-specific locations:
/// - Linux: `~/.config/BraveSoftware/Brave-Browser/Default/Extensions/`
/// - macOS: `~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions/`
/// - Windows: `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions\`
///
/// Returns `None` if the directory doesn't exist.
pub fn brave_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config
                .join("BraveSoftware")
                .join("Brave-Browser")
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
                .join("BraveSoftware")
                .join("Brave-Browser")
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
                .join("BraveSoftware")
                .join("Brave-Browser")
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

/// Returns the path to Arc extensions directory.
///
/// Arc is only available on macOS.
///
/// Location: `~/Library/Application Support/Arc/User Data/Default/Extensions/`
///
/// Returns `None` if the directory doesn't exist or on non-macOS platforms.
pub fn arc_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::MacOS => {
            let home = dirs::home_dir()?;
            let path = home
                .join("Library")
                .join("Application Support")
                .join("Arc")
                .join("User Data")
                .join("Default")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        _ => None, // Arc is macOS-only
    }
}

/// Returns the path to Opera extensions directory.
///
/// Platform-specific locations:
/// - Linux: `~/.config/opera/Extensions/`
/// - macOS: `~/Library/Application Support/com.operasoftware.Opera/Extensions/`
/// - Windows: `%APPDATA%\Opera Software\Opera Stable\Extensions\`
///
/// Returns `None` if the directory doesn't exist.
pub fn opera_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config.join("opera").join("Extensions");
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
                .join("com.operasoftware.Opera")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
        Platform::Windows => {
            let roaming = dirs::data_dir()?;
            let path = roaming
                .join("Opera Software")
                .join("Opera Stable")
                .join("Extensions");
            if path.exists() {
                Some(path)
            } else {
                None
            }
        }
    }
}

/// Returns the path to Vivaldi extensions directory.
///
/// Platform-specific locations:
/// - Linux: `~/.config/vivaldi/Default/Extensions/`
/// - macOS: `~/Library/Application Support/Vivaldi/Default/Extensions/`
/// - Windows: `%LOCALAPPDATA%\Vivaldi\User Data\Default\Extensions\`
///
/// Returns `None` if the directory doesn't exist.
pub fn vivaldi_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config.join("vivaldi").join("Default").join("Extensions");
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
                .join("Vivaldi")
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
                .join("Vivaldi")
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

/// Returns the path to Chromium extensions directory.
///
/// Platform-specific locations:
/// - Linux: `~/.config/chromium/Default/Extensions/`
/// - macOS: `~/Library/Application Support/Chromium/Default/Extensions/`
/// - Windows: `%LOCALAPPDATA%\Chromium\User Data\Default\Extensions\`
///
/// Returns `None` if the directory doesn't exist.
pub fn chromium_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config.join("chromium").join("Default").join("Extensions");
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
                .join("Chromium")
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
                .join("Chromium")
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
