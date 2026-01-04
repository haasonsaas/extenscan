use crate::model::Platform;
use std::path::PathBuf;

pub fn vscode_extensions_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let path = home.join(".vscode").join("extensions");
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

pub fn chrome_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config.join("google-chrome").join("Default").join("Extensions");
            if path.exists() { Some(path) } else { None }
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
            if path.exists() { Some(path) } else { None }
        }
        Platform::Windows => {
            let local = dirs::data_local_dir()?;
            let path = local
                .join("Google")
                .join("Chrome")
                .join("User Data")
                .join("Default")
                .join("Extensions");
            if path.exists() { Some(path) } else { None }
        }
    }
}

pub fn edge_extensions_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let config = dirs::config_dir()?;
            let path = config.join("microsoft-edge").join("Default").join("Extensions");
            if path.exists() { Some(path) } else { None }
        }
        Platform::MacOS => {
            let home = dirs::home_dir()?;
            let path = home
                .join("Library")
                .join("Application Support")
                .join("Microsoft Edge")
                .join("Default")
                .join("Extensions");
            if path.exists() { Some(path) } else { None }
        }
        Platform::Windows => {
            let local = dirs::data_local_dir()?;
            let path = local
                .join("Microsoft")
                .join("Edge")
                .join("User Data")
                .join("Default")
                .join("Extensions");
            if path.exists() { Some(path) } else { None }
        }
    }
}

pub fn firefox_profiles_dir() -> Option<PathBuf> {
    match Platform::current() {
        Platform::Linux => {
            let home = dirs::home_dir()?;
            let path = home.join(".mozilla").join("firefox");
            if path.exists() { Some(path) } else { None }
        }
        Platform::MacOS => {
            let home = dirs::home_dir()?;
            let path = home
                .join("Library")
                .join("Application Support")
                .join("Firefox")
                .join("Profiles");
            if path.exists() { Some(path) } else { None }
        }
        Platform::Windows => {
            let roaming = dirs::data_dir()?;
            let path = roaming
                .join("Mozilla")
                .join("Firefox")
                .join("Profiles");
            if path.exists() { Some(path) } else { None }
        }
    }
}

pub fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("extenscan")
}
