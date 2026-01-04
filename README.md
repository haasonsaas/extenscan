# extenscan

[![Build Status](https://img.shields.io/github/actions/workflow/status/haasonsaas/extenscan/ci.yml?branch=main&label=build)](https://github.com/haasonsaas/extenscan/actions)
[![License](https://img.shields.io/github/license/haasonsaas/extenscan?color=green)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg?logo=rust)](https://www.rust-lang.org)
[![GitHub release](https://img.shields.io/github/v/release/haasonsaas/extenscan?include_prereleases&label=version)](https://github.com/haasonsaas/extenscan/releases)

A cross-platform CLI tool and library that scans locally installed extensions and packages from multiple sources, checking for security vulnerabilities, outdated versions, and generating inventory reports.

## Features

- **Multi-source scanning**: VSCode extensions, Chrome/Edge/Firefox browser extensions, NPM global packages, Homebrew packages
- **Vulnerability checking**: Integrates with [OSV.dev](https://osv.dev) API to detect known security vulnerabilities
- **Outdated detection**: Identifies packages with newer versions available
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Multiple output formats**: CLI tables or JSON for integration with other tools
- **Caching**: 24-hour cache for API responses to improve performance
- **Configurable**: TOML config file for customizing default behavior
- **Library support**: Use as a Rust library in your own projects

## Installation

### From source

```bash
git clone https://github.com/haasonsaas/extenscan
cd extenscan
cargo install --path .
```

### Build manually

```bash
cargo build --release
./target/release/extenscan --help
```

## Quick Start

```bash
# Scan all sources
extenscan scan

# Scan only NPM packages
extenscan scan --source npm

# Output as JSON
extenscan scan --format json

# Skip slow checks for a quick inventory
extenscan scan --no-vuln-check --no-outdated-check
```

## CLI Usage

### Scan Commands

```bash
# Full scan of all sources
extenscan scan

# Scan specific source
extenscan scan --source npm
extenscan scan --source vscode
extenscan scan --source chrome
extenscan scan --source firefox
extenscan scan --source homebrew

# Multiple output options
extenscan scan                      # CLI table (default)
extenscan scan --format json        # JSON output
extenscan scan --output report.json # Save to file
```

### Performance Options

```bash
# Skip vulnerability checking (faster)
extenscan scan --no-vuln-check

# Skip outdated version checking
extenscan scan --no-outdated-check

# Clear cache before scanning
extenscan scan --clear-cache
```

### Other Commands

```bash
# List available sources and their status
extenscan list-sources

# Configuration management
extenscan config           # Show current config
extenscan config --init    # Create default config
extenscan config --path    # Show config file path

# Cache management
extenscan clear-cache      # Clear all cached data
```

## Library Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
extenscan = "0.1"
tokio = { version = "1", features = ["full"] }
```

### Basic Example

```rust
use extenscan::{scanner::all_scanners, Scanner, ScanResult};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut packages = Vec::new();

    for scanner in all_scanners() {
        if scanner.is_supported() {
            println!("Scanning {}...", scanner.name());
            packages.extend(scanner.scan().await?);
        }
    }

    let result = ScanResult::new(packages);
    println!("Found {} packages", result.packages.len());

    Ok(())
}
```

### Scanning a Specific Source

```rust
use extenscan::{scanner::NpmScanner, Scanner};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let scanner = NpmScanner;

    if scanner.is_supported() {
        let packages = scanner.scan().await?;
        for pkg in packages {
            println!("{}: {} ({})", pkg.name, pkg.version, pkg.source);
        }
    }

    Ok(())
}
```

### Checking for Vulnerabilities

```rust
use extenscan::{
    checker::{default_checker, VulnerabilityChecker},
    scanner::NpmScanner,
    Scanner,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let packages = NpmScanner.scan().await?;

    let checker = default_checker();
    let vulns = checker.check(&packages).await?;

    for vuln in vulns {
        println!("{}: {} - {}", vuln.severity, vuln.id, vuln.title);
    }

    Ok(())
}
```

## Architecture

```
extenscan/
├── src/
│   ├── lib.rs           # Library entry point
│   ├── main.rs          # CLI application
│   ├── cache.rs         # File-based caching
│   ├── config.rs        # TOML configuration
│   ├── platform.rs      # Cross-platform path resolution
│   ├── model/           # Core data types
│   │   ├── package.rs   # Package, Source, Platform
│   │   └── vulnerability.rs  # Vulnerability, ScanResult
│   ├── scanner/         # Package scanners
│   │   ├── vscode.rs    # VSCode extensions
│   │   ├── chrome.rs    # Chrome extensions
│   │   ├── edge.rs      # Edge extensions
│   │   ├── firefox.rs   # Firefox add-ons
│   │   ├── npm.rs       # NPM global packages
│   │   └── homebrew.rs  # Homebrew packages
│   ├── checker/         # Security checkers
│   │   ├── osv.rs       # OSV.dev vulnerability API
│   │   └── version.rs   # Version comparison
│   └── output/          # Output formatting
│       ├── cli.rs       # Terminal tables
│       └── json.rs      # JSON output
```

### Data Flow

```
┌─────────────┐    ┌──────────┐    ┌─────────────┐    ┌────────┐
│  Scanners   │───▶│ Packages │───▶│   Checkers  │───▶│ Output │
│ (6 sources) │    │   List   │    │ (vuln/ver)  │    │ (table │
└─────────────┘    └──────────┘    └─────────────┘    │  /json)│
                                          │           └────────┘
                                          ▼
                                   ┌─────────────┐
                                   │    Cache    │
                                   │ (24h file)  │
                                   └─────────────┘
```

## Supported Sources

| Source | Description | Platforms | Vulnerability Check | Version Check |
|--------|-------------|-----------|---------------------|---------------|
| `vscode` | VSCode/VSCodium extensions | All | - | - |
| `chrome` | Google Chrome extensions | All | - | - |
| `edge` | Microsoft Edge extensions | All | - | - |
| `firefox` | Firefox add-ons | All | - | - |
| `npm` | NPM global packages | All | OSV.dev | npm registry |
| `homebrew` | Homebrew packages/casks | Linux, macOS | OSV.dev | Homebrew API |

## Configuration

Configuration file location:
- Linux: `~/.config/extenscan/config.toml`
- macOS: `~/Library/Application Support/extenscan/config.toml`
- Windows: `%APPDATA%\extenscan\config.toml`

### Example Configuration

```toml
# How long to cache API responses (hours)
cache_ttl_hours = 24

# Skip vulnerability checking by default
skip_vuln_check = false

# Default output format ("table" or "json")
default_format = "table"

# Check for outdated packages by default
check_outdated = true

# Sources to scan by default
default_sources = ["vscode", "chrome", "edge", "firefox", "npm", "homebrew"]
```

## Cache

Cached data is stored at:
- Linux: `~/.cache/extenscan/`
- macOS: `~/Library/Caches/extenscan/`
- Windows: `%LOCALAPPDATA%\extenscan\cache\`

Cache entries expire after 24 hours by default (configurable).

## Output Examples

### Table Output

```
╭────────┬───────────────────────────┬─────────┬───────────────────────────╮
│ Source │ Name                      │ Version │ ID                        │
├────────┼───────────────────────────┼─────────┼───────────────────────────┤
│ NPM    │ typescript                │ 5.3.3   │ typescript                │
│ NPM    │ @anthropic-ai/claude-code │ 2.0.75  │ @anthropic-ai/claude-code │
╰────────┴───────────────────────────┴─────────┴───────────────────────────╯

╭───────────────────────────┬─────────┬────────╮
│ Package                   │ Current │ Latest │
├───────────────────────────┼─────────┼────────┤
│ typescript                │ 5.3.3   │ 5.4.2  │
╰───────────────────────────┴─────────┴────────╯
```

### JSON Output

```json
{
  "packages": [
    {
      "id": "typescript",
      "name": "typescript",
      "version": "5.3.3",
      "source": "npm",
      "homepage": "https://www.npmjs.com/package/typescript"
    }
  ],
  "vulnerabilities": [],
  "outdated": [
    {
      "package_id": "typescript",
      "current_version": "5.3.3",
      "latest_version": "5.4.2"
    }
  ],
  "scan_time": "2024-01-15T10:30:00Z"
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
