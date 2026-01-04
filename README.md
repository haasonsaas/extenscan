# extenscan

A cross-platform CLI tool that scans locally installed extensions and packages from multiple sources, checking for security vulnerabilities, outdated versions, and generating inventory reports.

## Features

- **Multi-source scanning**: VSCode extensions, Chrome/Edge/Firefox browser extensions, NPM global packages, Homebrew packages
- **Vulnerability checking**: Integrates with OSV.dev API to detect known security vulnerabilities
- **Outdated detection**: Identifies packages with newer versions available
- **Cross-platform**: Works on Linux, macOS, and Windows
- **Multiple output formats**: CLI tables or JSON for integration with other tools
- **Caching**: 24-hour cache for API responses to improve performance
- **Configurable**: TOML config file for customizing default behavior

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
./target/release/extenscan --help
```

## Usage

### Scan all sources

```bash
extenscan scan
```

### Scan specific source

```bash
extenscan scan --source npm
extenscan scan --source vscode
extenscan scan --source chrome
```

### Output formats

```bash
# CLI table (default)
extenscan scan

# JSON output
extenscan scan --format json

# Save to file
extenscan scan --output results.json
```

### Skip checks

```bash
# Skip vulnerability checking (faster)
extenscan scan --no-vuln-check

# Skip outdated version checking
extenscan scan --no-outdated-check
```

### List available sources

```bash
extenscan list-sources
```

### Configuration

```bash
# Show config path
extenscan config --path

# Create default config
extenscan config --init

# View current config
extenscan config
```

### Cache management

```bash
# Clear cache
extenscan clear-cache

# Clear cache before scanning
extenscan scan --clear-cache
```

## Supported Sources

| Source | Description | Platforms |
|--------|-------------|-----------|
| `vscode` | VSCode/VSCodium extensions | Linux, macOS, Windows |
| `chrome` | Google Chrome extensions | Linux, macOS, Windows |
| `edge` | Microsoft Edge extensions | Linux, macOS, Windows |
| `firefox` | Firefox add-ons | Linux, macOS, Windows |
| `npm` | NPM global packages | Linux, macOS, Windows |
| `homebrew` | Homebrew packages/casks | Linux, macOS |

## Configuration File

Location: `~/.config/extenscan/config.toml`

```toml
# Cache TTL in hours (default: 24)
cache_ttl_hours = 24

# Skip vulnerability checking by default
skip_vuln_check = false

# Default output format ("table" or "json")
default_format = "table"

# Check for outdated packages
check_outdated = true
```

## License

MIT
