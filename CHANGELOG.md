# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-04

### Added

- Initial release of extenscan
- **Multi-source scanning**
  - VSCode/VSCodium extensions
  - Google Chrome extensions
  - Microsoft Edge extensions
  - Mozilla Firefox add-ons
  - NPM global packages
  - Homebrew packages and casks
- **Security features**
  - Vulnerability checking via OSV.dev API
  - Support for CVE and GHSA identifiers
  - Severity classification (Critical, High, Medium, Low)
- **Version management**
  - Outdated package detection
  - Version comparison for NPM and Homebrew packages
  - Latest version lookup from package registries
- **Output formats**
  - CLI table output with colored severity indicators
  - JSON output for machine processing
  - File output option
- **Performance**
  - 24-hour file-based caching for API responses
  - Configurable cache TTL
  - Cache clearing commands
- **Configuration**
  - TOML configuration file support
  - Cross-platform config paths
  - Per-setting defaults
- **CLI features**
  - Progress indicators during scanning
  - Source filtering
  - Skip flags for vulnerability and outdated checks
- **Library support**
  - Full Rust library with public API
  - Async/await support with tokio
  - Comprehensive rustdoc documentation

### Platforms

- Linux (x86_64)
- macOS (x86_64, arm64)
- Windows (x86_64)

[Unreleased]: https://github.com/haasonsaas/extenscan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/haasonsaas/extenscan/releases/tag/v0.1.0
