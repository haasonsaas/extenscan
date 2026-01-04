# Contributing to extenscan

Thank you for your interest in contributing to extenscan! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/extenscan
   cd extenscan
   ```
3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/haasonsaas/extenscan
   ```
4. Build the project:
   ```bash
   cargo build
   ```
5. Run tests:
   ```bash
   cargo test
   ```

## Making Changes

### Branching Strategy

- Create a new branch for each feature or bug fix
- Use descriptive branch names: `feature/add-pip-scanner`, `fix/chrome-path-windows`
- Keep branches focused on a single change

### Code Style

- Follow standard Rust formatting: `cargo fmt`
- Ensure no clippy warnings: `cargo clippy`
- Add rustdoc comments to all public APIs
- Keep functions focused and reasonably sized

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb in present tense: "Add", "Fix", "Update", "Remove"
- Keep the first line under 72 characters
- Reference issues when applicable: "Fix #123: Handle missing config file"

### Adding a New Scanner

To add support for a new package source:

1. Create a new file in `src/scanner/` (e.g., `pip.rs`)
2. Implement the `Scanner` trait:
   ```rust
   pub struct PipScanner;

   #[async_trait]
   impl Scanner for PipScanner {
       fn name(&self) -> &'static str { "Pip Packages" }
       fn source(&self) -> Source { Source::Pip }
       fn supported_platforms(&self) -> &[Platform] { &[...] }
       async fn scan(&self) -> Result<Vec<Package>> { ... }
   }
   ```
3. Add the `Source` variant to `src/model/package.rs`
4. Register the scanner in `src/scanner/mod.rs`
5. Add platform paths to `src/platform.rs` if needed
6. Update documentation and tests

### Adding Vulnerability/Version Checking

To add checking support for a new source:

1. For vulnerability checking: Add ecosystem mapping in `src/checker/osv.rs`
2. For version checking: Add registry API in `src/checker/version.rs`
3. Both checkers use caching - ensure new checks are cache-aware

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name
```

### Test Guidelines

- Add tests for new functionality
- Test edge cases and error conditions
- Use meaningful test names that describe the scenario

## Documentation

- Update README.md for user-facing changes
- Update CHANGELOG.md following Keep a Changelog format
- Add rustdoc comments for all public items
- Include examples in documentation where helpful

## Submitting Changes

### Pull Request Process

1. Ensure all tests pass: `cargo test`
2. Ensure code is formatted: `cargo fmt`
3. Ensure no clippy warnings: `cargo clippy`
4. Update documentation as needed
5. Push your branch and create a pull request
6. Fill out the PR template with relevant details
7. Link any related issues

### PR Guidelines

- Keep PRs focused on a single change
- Provide a clear description of what and why
- Include testing instructions if applicable
- Be responsive to review feedback

## Reporting Issues

### Bug Reports

Please include:
- Operating system and version
- Rust version (`rustc --version`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant error messages or logs

### Feature Requests

Please include:
- Clear description of the feature
- Use case and motivation
- Possible implementation approach (optional)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow

## Questions?

Feel free to open an issue for questions or discussions about contributing.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
