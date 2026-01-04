mod cli;
mod cyclonedx;
mod json;
mod sarif;

pub use cli::print_cli_table;
pub use cyclonedx::print_cyclonedx;
pub use json::print_json;
pub use sarif::print_sarif;

use crate::model::ScanResult;
use anyhow::Result;

/// Output format for scan results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable table format
    Table,
    /// JSON format for programmatic use
    Json,
    /// SARIF format for GitHub Actions code scanning
    Sarif,
    /// CycloneDX SBOM format for compliance
    CycloneDx,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "cyclonedx" | "cdx" | "sbom" => Ok(OutputFormat::CycloneDx),
            _ => Err(format!(
                "Unknown format: {}. Use 'table', 'json', 'sarif', or 'cyclonedx'",
                s
            )),
        }
    }
}

pub fn print_result(result: &ScanResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => print_cli_table(result),
        OutputFormat::Json => print_json(result),
        OutputFormat::Sarif => print_sarif(result),
        OutputFormat::CycloneDx => print_cyclonedx(result),
    }
}
