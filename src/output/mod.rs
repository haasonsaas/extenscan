mod cli;
mod json;
mod sarif;

pub use cli::print_cli_table;
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
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            _ => Err(format!(
                "Unknown format: {}. Use 'table', 'json', or 'sarif'",
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
    }
}
