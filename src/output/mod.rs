mod cli;
mod cyclonedx;
mod html;
mod json;
mod sarif;

pub use cli::print_cli_table;
pub use cyclonedx::print_cyclonedx;
pub use html::print_html;
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
    /// HTML report format
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "cyclonedx" | "cdx" | "sbom" => Ok(OutputFormat::CycloneDx),
            "html" => Ok(OutputFormat::Html),
            _ => Err(format!(
                "Unknown format: {}. Use 'table', 'json', 'sarif', 'cyclonedx', or 'html'",
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
        OutputFormat::Html => print_html(result),
    }
}

/// Format result to string for file output
pub fn format_result_to_string(result: &ScanResult, format: OutputFormat) -> Result<String> {
    match format {
        OutputFormat::Json => Ok(serde_json::to_string_pretty(result)?),
        OutputFormat::Html => Ok(html::generate_html_string(result)),
        OutputFormat::Sarif => Ok(sarif::generate_sarif_string(result)?),
        OutputFormat::CycloneDx => Ok(cyclonedx::generate_cyclonedx_string(result)?),
        OutputFormat::Table => {
            // For table format, just use JSON as the file output
            Ok(serde_json::to_string_pretty(result)?)
        }
    }
}
