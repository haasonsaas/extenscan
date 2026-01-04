mod cli;
mod json;

pub use cli::print_cli_table;
pub use json::print_json;

use crate::model::ScanResult;
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Unknown format: {}. Use 'table' or 'json'", s)),
        }
    }
}

pub fn print_result(result: &ScanResult, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Table => print_cli_table(result),
        OutputFormat::Json => print_json(result),
    }
}
