use crate::model::ScanResult;
use anyhow::Result;

pub fn print_json(result: &ScanResult) -> Result<()> {
    let json = serde_json::to_string_pretty(result)?;
    println!("{}", json);
    Ok(())
}
