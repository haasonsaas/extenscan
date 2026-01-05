//! SARIF (Static Analysis Results Interchange Format) output for GitHub Actions integration.
//!
//! When used with `--format sarif`, the output can be uploaded to GitHub Code Scanning
//! to show vulnerability annotations directly on pull requests.

use crate::model::{ScanResult, Severity};
use anyhow::Result;
use serde::Serialize;

/// SARIF v2.1.0 schema root
#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    full_description: Option<SarifMessage>,
    #[serde(rename = "helpUri")]
    help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifRuleConfiguration,
}

#[derive(Serialize)]
struct SarifRuleConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
    #[serde(rename = "uriBaseId")]
    uri_base_id: Option<&'static str>,
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Unknown => "note",
    }
}

/// Generate and print SARIF output
pub fn print_sarif(result: &ScanResult) -> Result<()> {
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for vuln in &result.vulnerabilities {
        // Find the package to get its path
        let package = result.packages.iter().find(|p| p.id == vuln.package_id);

        let location_uri = package
            .and_then(|p| p.install_path.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| vuln.package_id.clone());

        // Create a rule for each unique vulnerability
        let rule = SarifRule {
            id: vuln.id.clone(),
            name: vuln.title.clone(),
            short_description: SarifMessage {
                text: vuln.title.clone(),
            },
            full_description: vuln
                .description
                .as_ref()
                .map(|d| SarifMessage { text: d.clone() }),
            help_uri: vuln.reference_url.clone(),
            default_configuration: SarifRuleConfiguration {
                level: severity_to_sarif_level(vuln.severity),
            },
        };
        rules.push(rule);

        // Create a result for each vulnerability
        let sarif_result = SarifResult {
            rule_id: vuln.id.clone(),
            level: severity_to_sarif_level(vuln.severity),
            message: SarifMessage {
                text: format!(
                    "{} vulnerability in {}: {}{}",
                    vuln.severity.as_str(),
                    vuln.package_id,
                    vuln.title,
                    vuln.fixed_version
                        .as_ref()
                        .map(|v| format!(" (fixed in {})", v))
                        .unwrap_or_default()
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: location_uri,
                        uri_base_id: None,
                    },
                },
            }],
        };
        results.push(sarif_result);
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "extenscan",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/haasonsaas/extenscan",
                    rules,
                },
            },
            results,
        }],
    };

    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);

    Ok(())
}

/// Generate SARIF as a string (for file output)
pub fn generate_sarif_string(result: &ScanResult) -> Result<String> {
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for vuln in &result.vulnerabilities {
        let package = result.packages.iter().find(|p| p.id == vuln.package_id);

        let location_uri = package
            .and_then(|p| p.install_path.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| vuln.package_id.clone());

        let rule = SarifRule {
            id: vuln.id.clone(),
            name: vuln.title.clone(),
            short_description: SarifMessage {
                text: vuln.title.clone(),
            },
            full_description: vuln
                .description
                .as_ref()
                .map(|d| SarifMessage { text: d.clone() }),
            help_uri: vuln.reference_url.clone(),
            default_configuration: SarifRuleConfiguration {
                level: severity_to_sarif_level(vuln.severity),
            },
        };
        rules.push(rule);

        let sarif_result = SarifResult {
            rule_id: vuln.id.clone(),
            level: severity_to_sarif_level(vuln.severity),
            message: SarifMessage {
                text: format!(
                    "{} vulnerability in {}: {}{}",
                    vuln.severity.as_str(),
                    vuln.package_id,
                    vuln.title,
                    vuln.fixed_version
                        .as_ref()
                        .map(|v| format!(" (fixed in {})", v))
                        .unwrap_or_default()
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: location_uri,
                        uri_base_id: None,
                    },
                },
            }],
        };
        results.push(sarif_result);
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "extenscan",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/haasonsaas/extenscan",
                    rules,
                },
            },
            results,
        }],
    };

    Ok(serde_json::to_string_pretty(&report)?)
}
