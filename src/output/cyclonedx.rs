//! CycloneDX SBOM (Software Bill of Materials) output format.
//!
//! Generates a CycloneDX 1.5 compliant SBOM for compliance and supply chain security.
//! See: https://cyclonedx.org/

use crate::model::{ScanResult, Severity, Source};
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

/// CycloneDX SBOM root document
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u32,
    serial_number: String,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<CycloneDxVulnerability>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxMetadata {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
}

#[derive(Serialize)]
struct CycloneDxTool {
    vendor: &'static str,
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publisher: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<CycloneDxLicense>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_references: Vec<CycloneDxExternalRef>,
}

#[derive(Serialize)]
struct CycloneDxLicense {
    license: CycloneDxLicenseId,
}

#[derive(Serialize)]
struct CycloneDxLicenseId {
    id: String,
}

#[derive(Serialize)]
struct CycloneDxExternalRef {
    #[serde(rename = "type")]
    ref_type: &'static str,
    url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxVulnerability {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recommendation: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ratings: Vec<CycloneDxRating>,
    affects: Vec<CycloneDxAffects>,
}

#[derive(Serialize)]
struct CycloneDxRating {
    severity: String,
    method: &'static str,
}

#[derive(Serialize)]
struct CycloneDxAffects {
    #[serde(rename = "ref")]
    component_ref: String,
}

fn source_to_purl_type(source: &Source) -> &'static str {
    match source {
        Source::Npm => "npm",
        Source::Homebrew => "brew",
        Source::Vscode => "vscode",
        Source::Chrome => "chrome",
        Source::Edge => "edge",
        Source::Firefox => "firefox",
        Source::Brave => "brave",
        Source::Arc => "arc",
        Source::Opera => "opera",
        Source::Vivaldi => "vivaldi",
        Source::Chromium => "chromium",
    }
}

fn severity_to_cyclonedx(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

/// Generate and print CycloneDX SBOM output
pub fn print_cyclonedx(result: &ScanResult) -> Result<()> {
    let mut components = Vec::new();

    for package in &result.packages {
        let purl = format!(
            "pkg:{}/{}@{}",
            source_to_purl_type(&package.source),
            package.id,
            package.version
        );

        let mut external_refs = Vec::new();
        if let Some(ref homepage) = package.metadata.homepage {
            external_refs.push(CycloneDxExternalRef {
                ref_type: "website",
                url: homepage.clone(),
            });
        }
        if let Some(ref repo) = package.metadata.repository {
            external_refs.push(CycloneDxExternalRef {
                ref_type: "vcs",
                url: repo.clone(),
            });
        }

        let licenses = package
            .metadata
            .license
            .as_ref()
            .map(|l| {
                vec![CycloneDxLicense {
                    license: CycloneDxLicenseId { id: l.clone() },
                }]
            })
            .unwrap_or_default();

        let component = CycloneDxComponent {
            component_type: "library",
            bom_ref: package.id.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            purl: Some(purl),
            description: package.metadata.description.clone(),
            publisher: package.metadata.publisher.clone(),
            licenses,
            external_references: external_refs,
        };

        components.push(component);
    }

    let vulnerabilities: Vec<CycloneDxVulnerability> = result
        .vulnerabilities
        .iter()
        .map(|vuln| {
            let recommendation = vuln
                .fixed_version
                .as_ref()
                .map(|v| format!("Upgrade to version {}", v));

            CycloneDxVulnerability {
                bom_ref: format!("vuln-{}", vuln.id),
                id: vuln.id.clone(),
                description: vuln.description.clone().or(Some(vuln.title.clone())),
                recommendation,
                ratings: vec![CycloneDxRating {
                    severity: severity_to_cyclonedx(vuln.severity).to_string(),
                    method: "other",
                }],
                affects: vec![CycloneDxAffects {
                    component_ref: vuln.package_id.clone(),
                }],
            }
        })
        .collect();

    let bom = CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        serial_number: format!("urn:uuid:{}", uuid_v4()),
        metadata: CycloneDxMetadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![CycloneDxTool {
                vendor: "extenscan",
                name: "extenscan",
                version: env!("CARGO_PKG_VERSION"),
            }],
        },
        components,
        vulnerabilities,
    };

    let json = serde_json::to_string_pretty(&bom)?;
    println!("{}", json);

    Ok(())
}

/// Generate CycloneDX as a string (for file output)
pub fn generate_cyclonedx_string(result: &ScanResult) -> Result<String> {
    let mut components = Vec::new();

    for package in &result.packages {
        let purl = format!(
            "pkg:{}/{}@{}",
            source_to_purl_type(&package.source),
            package.id,
            package.version
        );

        let mut external_refs = Vec::new();
        if let Some(ref homepage) = package.metadata.homepage {
            external_refs.push(CycloneDxExternalRef {
                ref_type: "website",
                url: homepage.clone(),
            });
        }
        if let Some(ref repo) = package.metadata.repository {
            external_refs.push(CycloneDxExternalRef {
                ref_type: "vcs",
                url: repo.clone(),
            });
        }

        let licenses = package
            .metadata
            .license
            .as_ref()
            .map(|l| {
                vec![CycloneDxLicense {
                    license: CycloneDxLicenseId { id: l.clone() },
                }]
            })
            .unwrap_or_default();

        let component = CycloneDxComponent {
            component_type: "library",
            bom_ref: package.id.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
            purl: Some(purl),
            description: package.metadata.description.clone(),
            publisher: package.metadata.publisher.clone(),
            licenses,
            external_references: external_refs,
        };

        components.push(component);
    }

    let vulnerabilities: Vec<CycloneDxVulnerability> = result
        .vulnerabilities
        .iter()
        .map(|vuln| {
            let recommendation = vuln
                .fixed_version
                .as_ref()
                .map(|v| format!("Upgrade to version {}", v));

            CycloneDxVulnerability {
                bom_ref: format!("vuln-{}", vuln.id),
                id: vuln.id.clone(),
                description: vuln.description.clone().or(Some(vuln.title.clone())),
                recommendation,
                ratings: vec![CycloneDxRating {
                    severity: severity_to_cyclonedx(vuln.severity).to_string(),
                    method: "other",
                }],
                affects: vec![CycloneDxAffects {
                    component_ref: vuln.package_id.clone(),
                }],
            }
        })
        .collect();

    let bom = CycloneDxBom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        version: 1,
        serial_number: format!("urn:uuid:{}", uuid_v4()),
        metadata: CycloneDxMetadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![CycloneDxTool {
                vendor: "extenscan",
                name: "extenscan",
                version: env!("CARGO_PKG_VERSION"),
            }],
        },
        components,
        vulnerabilities,
    };

    Ok(serde_json::to_string_pretty(&bom)?)
}

/// Generate a simple UUID v4 (random)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // Simple pseudo-random UUID based on timestamp
    // In production, use uuid crate for proper random UUIDs
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (now >> 96) as u32,
        (now >> 80) as u16,
        (now >> 68) as u16 & 0x0fff,
        ((now >> 52) as u16 & 0x3fff) | 0x8000,
        now as u64 & 0xffffffffffff,
    )
}
