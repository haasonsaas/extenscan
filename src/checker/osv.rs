use crate::model::{Package, Severity, Source, Vulnerability};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub struct OsvChecker {
    client: reqwest::Client,
}

impl OsvChecker {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    fn get_ecosystem(source: &Source) -> Option<&'static str> {
        match source {
            Source::Npm => Some("npm"),
            Source::Homebrew => Some("Homebrew"),
            // Browser extensions and VSCode don't have direct OSV ecosystems
            _ => None,
        }
    }
}

impl Default for OsvChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<Vec<OsvSeverity>>,
    affected: Option<Vec<OsvAffected>>,
    references: Option<Vec<OsvReference>>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    severity_type: Option<String>,
    score: Option<String>,
}

#[derive(Deserialize)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize)]
struct OsvRange {
    events: Option<Vec<OsvEvent>>,
}

#[derive(Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct OsvReference {
    url: Option<String>,
}

#[async_trait]
impl super::VulnerabilityChecker for OsvChecker {
    fn name(&self) -> &'static str {
        "OSV.dev"
    }

    async fn check(&self, packages: &[Package]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        for package in packages {
            let ecosystem = match Self::get_ecosystem(&package.source) {
                Some(e) => e,
                None => continue, // Skip packages without OSV ecosystem support
            };

            let query = OsvQuery {
                package: OsvPackage {
                    name: package.name.clone(),
                    ecosystem: ecosystem.to_string(),
                },
                version: package.version.clone(),
            };

            let response = self
                .client
                .post("https://api.osv.dev/v1/query")
                .json(&query)
                .send()
                .await;

            let response = match response {
                Ok(r) => r,
                Err(_) => continue, // Skip on network errors
            };

            let osv_response: OsvResponse = match response.json().await {
                Ok(r) => r,
                Err(_) => continue,
            };

            if let Some(vulns) = osv_response.vulns {
                for vuln in vulns {
                    let severity = parse_severity(&vuln);
                    let fixed_version = extract_fixed_version(&vuln);
                    let reference_url = vuln
                        .references
                        .and_then(|refs| refs.into_iter().find_map(|r| r.url));

                    let vulnerability = Vulnerability {
                        id: vuln.id,
                        package_id: package.id.clone(),
                        severity,
                        title: vuln.summary.unwrap_or_else(|| "Unknown vulnerability".to_string()),
                        description: vuln.details,
                        fixed_version,
                        reference_url,
                    };

                    vulnerabilities.push(vulnerability);
                }
            }
        }

        Ok(vulnerabilities)
    }
}

fn parse_severity(vuln: &OsvVuln) -> Severity {
    if let Some(severities) = &vuln.severity {
        for sev in severities {
            if let Some(score) = &sev.score {
                // CVSS score parsing
                if let Ok(cvss) = score.parse::<f32>() {
                    return match cvss {
                        s if s >= 9.0 => Severity::Critical,
                        s if s >= 7.0 => Severity::High,
                        s if s >= 4.0 => Severity::Medium,
                        s if s > 0.0 => Severity::Low,
                        _ => Severity::Unknown,
                    };
                }

                // Try to extract from CVSS vector string
                if score.contains("CVSS:") {
                    // Extract base score from vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    // This is a simplified check
                    if score.contains("/C:H") || score.contains("/I:H") || score.contains("/A:H") {
                        return Severity::High;
                    }
                }
            }
        }
    }

    Severity::Unknown
}

fn extract_fixed_version(vuln: &OsvVuln) -> Option<String> {
    vuln.affected.as_ref()?.iter().find_map(|affected| {
        affected.ranges.as_ref()?.iter().find_map(|range| {
            range.events.as_ref()?.iter().find_map(|event| event.fixed.clone())
        })
    })
}
