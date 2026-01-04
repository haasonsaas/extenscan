use crate::model::{Package, Severity, Source, Vulnerability};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Maximum number of packages to query in a single batch request.
const BATCH_SIZE: usize = 100;

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

    /// Performs a batch query to OSV.dev for multiple packages at once.
    /// Returns vulnerabilities mapped to their original package indices.
    async fn batch_query(
        &self,
        packages: &[(usize, &Package)],
    ) -> Result<Vec<(usize, Vec<OsvVuln>)>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        let queries: Vec<OsvBatchQueryItem> = packages
            .iter()
            .filter_map(|(_, pkg)| {
                let ecosystem = Self::get_ecosystem(&pkg.source)?;
                Some(OsvBatchQueryItem {
                    package: OsvPackage {
                        name: pkg.id.clone(),
                        ecosystem: ecosystem.to_string(),
                    },
                    version: pkg.version.clone(),
                })
            })
            .collect();

        if queries.is_empty() {
            return Ok(Vec::new());
        }

        let batch_query = OsvBatchQuery { queries };

        let response = self
            .client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&batch_query)
            .send()
            .await?;

        let batch_response: OsvBatchResponse = response.json().await?;

        // Map responses back to package indices
        let mut results = Vec::new();
        for (i, result) in batch_response.results.into_iter().enumerate() {
            if let Some((pkg_idx, _)) = packages.get(i) {
                if let Some(vulns) = result.vulns {
                    if !vulns.is_empty() {
                        results.push((*pkg_idx, vulns));
                    }
                }
            }
        }

        Ok(results)
    }
}

impl Default for OsvChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Clone)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

// Batch query types for efficient bulk lookups
#[derive(Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvBatchQueryItem>,
}

#[derive(Serialize)]
struct OsvBatchQueryItem {
    package: OsvPackage,
    version: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvBatchResult>,
}

#[derive(Deserialize)]
struct OsvBatchResult {
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

        // Filter to only packages with OSV ecosystem support and track indices
        let checkable_packages: Vec<(usize, &Package)> = packages
            .iter()
            .enumerate()
            .filter(|(_, pkg)| Self::get_ecosystem(&pkg.source).is_some())
            .collect();

        // Process in batches for efficiency
        for chunk in checkable_packages.chunks(BATCH_SIZE) {
            let batch_results = match self.batch_query(chunk).await {
                Ok(results) => results,
                Err(_) => continue, // Skip batch on network errors
            };

            for (pkg_idx, vulns) in batch_results {
                let package = &packages[pkg_idx];
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
                        title: vuln
                            .summary
                            .unwrap_or_else(|| "Unknown vulnerability".to_string()),
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

/// Parses CVSS score into a severity level.
///
/// Supports both numeric scores and CVSS vector strings.
pub fn parse_cvss_score(score: &str) -> Severity {
    // Try parsing as numeric CVSS score
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
        // This is a simplified check based on impact metrics
        if score.contains("/C:H") || score.contains("/I:H") || score.contains("/A:H") {
            return Severity::High;
        }
        if score.contains("/C:L") || score.contains("/I:L") || score.contains("/A:L") {
            return Severity::Medium;
        }
        return Severity::Low;
    }

    Severity::Unknown
}

fn parse_severity(vuln: &OsvVuln) -> Severity {
    if let Some(severities) = &vuln.severity {
        for sev in severities {
            if let Some(score) = &sev.score {
                let severity = parse_cvss_score(score);
                if severity != Severity::Unknown {
                    return severity;
                }
            }
        }
    }

    Severity::Unknown
}

fn extract_fixed_version(vuln: &OsvVuln) -> Option<String> {
    vuln.affected.as_ref()?.iter().find_map(|affected| {
        affected.ranges.as_ref()?.iter().find_map(|range| {
            range
                .events
                .as_ref()?
                .iter()
                .find_map(|event| event.fixed.clone())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checker::VulnerabilityChecker;

    #[test]
    fn test_parse_cvss_score_critical() {
        assert_eq!(parse_cvss_score("9.0"), Severity::Critical);
        assert_eq!(parse_cvss_score("9.8"), Severity::Critical);
        assert_eq!(parse_cvss_score("10.0"), Severity::Critical);
    }

    #[test]
    fn test_parse_cvss_score_high() {
        assert_eq!(parse_cvss_score("7.0"), Severity::High);
        assert_eq!(parse_cvss_score("8.5"), Severity::High);
        assert_eq!(parse_cvss_score("7.9"), Severity::High);
    }

    #[test]
    fn test_parse_cvss_score_medium() {
        assert_eq!(parse_cvss_score("4.0"), Severity::Medium);
        assert_eq!(parse_cvss_score("5.5"), Severity::Medium);
        assert_eq!(parse_cvss_score("6.9"), Severity::Medium);
    }

    #[test]
    fn test_parse_cvss_score_low() {
        assert_eq!(parse_cvss_score("0.1"), Severity::Low);
        assert_eq!(parse_cvss_score("1.0"), Severity::Low);
        assert_eq!(parse_cvss_score("3.9"), Severity::Low);
    }

    #[test]
    fn test_parse_cvss_score_unknown() {
        assert_eq!(parse_cvss_score("0.0"), Severity::Unknown);
        assert_eq!(parse_cvss_score("-1.0"), Severity::Unknown);
        assert_eq!(parse_cvss_score("not a number"), Severity::Unknown);
    }

    #[test]
    fn test_parse_cvss_vector_high() {
        // Vector with High impact on Confidentiality
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Severity::High
        );
        // Vector with High impact on Integrity
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
            Severity::High
        );
        // Vector with High impact on Availability
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
            Severity::High
        );
    }

    #[test]
    fn test_parse_cvss_vector_medium() {
        // Vector with Low impact metrics
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
            Severity::Medium
        );
    }

    #[test]
    fn test_parse_cvss_vector_low() {
        // Vector with None impact metrics
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
            Severity::Low
        );
    }

    #[test]
    fn test_osv_checker_get_ecosystem() {
        assert_eq!(OsvChecker::get_ecosystem(&Source::Npm), Some("npm"));
        assert_eq!(
            OsvChecker::get_ecosystem(&Source::Homebrew),
            Some("Homebrew")
        );
        assert_eq!(OsvChecker::get_ecosystem(&Source::Chrome), None);
        assert_eq!(OsvChecker::get_ecosystem(&Source::Vscode), None);
        assert_eq!(OsvChecker::get_ecosystem(&Source::Edge), None);
        assert_eq!(OsvChecker::get_ecosystem(&Source::Firefox), None);
    }

    #[test]
    fn test_osv_checker_default() {
        let checker = OsvChecker::default();
        assert_eq!(checker.name(), "OSV.dev");
    }
}
