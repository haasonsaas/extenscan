use crate::model::{ScanResult, Severity, Source};
use anyhow::Result;
use std::collections::HashMap;
use tabled::{settings::Style, Table, Tabled};

#[derive(Tabled)]
struct PackageRow {
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Version")]
    version: String,
    #[tabled(rename = "ID")]
    id: String,
}

#[derive(Tabled)]
struct VulnRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Package")]
    package: String,
    #[tabled(rename = "CVE")]
    cve: String,
    #[tabled(rename = "Title")]
    title: String,
    #[tabled(rename = "Fixed In")]
    fixed_in: String,
}

#[derive(Tabled)]
struct OutdatedRow {
    #[tabled(rename = "Package")]
    package: String,
    #[tabled(rename = "Current")]
    current: String,
    #[tabled(rename = "Latest")]
    latest: String,
    #[tabled(rename = "Type")]
    update_type: String,
}

#[derive(Tabled)]
struct ExtensionRiskRow {
    #[tabled(rename = "Extension")]
    name: String,
    #[tabled(rename = "Risk")]
    risk_level: String,
    #[tabled(rename = "Score")]
    score: String,
    #[tabled(rename = "Permissions")]
    permissions: String,
    #[tabled(rename = "Issues")]
    issues: String,
}

pub fn print_cli_table(result: &ScanResult) -> Result<()> {
    println!();
    println!(
        "Scan completed at: {}",
        result.scan_time.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();

    // Packages table
    if result.packages.is_empty() {
        println!("No packages found.");
    } else {
        println!("Found {} packages:", result.packages.len());
        println!();

        let rows: Vec<PackageRow> = result
            .packages
            .iter()
            .map(|p| PackageRow {
                source: p.source.display_name().to_string(),
                name: truncate(&p.name, 40),
                version: format_version(&p.version),
                id: truncate(&p.id, 50),
            })
            .collect();

        let table = Table::new(rows).with(Style::rounded()).to_string();
        println!("{}", table);
    }

    // Vulnerabilities
    if !result.vulnerabilities.is_empty() {
        println!();
        println!("Found {} vulnerabilities:", result.vulnerabilities.len());
        println!();

        let mut vulns = result.vulnerabilities.clone();
        vulns.sort_by_key(|v| match v.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Unknown => 4,
        });

        let rows: Vec<VulnRow> = vulns
            .iter()
            .map(|v| VulnRow {
                severity: format_severity(&v.severity),
                package: v.package_id.clone(),
                cve: v.id.clone(),
                title: truncate(&v.title, 50),
                fixed_in: v.fixed_version.clone().unwrap_or_else(|| "-".to_string()),
            })
            .collect();

        let table = Table::new(rows).with(Style::rounded()).to_string();
        println!("{}", table);
    }

    // Outdated packages
    if !result.outdated.is_empty() {
        println!();
        println!("Found {} outdated packages:", result.outdated.len());
        println!();

        let rows: Vec<OutdatedRow> = result
            .outdated
            .iter()
            .map(|o| {
                let update_type = classify_update(&o.current_version, &o.latest_version);
                OutdatedRow {
                    package: o.package_id.clone(),
                    current: o.current_version.clone(),
                    latest: o.latest_version.clone(),
                    update_type,
                }
            })
            .collect();

        let table = Table::new(rows).with(Style::rounded()).to_string();
        println!("{}", table);

        // Show upgrade commands
        print_upgrade_commands(result);
    }

    // Extension Risk Analysis (for browser extensions)
    print_extension_risks(result);

    // Summary
    println!();
    print_summary(result);

    Ok(())
}

fn print_extension_risks(result: &ScanResult) {
    use crate::model::Source;

    // Filter to browser extensions with risk data
    let extensions_with_risk: Vec<_> = result
        .packages
        .iter()
        .filter(|p| {
            matches!(p.source, Source::Chrome | Source::Edge | Source::Firefox | Source::Vscode)
                && p.extension_risk.is_some()
        })
        .collect();

    if extensions_with_risk.is_empty() {
        return;
    }

    // Only show if there are risky extensions (medium or higher)
    let risky_extensions: Vec<_> = extensions_with_risk
        .iter()
        .filter(|p| {
            p.extension_risk
                .as_ref()
                .map(|r| r.total_score > 20)
                .unwrap_or(false)
        })
        .collect();

    if risky_extensions.is_empty() {
        return;
    }

    println!();
    println!(
        "Extension Risk Analysis ({} with elevated risk):",
        risky_extensions.len()
    );
    println!();

    let mut rows: Vec<ExtensionRiskRow> = risky_extensions
        .iter()
        .filter_map(|p| {
            let risk = p.extension_risk.as_ref()?;
            let high_risk_perms: Vec<_> = risk
                .permissions
                .iter()
                .filter(|perm| {
                    matches!(
                        perm.level,
                        crate::checker::extension_risk::RiskLevel::Critical
                            | crate::checker::extension_risk::RiskLevel::High
                    )
                })
                .map(|p| p.name.clone())
                .collect();

            Some(ExtensionRiskRow {
                name: truncate(&p.name, 30),
                risk_level: format_risk_level(&risk.risk_level),
                score: risk.total_score.to_string(),
                permissions: if high_risk_perms.is_empty() {
                    "-".to_string()
                } else {
                    truncate(&high_risk_perms.join(", "), 35)
                },
                issues: risk.issues.len().to_string(),
            })
        })
        .collect();

    // Sort by score descending
    rows.sort_by(|a, b| {
        b.score
            .parse::<u32>()
            .unwrap_or(0)
            .cmp(&a.score.parse::<u32>().unwrap_or(0))
    });

    let table = Table::new(rows).with(Style::rounded()).to_string();
    println!("{}", table);
}

fn format_risk_level(level: &str) -> String {
    match level {
        "critical" => "\x1b[31mCRITICAL\x1b[0m".to_string(),
        "high" => "\x1b[91mHIGH\x1b[0m".to_string(),
        "medium" => "\x1b[33mMEDIUM\x1b[0m".to_string(),
        _ => "LOW".to_string(),
    }
}

fn format_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "\x1b[31mCRITICAL\x1b[0m".to_string(),
        Severity::High => "\x1b[91mHIGH\x1b[0m".to_string(),
        Severity::Medium => "\x1b[33mMEDIUM\x1b[0m".to_string(),
        Severity::Low => "\x1b[32mLOW\x1b[0m".to_string(),
        Severity::Unknown => "UNKNOWN".to_string(),
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn format_version(version: &str) -> String {
    if version == "unknown" {
        "-".to_string()
    } else {
        version.to_string()
    }
}

/// Classify version update as major, minor, or patch
fn classify_update(current: &str, latest: &str) -> String {
    let current_clean = current.trim_start_matches('v');
    let latest_clean = latest.trim_start_matches('v');

    // Try to parse as semver
    let current_parts: Vec<&str> = current_clean.split('.').collect();
    let latest_parts: Vec<&str> = latest_clean.split('.').collect();

    if !current_parts.is_empty() && !latest_parts.is_empty() {
        let current_major = current_parts[0].parse::<u32>().ok();
        let latest_major = latest_parts[0].parse::<u32>().ok();

        if let (Some(cm), Some(lm)) = (current_major, latest_major) {
            if lm > cm {
                return "MAJOR".to_string();
            }
        }

        if current_parts.len() >= 2 && latest_parts.len() >= 2 {
            let current_minor = current_parts[1].parse::<u32>().ok();
            let latest_minor = latest_parts[1].parse::<u32>().ok();

            if let (Some(cmi), Some(lmi)) = (current_minor, latest_minor) {
                if current_major == latest_major && lmi > cmi {
                    return "minor".to_string();
                }
            }
        }
    }

    "patch".to_string()
}

/// Print upgrade commands for outdated packages
fn print_upgrade_commands(result: &ScanResult) {
    // Group outdated packages by source
    let mut by_source: HashMap<Source, Vec<&str>> = HashMap::new();

    for outdated in &result.outdated {
        // Find the package to get its source
        if let Some(pkg) = result.packages.iter().find(|p| p.id == outdated.package_id) {
            by_source
                .entry(pkg.source)
                .or_default()
                .push(&outdated.package_id);
        }
    }

    if by_source.is_empty() {
        return;
    }

    println!();
    println!("Upgrade commands:");

    for (source, packages) in &by_source {
        match source {
            Source::Npm => {
                if packages.len() <= 5 {
                    println!("  npm update -g {}", packages.to_vec().join(" "));
                } else {
                    println!("  npm update -g  # {} packages", packages.len());
                }
            }
            Source::Homebrew => {
                if packages.len() <= 5 {
                    println!("  brew upgrade {}", packages.to_vec().join(" "));
                } else {
                    println!("  brew upgrade  # {} packages", packages.len());
                }
            }
            _ => {}
        }
    }
}

/// Calculate a health score (0-100) based on vulnerabilities and outdated packages
fn calculate_health_score(result: &ScanResult) -> u8 {
    if result.packages.is_empty() {
        return 100;
    }

    let mut score: i32 = 100;

    // Deduct for vulnerabilities
    for vuln in &result.vulnerabilities {
        match vuln.severity {
            Severity::Critical => score -= 25,
            Severity::High => score -= 15,
            Severity::Medium => score -= 8,
            Severity::Low => score -= 3,
            Severity::Unknown => score -= 5,
        }
    }

    // Deduct for outdated packages
    for outdated in &result.outdated {
        let is_major = {
            let c = outdated.current_version.trim_start_matches('v');
            let l = outdated.latest_version.trim_start_matches('v');
            let cp: Vec<&str> = c.split('.').collect();
            let lp: Vec<&str> = l.split('.').collect();
            if let (Some(cm), Some(lm)) = (
                cp.first().and_then(|s| s.parse::<u32>().ok()),
                lp.first().and_then(|s| s.parse::<u32>().ok()),
            ) {
                lm > cm
            } else {
                false
            }
        };

        if is_major {
            score -= 5; // Major updates are more important
        } else {
            score -= 2; // Minor/patch updates
        }
    }

    score.clamp(0, 100) as u8
}

fn health_score_indicator(score: u8) -> &'static str {
    match score {
        90..=100 => "[Excellent]",
        70..=89 => "[Good]",
        50..=69 => "[Fair]",
        25..=49 => "[Poor]",
        _ => "[Critical]",
    }
}

fn print_summary(result: &ScanResult) {
    let critical = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    let high = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count();
    let medium = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Medium)
        .count();
    let low = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Low)
        .count();

    // Count packages by source and unknown versions
    let mut by_source: HashMap<Source, usize> = HashMap::new();
    let mut unknown_count = 0;
    for pkg in &result.packages {
        *by_source.entry(pkg.source).or_default() += 1;
        if pkg.version == "unknown" {
            unknown_count += 1;
        }
    }

    println!("Summary:");
    if unknown_count > 0 {
        println!(
            "  Total packages: {} ({} with unknown version)",
            result.packages.len(),
            unknown_count
        );
    } else {
        println!("  Total packages: {}", result.packages.len());
    }

    // Show breakdown by source if multiple sources
    if by_source.len() > 1 {
        let source_summary: Vec<String> = by_source
            .iter()
            .map(|(s, c)| format!("{} {}", c, s.display_name()))
            .collect();
        println!("  By source: {}", source_summary.join(", "));
    }

    if !result.vulnerabilities.is_empty() {
        println!(
            "  Vulnerabilities: {} critical, {} high, {} medium, {} low",
            critical, high, medium, low
        );
    }

    if !result.outdated.is_empty() {
        // Count major updates
        let major_count = result
            .outdated
            .iter()
            .filter(|o| {
                let c = o.current_version.trim_start_matches('v');
                let l = o.latest_version.trim_start_matches('v');
                let cp: Vec<&str> = c.split('.').collect();
                let lp: Vec<&str> = l.split('.').collect();
                if let (Some(cm), Some(lm)) = (
                    cp.first().and_then(|s| s.parse::<u32>().ok()),
                    lp.first().and_then(|s| s.parse::<u32>().ok()),
                ) {
                    lm > cm
                } else {
                    false
                }
            })
            .count();

        if major_count > 0 {
            println!(
                "  Outdated packages: {} ({} major updates)",
                result.outdated.len(),
                major_count
            );
        } else {
            println!("  Outdated packages: {}", result.outdated.len());
        }
    }

    // Health score
    let score = calculate_health_score(result);
    println!();
    println!("Health Score: {}/100 {}", score, health_score_indicator(score));
}
