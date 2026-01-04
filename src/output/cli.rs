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
                version: p.version.clone(),
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

    // Summary
    println!();
    print_summary(result);

    Ok(())
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
                return "MAJOR ⚠".to_string();
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

    // Count packages by source
    let mut by_source: HashMap<Source, usize> = HashMap::new();
    for pkg in &result.packages {
        *by_source.entry(pkg.source).or_default() += 1;
    }

    println!("Summary:");
    println!("  Total packages: {}", result.packages.len());

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
}
