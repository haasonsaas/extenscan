use crate::model::{ScanResult, Severity};
use anyhow::Result;
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
            .map(|o| OutdatedRow {
                package: o.package_id.clone(),
                current: o.current_version.clone(),
                latest: o.latest_version.clone(),
            })
            .collect();

        let table = Table::new(rows).with(Style::rounded()).to_string();
        println!("{}", table);
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

    println!("Summary:");
    println!("  Total packages: {}", result.packages.len());

    if !result.vulnerabilities.is_empty() {
        println!(
            "  Vulnerabilities: {} critical, {} high, {} medium, {} low",
            critical, high, medium, low
        );
    }

    if !result.outdated.is_empty() {
        println!("  Outdated packages: {}", result.outdated.len());
    }
}
