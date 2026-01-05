//! HTML report output format.
//!
//! Generates a self-contained HTML report with styling for easy viewing and sharing.

use crate::model::{ScanResult, Severity};
use anyhow::Result;

/// Generate and print HTML report output
pub fn print_html(result: &ScanResult) -> Result<()> {
    let html = generate_html_string(result);
    println!("{}", html);
    Ok(())
}

/// Generate HTML as a string (for file output)
pub fn generate_html_string(result: &ScanResult) -> String {
    let critical_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    let high_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::High)
        .count();
    let medium_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Medium)
        .count();
    let low_count = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Low)
        .count();

    let health_score = calculate_health_score(result);

    let mut html = String::new();

    html.push_str(&format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>extenscan Report - {}</title>
    <style>
        :root {{
            --bg-color: #1a1a2e;
            --card-bg: #16213e;
            --text-color: #eee;
            --text-muted: #888;
            --border-color: #0f3460;
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --accent: #0f3460;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        h1 {{ font-size: 1.75rem; font-weight: 600; }}
        .timestamp {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 1.25rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .stat-value {{ font-size: 2rem; font-weight: 700; }}
        .stat-label {{ color: var(--text-muted); font-size: 0.85rem; }}
        .health-excellent {{ color: #28a745; }}
        .health-good {{ color: #5cb85c; }}
        .health-fair {{ color: #ffc107; }}
        .health-poor {{ color: #fd7e14; }}
        .health-critical {{ color: #dc3545; }}
        section {{ margin-bottom: 2rem; }}
        h2 {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background: var(--accent); font-weight: 600; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        .severity {{ padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
        .severity-critical {{ background: var(--critical); color: white; }}
        .severity-high {{ background: var(--high); color: white; }}
        .severity-medium {{ background: var(--medium); color: black; }}
        .severity-low {{ background: var(--low); color: white; }}
        .update-major {{ color: var(--critical); font-weight: 600; }}
        .update-minor {{ color: var(--medium); }}
        .update-patch {{ color: var(--text-muted); }}
        .empty {{ text-align: center; padding: 2rem; color: var(--text-muted); }}
        footer {{ text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border-color); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>extenscan Report</h1>
            <span class="timestamp">{}</span>
        </header>
"#,
        result.scan_time.format("%Y-%m-%d"),
        result.scan_time.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Stats cards
    let health_class = match health_score {
        90..=100 => "health-excellent",
        70..=89 => "health-good",
        50..=69 => "health-fair",
        25..=49 => "health-poor",
        _ => "health-critical",
    };

    html.push_str(&format!(
        r#"        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Packages</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Outdated</div>
            </div>
            <div class="stat-card">
                <div class="stat-value {}">{}%</div>
                <div class="stat-label">Health Score</div>
            </div>
        </div>
"#,
        result.packages.len(),
        result.vulnerabilities.len(),
        result.outdated.len(),
        health_class,
        health_score
    ));

    // Vulnerabilities section
    html.push_str(r#"        <section>
            <h2>Vulnerabilities</h2>
"#);

    if result.vulnerabilities.is_empty() {
        html.push_str(r#"            <div class="empty">No vulnerabilities found</div>
"#);
    } else {
        html.push_str(r#"            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Package</th>
                        <th>CVE</th>
                        <th>Title</th>
                        <th>Fixed In</th>
                    </tr>
                </thead>
                <tbody>
"#);

        let mut vulns = result.vulnerabilities.clone();
        vulns.sort_by_key(|v| match v.severity {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Medium => 2,
            Severity::Low => 3,
            Severity::Unknown => 4,
        });

        for vuln in &vulns {
            let severity_class = match vuln.severity {
                Severity::Critical => "severity-critical",
                Severity::High => "severity-high",
                Severity::Medium => "severity-medium",
                Severity::Low => "severity-low",
                Severity::Unknown => "",
            };

            html.push_str(&format!(
                r#"                    <tr>
                        <td><span class="severity {}">{}</span></td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>
"#,
                severity_class,
                vuln.severity.as_str().to_uppercase(),
                html_escape(&vuln.package_id),
                html_escape(&vuln.id),
                html_escape(&vuln.title),
                vuln.fixed_version
                    .as_ref()
                    .map(|s| html_escape(s))
                    .unwrap_or_else(|| "-".to_string())
            ));
        }

        html.push_str(r#"                </tbody>
            </table>
"#);
    }

    html.push_str("        </section>\n");

    // Outdated packages section
    html.push_str(r#"        <section>
            <h2>Outdated Packages</h2>
"#);

    if result.outdated.is_empty() {
        html.push_str(r#"            <div class="empty">All packages are up to date</div>
"#);
    } else {
        html.push_str(r#"            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Current</th>
                        <th>Latest</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
"#);

        for outdated in &result.outdated {
            let update_type = classify_update(&outdated.current_version, &outdated.latest_version);
            let type_class = match update_type.as_str() {
                "MAJOR" => "update-major",
                "minor" => "update-minor",
                _ => "update-patch",
            };

            html.push_str(&format!(
                r#"                    <tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td class="{}">{}</td>
                    </tr>
"#,
                html_escape(&outdated.package_id),
                html_escape(&outdated.current_version),
                html_escape(&outdated.latest_version),
                type_class,
                update_type
            ));
        }

        html.push_str(r#"                </tbody>
            </table>
"#);
    }

    html.push_str("        </section>\n");

    // Packages section
    html.push_str(r#"        <section>
            <h2>All Packages</h2>
"#);

    if result.packages.is_empty() {
        html.push_str(r#"            <div class="empty">No packages found</div>
"#);
    } else {
        html.push_str(r#"            <table>
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Name</th>
                        <th>Version</th>
                        <th>ID</th>
                    </tr>
                </thead>
                <tbody>
"#);

        for pkg in &result.packages {
            html.push_str(&format!(
                r#"                    <tr>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>
"#,
                pkg.source.display_name(),
                html_escape(&pkg.name),
                if pkg.version == "unknown" {
                    "-".to_string()
                } else {
                    html_escape(&pkg.version)
                },
                html_escape(&pkg.id)
            ));
        }

        html.push_str(r#"                </tbody>
            </table>
"#);
    }

    html.push_str("        </section>\n");

    // Summary
    html.push_str(&format!(
        r#"        <section>
            <h2>Summary</h2>
            <div class="stat-card">
                <p>Scanned {} packages across {} sources.</p>
                <p>Found {} vulnerabilities ({} critical, {} high, {} medium, {} low).</p>
                <p>Found {} outdated packages.</p>
            </div>
        </section>
"#,
        result.packages.len(),
        count_sources(result),
        result.vulnerabilities.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        result.outdated.len()
    ));

    // Footer
    html.push_str(r#"        <footer>
            Generated by extenscan
        </footer>
    </div>
</body>
</html>
"#);

    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn calculate_health_score(result: &ScanResult) -> u8 {
    if result.packages.is_empty() {
        return 100;
    }

    let mut score: i32 = 100;

    for vuln in &result.vulnerabilities {
        match vuln.severity {
            Severity::Critical => score -= 25,
            Severity::High => score -= 15,
            Severity::Medium => score -= 8,
            Severity::Low => score -= 3,
            Severity::Unknown => score -= 5,
        }
    }

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
            score -= 5;
        } else {
            score -= 2;
        }
    }

    score.clamp(0, 100) as u8
}

fn classify_update(current: &str, latest: &str) -> String {
    let current_clean = current.trim_start_matches('v');
    let latest_clean = latest.trim_start_matches('v');

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

fn count_sources(result: &ScanResult) -> usize {
    use std::collections::HashSet;
    result
        .packages
        .iter()
        .map(|p| p.source)
        .collect::<HashSet<_>>()
        .len()
}
