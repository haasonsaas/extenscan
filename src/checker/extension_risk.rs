//! Browser extension risk analysis based on permissions and security policies.
//!
//! Provides CRXcavator-style risk scoring for browser extensions by analyzing:
//! - Permission declarations and their risk levels
//! - Content Security Policy (CSP) weaknesses
//! - Host permissions scope
//! - External communication patterns

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk level for a permission or security issue
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical = 4,
    High = 3,
    Medium = 2,
    Low = 1,
    None = 0,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "critical",
            RiskLevel::High => "high",
            RiskLevel::Medium => "medium",
            RiskLevel::Low => "low",
            RiskLevel::None => "none",
        }
    }

    pub fn score(&self) -> u32 {
        match self {
            RiskLevel::Critical => 100,
            RiskLevel::High => 50,
            RiskLevel::Medium => 20,
            RiskLevel::Low => 5,
            RiskLevel::None => 0,
        }
    }
}

/// Analysis result for a single permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRisk {
    pub name: String,
    pub level: RiskLevel,
    pub description: String,
    pub warning: Option<String>,
}

/// Content Security Policy analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CspAnalysis {
    pub has_csp: bool,
    pub allows_unsafe_eval: bool,
    pub allows_unsafe_inline: bool,
    pub allows_remote_scripts: bool,
    pub allowed_domains: Vec<String>,
    pub issues: Vec<String>,
    pub score: u32,
}

/// Complete extension risk analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionRiskReport {
    pub total_score: u32,
    pub risk_level: String,
    pub permissions: Vec<PermissionRisk>,
    pub host_permissions: Vec<String>,
    pub host_permission_scope: HostPermissionScope,
    pub csp: CspAnalysis,
    pub external_domains: Vec<String>,
    pub issues: Vec<RiskIssue>,
}

/// Scope of host permissions
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostPermissionScope {
    #[default]
    None,
    Specific,      // Limited to specific domains
    Broad,         // Uses wildcards like *.google.com
    AllUrls,       // <all_urls> or *://*/*
}

impl HostPermissionScope {
    pub fn score(&self) -> u32 {
        match self {
            HostPermissionScope::None => 0,
            HostPermissionScope::Specific => 5,
            HostPermissionScope::Broad => 30,
            HostPermissionScope::AllUrls => 80,
        }
    }
}

/// A specific risk issue found during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIssue {
    pub category: String,
    pub severity: RiskLevel,
    pub title: String,
    pub description: String,
}

/// Permission database with risk levels and descriptions
pub fn get_permission_risk(permission: &str) -> PermissionRisk {
    // Critical risk - can access/modify everything
    let critical_permissions: HashMap<&str, (&str, &str)> = [
        ("debugger", ("Access browser debugger", "Can read and modify all data on all websites")),
        ("proxy", ("Control browser proxy settings", "Can intercept all network traffic")),
        ("vpnProvider", ("VPN provider access", "Can route all network traffic")),
        ("webAuthenticationProxy", ("Web authentication proxy", "Can intercept authentication flows")),
    ].into_iter().collect();

    // High risk - significant access to user data
    let high_permissions: HashMap<&str, (&str, &str)> = [
        ("tabs", ("Read browser tabs", "Can see URLs and titles of all open tabs")),
        ("webNavigation", ("Monitor navigation", "Can read your browsing history")),
        ("history", ("Access browsing history", "Can read and modify browsing history")),
        ("bookmarks", ("Access bookmarks", "Can read and modify your bookmarks")),
        ("topSites", ("Access top sites", "Can see your most visited websites")),
        ("sessions", ("Access session data", "Can access recently closed tabs and windows")),
        ("cookies", ("Access cookies", "Can read and modify cookies for any website")),
        ("webRequest", ("Intercept web requests", "Can observe and analyze traffic")),
        ("webRequestBlocking", ("Block web requests", "Can block or modify network requests")),
        ("declarativeNetRequest", ("Modify network requests", "Can redirect or modify requests")),
        ("declarativeNetRequestWithHostAccess", ("Modify requests with host access", "Can modify requests to allowed hosts")),
        ("pageCapture", ("Capture pages", "Can capture full page content as MHTML")),
        ("tabCapture", ("Capture tabs", "Can capture video/audio from tabs")),
        ("desktopCapture", ("Capture screen", "Can capture your entire screen")),
        ("nativeMessaging", ("Native messaging", "Can communicate with programs on your computer")),
        ("management", ("Manage extensions", "Can manage other installed extensions")),
        ("privacy", ("Change privacy settings", "Can modify browser privacy settings")),
        ("browsingData", ("Clear browsing data", "Can delete browsing history and data")),
        ("contentSettings", ("Modify content settings", "Can change website permissions")),
        ("downloads", ("Access downloads", "Can manage downloaded files")),
        ("downloads.open", ("Open downloads", "Can open downloaded files")),
        ("clipboardRead", ("Read clipboard", "Can read data you copy")),
    ].into_iter().collect();

    // Medium risk - moderate access
    let medium_permissions: HashMap<&str, (&str, &str)> = [
        ("activeTab", ("Access active tab", "Can access current tab when you click the extension")),
        ("scripting", ("Inject scripts", "Can inject JavaScript into web pages")),
        ("geolocation", ("Access location", "Can detect your physical location")),
        ("notifications", ("Show notifications", "Can display desktop notifications")),
        ("clipboardWrite", ("Write clipboard", "Can modify your clipboard")),
        ("identity", ("Access identity", "Can access your browser identity")),
        ("identity.email", ("Access email", "Can see your email address")),
        ("tts", ("Text to speech", "Can use text-to-speech")),
        ("ttsEngine", ("TTS engine", "Can provide text-to-speech engine")),
        ("webRequestAuthProvider", ("Auth provider", "Can provide authentication")),
        ("userScripts", ("User scripts", "Can execute user scripts")),
        ("offscreen", ("Offscreen documents", "Can create offscreen documents")),
    ].into_iter().collect();

    // Low risk - limited functionality
    let low_permissions: HashMap<&str, (&str, &str)> = [
        ("storage", ("Store data", "Can store extension data locally")),
        ("unlimitedStorage", ("Unlimited storage", "Can store large amounts of data")),
        ("alarms", ("Set alarms", "Can schedule periodic tasks")),
        ("contextMenus", ("Context menus", "Can add items to right-click menu")),
        ("idle", ("Detect idle", "Can detect when you're idle")),
        ("power", ("Power management", "Can affect power saving")),
        ("system.cpu", ("CPU info", "Can read CPU information")),
        ("system.memory", ("Memory info", "Can read memory usage")),
        ("system.display", ("Display info", "Can read display information")),
        ("system.storage", ("Storage info", "Can read storage information")),
        ("fontSettings", ("Font settings", "Can modify font settings")),
        ("runtime", ("Runtime API", "Basic extension runtime access")),
        ("gcm", ("Cloud messaging", "Can receive push messages")),
        ("sidePanel", ("Side panel", "Can show side panel")),
        ("favicon", ("Favicon access", "Can access website favicons")),
        ("readingList", ("Reading list", "Can access reading list")),
        ("tabGroups", ("Tab groups", "Can organize tabs into groups")),
    ].into_iter().collect();

    if let Some((desc, warning)) = critical_permissions.get(permission) {
        return PermissionRisk {
            name: permission.to_string(),
            level: RiskLevel::Critical,
            description: desc.to_string(),
            warning: Some(warning.to_string()),
        };
    }

    if let Some((desc, warning)) = high_permissions.get(permission) {
        return PermissionRisk {
            name: permission.to_string(),
            level: RiskLevel::High,
            description: desc.to_string(),
            warning: Some(warning.to_string()),
        };
    }

    if let Some((desc, warning)) = medium_permissions.get(permission) {
        return PermissionRisk {
            name: permission.to_string(),
            level: RiskLevel::Medium,
            description: desc.to_string(),
            warning: Some(warning.to_string()),
        };
    }

    if let Some((desc, warning)) = low_permissions.get(permission) {
        return PermissionRisk {
            name: permission.to_string(),
            level: RiskLevel::Low,
            description: desc.to_string(),
            warning: Some(warning.to_string()),
        };
    }

    // Unknown permission - treat as low risk
    PermissionRisk {
        name: permission.to_string(),
        level: RiskLevel::Low,
        description: format!("Unknown permission: {}", permission),
        warning: None,
    }
}

/// Analyze host permissions for scope
pub fn analyze_host_permissions(hosts: &[String]) -> (HostPermissionScope, Vec<String>) {
    if hosts.is_empty() {
        return (HostPermissionScope::None, Vec::new());
    }

    let mut scope = HostPermissionScope::Specific;
    let mut domains = Vec::new();

    for host in hosts {
        let host = host.trim();

        // Check for all_urls or broad wildcards
        if host == "<all_urls>" || host == "*://*/*" || host == "http://*/*" || host == "https://*/*" {
            scope = HostPermissionScope::AllUrls;
        } else {
            // Extract the domain part to check for wildcards
            let domain_part = host
                .trim_start_matches("*://")
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .split('/')
                .next()
                .unwrap_or("");

            // Check if domain contains wildcard (e.g., *.google.com)
            if domain_part.starts_with("*.") || domain_part == "*" {
                if scope != HostPermissionScope::AllUrls {
                    scope = HostPermissionScope::Broad;
                }
            }
        }

        // Extract domain from pattern
        if let Some(domain) = extract_domain_from_pattern(host) {
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
    }

    (scope, domains)
}

fn extract_domain_from_pattern(pattern: &str) -> Option<String> {
    // Remove scheme prefix
    let pattern = pattern
        .trim_start_matches("*://")
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("file://");

    // Extract domain part (before first /)
    let domain = pattern.split('/').next()?;

    // Skip wildcards that match everything
    if domain == "*" {
        return None;
    }

    Some(domain.to_string())
}

/// Analyze Content Security Policy
pub fn analyze_csp(csp: Option<&str>) -> CspAnalysis {
    let mut analysis = CspAnalysis::default();

    let csp = match csp {
        Some(c) if !c.is_empty() => c,
        _ => {
            analysis.issues.push("No Content Security Policy defined".to_string());
            analysis.score = 30;
            return analysis;
        }
    };

    analysis.has_csp = true;

    // Parse CSP directives
    for directive in csp.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        let parts: Vec<&str> = directive.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let directive_name = parts[0];
        let values = &parts[1..];

        match directive_name {
            "script-src" | "default-src" => {
                for value in values {
                    if *value == "'unsafe-eval'" {
                        analysis.allows_unsafe_eval = true;
                        analysis.issues.push("CSP allows unsafe-eval (enables eval())".to_string());
                        analysis.score += 40;
                    }
                    if *value == "'unsafe-inline'" {
                        analysis.allows_unsafe_inline = true;
                        analysis.issues.push("CSP allows unsafe-inline scripts".to_string());
                        analysis.score += 30;
                    }
                    // Check for remote script sources
                    if value.starts_with("http://") || value.starts_with("https://") {
                        analysis.allows_remote_scripts = true;
                        if let Some(domain) = extract_domain_from_pattern(value) {
                            analysis.allowed_domains.push(domain);
                        }
                    }
                }
            }
            "connect-src" => {
                for value in values {
                    if value.starts_with("http://") || value.starts_with("https://") || value.contains("*") {
                        if let Some(domain) = extract_domain_from_pattern(value) {
                            if !analysis.allowed_domains.contains(&domain) {
                                analysis.allowed_domains.push(domain);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if analysis.allows_remote_scripts {
        analysis.issues.push(format!(
            "CSP allows loading scripts from {} external domain(s)",
            analysis.allowed_domains.len()
        ));
        analysis.score += 10 * analysis.allowed_domains.len() as u32;
    }

    analysis
}

/// Perform full risk analysis on an extension
pub fn analyze_extension(
    permissions: &[String],
    optional_permissions: &[String],
    host_permissions: &[String],
    csp: Option<&str>,
) -> ExtensionRiskReport {
    let mut report = ExtensionRiskReport::default();

    // Analyze required permissions
    for perm in permissions {
        let risk = get_permission_risk(perm);
        report.total_score += risk.level.score();
        report.permissions.push(risk);
    }

    // Analyze optional permissions (lower weight)
    for perm in optional_permissions {
        let risk = get_permission_risk(perm);
        report.total_score += risk.level.score() / 2; // Half weight for optional
        let mut optional_risk = risk;
        optional_risk.name = format!("{} (optional)", optional_risk.name);
        report.permissions.push(optional_risk);
    }

    // Analyze host permissions
    let (scope, hosts) = analyze_host_permissions(host_permissions);
    report.host_permission_scope = scope.clone();
    report.host_permissions = host_permissions.to_vec();
    report.total_score += scope.score();

    // Add host permissions to external domains
    report.external_domains = hosts;

    // Analyze CSP
    report.csp = analyze_csp(csp);
    report.total_score += report.csp.score;

    // Generate issues based on findings
    if report.host_permission_scope == HostPermissionScope::AllUrls {
        report.issues.push(RiskIssue {
            category: "Permissions".to_string(),
            severity: RiskLevel::Critical,
            title: "All URLs access".to_string(),
            description: "Extension can access all websites".to_string(),
        });
    }

    let critical_count = report.permissions.iter()
        .filter(|p| p.level == RiskLevel::Critical)
        .count();
    if critical_count > 0 {
        report.issues.push(RiskIssue {
            category: "Permissions".to_string(),
            severity: RiskLevel::Critical,
            title: format!("{} critical permission(s)", critical_count),
            description: "Extension requests highly dangerous permissions".to_string(),
        });
    }

    if report.csp.allows_unsafe_eval {
        report.issues.push(RiskIssue {
            category: "Security Policy".to_string(),
            severity: RiskLevel::High,
            title: "Allows eval()".to_string(),
            description: "Content Security Policy allows code execution via eval()".to_string(),
        });
    }

    // Determine overall risk level
    report.risk_level = match report.total_score {
        0..=20 => "low",
        21..=100 => "medium",
        101..=300 => "high",
        _ => "critical",
    }.to_string();

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_risk_levels() {
        assert_eq!(get_permission_risk("debugger").level, RiskLevel::Critical);
        assert_eq!(get_permission_risk("tabs").level, RiskLevel::High);
        assert_eq!(get_permission_risk("activeTab").level, RiskLevel::Medium);
        assert_eq!(get_permission_risk("storage").level, RiskLevel::Low);
    }

    #[test]
    fn test_host_permission_scope() {
        let (scope, _) = analyze_host_permissions(&["<all_urls>".to_string()]);
        assert_eq!(scope, HostPermissionScope::AllUrls);

        let (scope, _) = analyze_host_permissions(&["https://google.com/*".to_string()]);
        assert_eq!(scope, HostPermissionScope::Specific);

        let (scope, _) = analyze_host_permissions(&["https://*.google.com/*".to_string()]);
        assert_eq!(scope, HostPermissionScope::Broad);
    }

    #[test]
    fn test_csp_analysis() {
        let csp = analyze_csp(Some("script-src 'self' 'unsafe-eval'"));
        assert!(csp.has_csp);
        assert!(csp.allows_unsafe_eval);
        assert!(!csp.allows_unsafe_inline);

        let csp = analyze_csp(None);
        assert!(!csp.has_csp);
        assert!(!csp.issues.is_empty());
    }

    #[test]
    fn test_full_analysis() {
        let report = analyze_extension(
            &["tabs".to_string(), "storage".to_string()],
            &[],
            &["https://example.com/*".to_string()],
            Some("script-src 'self'"),
        );

        assert!(report.total_score > 0);
        assert_eq!(report.permissions.len(), 2);
    }
}
