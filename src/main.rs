use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use extenscan::{
    cache::Cache,
    checker::{default_checker, default_version_checker, VulnerabilityChecker},
    config::Config,
    model::{ScanResult, Severity, Source},
    output::{print_result, OutputFormat},
    scanner::{all_scanners, get_scanner, Scanner},
};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Exit codes for CI integration
mod exit_codes {
    pub const SUCCESS: u8 = 0;
    pub const CRITICAL_VULN: u8 = 2;
    pub const HIGH_VULN: u8 = 3;
    pub const MEDIUM_VULN: u8 = 4;
    pub const LOW_VULN: u8 = 5;
    pub const ERROR: u8 = 1;
}

#[derive(Parser)]
#[command(name = "extenscan")]
#[command(
    author,
    version,
    about = "Scan installed extensions and packages for vulnerabilities"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan installed extensions and packages
    Scan {
        /// Filter by source (vscode, chrome, edge, firefox, npm, homebrew)
        #[arg(short, long)]
        source: Option<String>,

        /// Output format (table, json, sarif)
        #[arg(short, long)]
        format: Option<String>,

        /// Skip vulnerability checking
        #[arg(long)]
        no_vuln_check: bool,

        /// Skip outdated version checking
        #[arg(long)]
        no_outdated_check: bool,

        /// Write output to file
        #[arg(short, long)]
        output: Option<String>,

        /// Clear cache before scanning
        #[arg(long)]
        clear_cache: bool,

        /// Exit with error if vulnerabilities at or above this severity are found
        #[arg(long, value_enum)]
        fail_on: Option<FailLevel>,

        /// Disable concurrent scanning (scan sources sequentially)
        #[arg(long)]
        no_parallel: bool,
    },

    /// List available sources
    ListSources,

    /// Show or create config file
    Config {
        /// Generate default config file
        #[arg(long)]
        init: bool,

        /// Show config file path
        #[arg(long)]
        path: bool,
    },

    /// Clear the cache
    ClearCache,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::from(exit_codes::ERROR)
        }
    }
}

async fn run() -> Result<u8> {
    let cli = Cli::parse();
    let config = Config::load().unwrap_or_default();

    match cli.command {
        Commands::Scan {
            source,
            format,
            no_vuln_check,
            no_outdated_check,
            output,
            clear_cache,
            fail_on,
            no_parallel,
        } => {
            if clear_cache {
                let cache = Cache::new();
                cache.clear()?;
            }

            let format_str = format.unwrap_or(config.default_format.clone());
            let skip_vuln = no_vuln_check || config.skip_vuln_check;
            let check_outdated = !no_outdated_check && config.check_outdated;

            run_scan(
                source,
                format_str,
                skip_vuln,
                check_outdated,
                output,
                fail_on,
                !no_parallel,
            )
            .await
        }
        Commands::ListSources => {
            list_sources();
            Ok(exit_codes::SUCCESS)
        }
        Commands::Config { init, path } => {
            handle_config(init, path)?;
            Ok(exit_codes::SUCCESS)
        }
        Commands::ClearCache => {
            let cache = Cache::new();
            cache.clear()?;
            println!("Cache cleared.");
            Ok(exit_codes::SUCCESS)
        }
    }
}

async fn run_scan(
    source_filter: Option<String>,
    format: String,
    skip_vuln_check: bool,
    check_outdated: bool,
    output_file: Option<String>,
    fail_on: Option<FailLevel>,
    parallel: bool,
) -> Result<u8> {
    let format = OutputFormat::from_str(&format).map_err(|e| anyhow::anyhow!(e))?;
    let is_interactive = format == OutputFormat::Table;

    let scanners: Vec<Box<dyn Scanner>> = if let Some(source_name) = source_filter {
        let source = parse_source(&source_name)?;
        vec![get_scanner(source)]
    } else {
        all_scanners()
    };

    // Scan packages (concurrently or sequentially)
    let all_packages = if parallel && scanners.len() > 1 {
        scan_concurrent(&scanners, is_interactive).await
    } else {
        scan_sequential(&scanners, is_interactive).await
    };

    let mut result = ScanResult::new(all_packages);

    // Check for vulnerabilities
    if !skip_vuln_check && !result.packages.is_empty() {
        let vuln_progress = if is_interactive {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap(),
            );
            pb.enable_steady_tick(Duration::from_millis(100));
            pb.set_message("Checking for vulnerabilities...");
            Some(pb)
        } else {
            None
        };

        let checker = default_checker();
        match checker.check(&result.packages).await {
            Ok(vulns) => {
                result.vulnerabilities = vulns;
            }
            Err(_) => {
                // Continue without vulnerability data
            }
        }

        if let Some(pb) = vuln_progress {
            pb.finish_with_message(format!(
                "Found {} vulnerabilities",
                result.vulnerabilities.len()
            ));
        }
    }

    // Check for outdated packages
    if check_outdated && !result.packages.is_empty() {
        let outdated_progress = if is_interactive {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.green} {msg}")
                    .unwrap(),
            );
            pb.enable_steady_tick(Duration::from_millis(100));
            pb.set_message("Checking for outdated packages...");
            Some(pb)
        } else {
            None
        };

        let version_checker = default_version_checker();
        match version_checker.check_outdated(&result.packages).await {
            Ok(outdated) => {
                result.outdated = outdated;
            }
            Err(_) => {
                // Continue without outdated data
            }
        }

        if let Some(pb) = outdated_progress {
            pb.finish_with_message(format!("Found {} outdated packages", result.outdated.len()));
        }
    }

    // Handle output
    if let Some(path) = output_file {
        let json = serde_json::to_string_pretty(&result)?;
        std::fs::write(&path, json)?;
        if is_interactive {
            println!("Results written to: {}", path);
        }
    } else {
        print_result(&result, format)?;
    }

    // Determine exit code based on --fail-on
    Ok(determine_exit_code(&result, fail_on))
}

/// Scan all sources concurrently using tokio tasks
async fn scan_concurrent(
    scanners: &[Box<dyn Scanner>],
    is_interactive: bool,
) -> Vec<extenscan::Package> {
    let progress = if is_interactive {
        let pb = ProgressBar::new(scanners.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} Scanning sources...")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(Arc::new(pb))
    } else {
        None
    };

    // Create futures for each scanner
    let futures: Vec<_> = scanners
        .iter()
        .map(|scanner| {
            let pb = progress.clone();
            async move {
                let result = if scanner.is_supported() {
                    scanner.scan().await.unwrap_or_default()
                } else {
                    Vec::new()
                };
                if let Some(ref pb) = pb {
                    pb.inc(1);
                }
                result
            }
        })
        .collect();

    // Run all scans concurrently
    let results = join_all(futures).await;

    if let Some(pb) = progress {
        let total: usize = results.iter().map(|r| r.len()).sum();
        pb.finish_with_message(format!("Found {} packages", total));
    }

    results.into_iter().flatten().collect()
}

/// Scan sources sequentially (original behavior)
async fn scan_sequential(
    scanners: &[Box<dyn Scanner>],
    is_interactive: bool,
) -> Vec<extenscan::Package> {
    let mut all_packages = Vec::new();

    let scan_progress = if is_interactive {
        let pb = ProgressBar::new(scanners.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.enable_steady_tick(Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    for scanner in scanners {
        if let Some(ref pb) = scan_progress {
            pb.set_message(format!("Scanning {}...", scanner.name()));
        }

        if !scanner.is_supported() {
            if let Some(ref pb) = scan_progress {
                pb.inc(1);
            }
            continue;
        }

        match scanner.scan().await {
            Ok(packages) => {
                all_packages.extend(packages);
            }
            Err(_) => {
                // Silently continue on errors during scanning
            }
        }

        if let Some(ref pb) = scan_progress {
            pb.inc(1);
        }
    }

    if let Some(pb) = scan_progress {
        pb.finish_with_message(format!("Found {} packages", all_packages.len()));
    }

    all_packages
}

/// Determine the exit code based on vulnerabilities found and --fail-on setting
fn determine_exit_code(result: &ScanResult, fail_on: Option<FailLevel>) -> u8 {
    let fail_on = match fail_on {
        Some(level) => level,
        None => return exit_codes::SUCCESS,
    };

    let has_critical = result
        .vulnerabilities
        .iter()
        .any(|v| v.severity == Severity::Critical);
    let has_high = result
        .vulnerabilities
        .iter()
        .any(|v| v.severity == Severity::High);
    let has_medium = result
        .vulnerabilities
        .iter()
        .any(|v| v.severity == Severity::Medium);
    let has_low = result
        .vulnerabilities
        .iter()
        .any(|v| v.severity == Severity::Low);

    match fail_on {
        FailLevel::Critical => {
            if has_critical {
                exit_codes::CRITICAL_VULN
            } else {
                exit_codes::SUCCESS
            }
        }
        FailLevel::High => {
            if has_critical {
                exit_codes::CRITICAL_VULN
            } else if has_high {
                exit_codes::HIGH_VULN
            } else {
                exit_codes::SUCCESS
            }
        }
        FailLevel::Medium => {
            if has_critical {
                exit_codes::CRITICAL_VULN
            } else if has_high {
                exit_codes::HIGH_VULN
            } else if has_medium {
                exit_codes::MEDIUM_VULN
            } else {
                exit_codes::SUCCESS
            }
        }
        FailLevel::Low => {
            if has_critical {
                exit_codes::CRITICAL_VULN
            } else if has_high {
                exit_codes::HIGH_VULN
            } else if has_medium {
                exit_codes::MEDIUM_VULN
            } else if has_low {
                exit_codes::LOW_VULN
            } else {
                exit_codes::SUCCESS
            }
        }
    }
}

fn list_sources() {
    println!("Available sources:");
    println!();

    let sources = [
        ("vscode", "VSCode Extensions", "~/.vscode/extensions/"),
        ("chrome", "Chrome Extensions", "Browser profile directory"),
        ("edge", "Edge Extensions", "Browser profile directory"),
        ("firefox", "Firefox Add-ons", "Browser profile directory"),
        ("npm", "NPM Global Packages", "npm list -g"),
        ("homebrew", "Homebrew Packages", "brew info --installed"),
    ];

    for (id, name, location) in sources {
        let scanner = get_scanner(parse_source(id).unwrap());
        let supported = if scanner.is_supported() { "yes" } else { "no" };

        println!("  {:<12} {:<25} [supported: {}]", id, name, supported);
        println!("  {:<12} Location: {}", "", location);
        println!();
    }
}

fn handle_config(init: bool, show_path: bool) -> Result<()> {
    let config_path = Config::config_path();

    if show_path {
        println!("{}", config_path.display());
        return Ok(());
    }

    if init {
        if config_path.exists() {
            println!("Config file already exists at: {}", config_path.display());
            return Ok(());
        }

        let config = Config::default();
        config.save()?;
        println!("Created config file at: {}", config_path.display());
        println!();
        println!("Default configuration:");
        println!("{}", Config::generate_default_config());
        return Ok(());
    }

    // Show current config
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        println!("Config file: {}", config_path.display());
        println!();
        println!("{}", content);
    } else {
        println!("No config file found.");
        println!("Run 'extenscan config --init' to create one.");
        println!();
        println!("Config path: {}", config_path.display());
    }

    Ok(())
}

fn parse_source(s: &str) -> Result<Source> {
    match s.to_lowercase().as_str() {
        "vscode" => Ok(Source::Vscode),
        "chrome" => Ok(Source::Chrome),
        "edge" => Ok(Source::Edge),
        "firefox" => Ok(Source::Firefox),
        "npm" => Ok(Source::Npm),
        "homebrew" | "brew" => Ok(Source::Homebrew),
        _ => Err(anyhow::anyhow!(
            "Unknown source: {}. Use: vscode, chrome, edge, firefox, npm, homebrew",
            s
        )),
    }
}
