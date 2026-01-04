use anyhow::Result;
use clap::{Parser, Subcommand};
use extenscan::{
    cache::Cache,
    checker::{default_checker, default_version_checker, VulnerabilityChecker},
    config::Config,
    model::{ScanResult, Source},
    output::{print_result, OutputFormat},
    scanner::{all_scanners, get_scanner, Scanner},
};
use indicatif::{ProgressBar, ProgressStyle};
use std::str::FromStr;
use std::time::Duration;

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

        /// Output format (table, json)
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

#[tokio::main]
async fn main() -> Result<()> {
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
        } => {
            if clear_cache {
                let cache = Cache::new();
                cache.clear()?;
            }

            let format_str = format.unwrap_or(config.default_format.clone());
            let skip_vuln = no_vuln_check || config.skip_vuln_check;
            let check_outdated = !no_outdated_check && config.check_outdated;

            run_scan(source, format_str, skip_vuln, check_outdated, output).await?;
        }
        Commands::ListSources => {
            list_sources();
        }
        Commands::Config { init, path } => {
            handle_config(init, path)?;
        }
        Commands::ClearCache => {
            let cache = Cache::new();
            cache.clear()?;
            println!("Cache cleared.");
        }
    }

    Ok(())
}

async fn run_scan(
    source_filter: Option<String>,
    format: String,
    skip_vuln_check: bool,
    check_outdated: bool,
    output_file: Option<String>,
) -> Result<()> {
    let format = OutputFormat::from_str(&format).map_err(|e| anyhow::anyhow!(e))?;
    let is_interactive = format == OutputFormat::Table;

    let scanners: Vec<Box<dyn Scanner>> = if let Some(source_name) = source_filter {
        let source = parse_source(&source_name)?;
        vec![get_scanner(source)]
    } else {
        all_scanners()
    };

    let mut all_packages = Vec::new();

    // Create progress bar for scanning
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

    for scanner in &scanners {
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

    Ok(())
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
