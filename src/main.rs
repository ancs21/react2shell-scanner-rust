mod crawler;
mod detection;
mod output;
mod payload;
mod scanner;
mod table;
mod types;

use clap::Parser;
use colored::control::set_override;
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::fs;
use std::process;
use std::sync::Arc;
use table::{CrawlTableRow, ScanStatus, StreamingTable};
use tokio::sync::{mpsc, Semaphore};
use types::{ScanConfig, ScanResult};

#[derive(Parser, Debug)]
#[command(name = "react2shell-scanner")]
#[command(about = "React2Shell Scanner - High Fidelity Detection for RSC/Next.js RCE\nCVE-2025-55182 & CVE-2025-66478\n\nBased on research from Assetnote Security Research Team.")]
#[command(version)]
struct Cli {
    /// Single URL/host to check
    #[arg(short, long, conflicts_with = "list")]
    url: Option<String>,

    /// File containing list of hosts (one per line)
    #[arg(short, long, conflicts_with = "url")]
    list: Option<String>,

    /// Number of concurrent requests
    #[arg(short = 't', long = "threads", default_value = "10")]
    threads: usize,

    /// Request timeout in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,

    /// Output file for results (JSON format)
    #[arg(short, long)]
    output: Option<String>,

    /// Save all results to output file, not just vulnerable hosts
    #[arg(long)]
    all_results: bool,

    /// Disable SSL certificate verification
    #[arg(short = 'k', long)]
    insecure: bool,

    /// Custom header in 'Key: Value' format (can be used multiple times)
    #[arg(short = 'H', long = "header", action = clap::ArgAction::Append)]
    headers: Vec<String>,

    /// Verbose output (show response snippets for all hosts)
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode (only show vulnerable hosts)
    #[arg(short, long)]
    quiet: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Use safe side-channel detection instead of RCE PoC
    #[arg(long)]
    safe_check: bool,

    /// Use Windows PowerShell payload instead of Unix shell
    #[arg(long)]
    windows: bool,

    /// Add junk data to bypass WAF content inspection
    #[arg(long)]
    waf_bypass: bool,

    /// Size of junk data in KB for WAF bypass
    #[arg(long, default_value = "128")]
    waf_bypass_size: u32,

    /// Use Vercel WAF bypass payload variant
    #[arg(long)]
    vercel_waf_bypass: bool,

    /// Custom path to test (can be used multiple times)
    #[arg(long, action = clap::ArgAction::Append)]
    path: Vec<String>,

    /// File containing paths to test (one per line)
    #[arg(long)]
    path_file: Option<String>,

    /// Enable crawling mode to discover URLs before scanning
    #[arg(long)]
    crawl: bool,

    /// Maximum crawl depth
    #[arg(long, default_value = "2")]
    max_depth: usize,

    /// Maximum pages to crawl per host
    #[arg(long, default_value = "100")]
    max_pages: usize,

    /// Crawl timeout in seconds
    #[arg(long, default_value = "60")]
    crawl_timeout: u64,

    /// Ignore robots.txt restrictions when crawling
    #[arg(long)]
    ignore_robots: bool,

    /// Proxy URL (e.g., http://127.0.0.1:8080, socks5://127.0.0.1:1080)
    #[arg(long)]
    proxy: Option<String>,
}

/// Load hosts from a file, one per line
fn load_hosts(path: &str) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|s| s.to_string())
        .collect())
}

/// Load paths from a file, one per line
fn load_paths_from_file(path: &str) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read file: {}", e))?;

    Ok(content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|p| {
            if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{}", p)
            }
        })
        .collect())
}

/// Parse custom headers from CLI arguments
fn parse_headers(header_list: &[String]) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for header in header_list {
        if let Some((key, value)) = header.split_once(": ") {
            headers.insert(key.to_string(), value.to_string());
        } else if let Some((key, value)) = header.split_once(':') {
            headers.insert(key.to_string(), value.trim_start().to_string());
        }
    }
    headers
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Handle color output
    if cli.no_color || !atty::is(atty::Stream::Stdout) {
        set_override(false);
    }

    // Validate mutual exclusivity
    if cli.url.is_none() && cli.list.is_none() {
        eprintln!("Error: Either --url or --list is required");
        process::exit(1);
    }

    // Load hosts
    let hosts: Vec<String> = if let Some(url) = &cli.url {
        vec![url.clone()]
    } else if let Some(list_file) = &cli.list {
        match load_hosts(list_file) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                process::exit(1);
            }
        }
    } else {
        vec![]
    };

    if hosts.is_empty() {
        eprintln!("[ERROR] No hosts to scan");
        process::exit(1);
    }

    // Crawl hosts if enabled (with streaming table display)
    let (scan_urls, streaming_table): (Vec<String>, Option<Arc<StreamingTable>>) = if cli.crawl {
        if !cli.quiet {
            output::print_crawl_start(cli.no_color);
        }

        let crawl_config = crawler::CrawlConfig {
            max_depth: cli.max_depth,
            max_pages: cli.max_pages,
            respect_robots: !cli.ignore_robots,
            timeout_secs: cli.crawl_timeout,
        };

        // Create table for results
        let table = Arc::new(StreamingTable::new(cli.no_color));

        let mut page_index = 0usize;
        let mut all_urls: Vec<String> = Vec::new();

        for host in &hosts {
            let normalized_host = scanner::normalize_host(host);
            if normalized_host.is_empty() {
                continue;
            }

            // Create channel for streaming pages
            let (tx, mut rx) = mpsc::channel::<crawler::PageInfo>(100);

            // Clone for the crawl task
            let crawl_host = normalized_host.clone();
            let crawl_config_clone = crawler::CrawlConfig {
                max_depth: crawl_config.max_depth,
                max_pages: crawl_config.max_pages,
                respect_robots: crawl_config.respect_robots,
                timeout_secs: crawl_config.timeout_secs,
            };

            // Start crawling in background
            let crawl_task = tokio::spawn(async move {
                crawler::crawl_site_streaming(&crawl_host, &crawl_config_clone, tx).await;
            });

            // Process pages as they come in
            while let Some(page_info) = rx.recv().await {
                page_index += 1;

                // Add row to table
                if !cli.quiet {
                    let row = CrawlTableRow::with_details(
                        page_index,
                        page_info.url.clone(),
                        page_info.title.clone(),
                        page_info.status_code,
                    );
                    table.add_row(row);
                }

                all_urls.push(page_info.url);
            }

            // Wait for crawl to complete
            let _ = crawl_task.await;

            if !cli.quiet {
                output::print_crawl_result(&normalized_host, page_index, cli.no_color);
            }
        }

        // Deduplicate
        all_urls.sort();
        all_urls.dedup();

        if all_urls.is_empty() {
            // If crawling found nothing, fall back to original hosts
            if !cli.quiet {
                println!("[*] No URLs discovered, falling back to original hosts");
            }
            (hosts, Some(table))
        } else {
            if !cli.quiet {
                println!("\n[*] Total unique URLs to scan: {}", all_urls.len());
                println!();
            }
            (all_urls, Some(table))
        }
    } else {
        (hosts.clone(), None)
    };

    // Load paths
    let paths: Option<Vec<String>> = if let Some(path_file) = &cli.path_file {
        match load_paths_from_file(path_file) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                process::exit(1);
            }
        }
    } else if !cli.path.is_empty() {
        Some(
            cli.path
                .iter()
                .map(|p| {
                    if p.starts_with('/') {
                        p.clone()
                    } else {
                        format!("/{}", p)
                    }
                })
                .collect(),
        )
    } else {
        None
    };

    // Parse custom headers
    let custom_headers = parse_headers(&cli.headers);

    // Adjust timeout for WAF bypass mode
    let timeout = if cli.waf_bypass && cli.timeout == 10 {
        20
    } else {
        cli.timeout
    };

    // Build config
    let config = Arc::new(ScanConfig {
        timeout_secs: timeout,
        verify_ssl: !cli.insecure,
        follow_redirects: true,
        custom_headers,
        safe_check: cli.safe_check,
        windows: cli.windows,
        waf_bypass: cli.waf_bypass,
        waf_bypass_size_kb: cli.waf_bypass_size,
        vercel_waf_bypass: cli.vercel_waf_bypass,
        paths: paths.clone(),
        verbose: cli.verbose,
        quiet: cli.quiet,
        no_color: cli.no_color,
        proxy: cli.proxy.clone(),
    });

    // Print banner and info
    if !cli.quiet {
        output::print_banner(cli.no_color);
        output::print_info(
            scan_urls.len(),
            &paths,
            cli.threads,
            timeout,
            cli.safe_check,
            cli.windows,
            cli.waf_bypass,
            cli.waf_bypass_size,
            cli.vercel_waf_bypass,
            cli.insecure,
            cli.crawl,
            &cli.proxy,
            cli.no_color,
        );
    }

    // Track statistics
    let mut vulnerable_count = 0;
    let mut error_count = 0;
    let results: Vec<ScanResult>;

    if scan_urls.len() == 1 {
        // Single host mode - no progress bar
        let result = scanner::check_vulnerability(&scan_urls[0], &config).await;

        if result.vulnerable == Some(true) {
            vulnerable_count = 1;
        }
        if result.error.is_some() && result.vulnerable.is_none() {
            error_count = 1;
        }

        // Update streaming table if in crawl mode
        if let Some(ref table) = streaming_table {
            let status = if result.vulnerable == Some(true) {
                ScanStatus::Vulnerable
            } else if result.error.is_some() {
                ScanStatus::Error(result.error.clone().unwrap_or_default())
            } else {
                ScanStatus::NotVulnerable
            };
            table.update_scan_status(&scan_urls[0], status);
        } else if !cli.quiet || result.vulnerable == Some(true) {
            output::print_result(&result, cli.verbose, cli.no_color);
        }

        results = vec![result];
    } else {
        // Multiple hosts - concurrent scanning
        // Use streaming table for crawl mode, progress bar otherwise
        let use_streaming_table = streaming_table.is_some();

        let pb = if !cli.quiet && !use_streaming_table {
            let pb = ProgressBar::new(scan_urls.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({per_sec})")
                    .expect("Invalid progress bar template")
                    .progress_chars("=> "),
            );
            Some(pb)
        } else {
            None
        };

        if use_streaming_table && !cli.quiet {
            println!("\n[*] Starting vulnerability scan...\n");
        }

        let semaphore = Arc::new(Semaphore::new(cli.threads));
        let pb_clone = pb.clone();
        let verbose = cli.verbose;
        let quiet = cli.quiet;
        let no_color = cli.no_color;
        let table_clone = streaming_table.clone();

        let scan_results: Vec<ScanResult> = stream::iter(scan_urls.clone())
            .map(|host| {
                let config = Arc::clone(&config);
                let semaphore = Arc::clone(&semaphore);
                let pb = pb_clone.clone();
                let table = table_clone.clone();
                let host_clone = host.clone();

                async move {
                    let _permit = semaphore.acquire().await.expect("Semaphore closed");
                    let result = scanner::check_vulnerability(&host, &config).await;

                    // Update streaming table if in crawl mode
                    if let Some(ref table) = table {
                        let status = if result.vulnerable == Some(true) {
                            ScanStatus::Vulnerable
                        } else if result.error.is_some() {
                            ScanStatus::Error(result.error.clone().unwrap_or_default())
                        } else {
                            ScanStatus::NotVulnerable
                        };
                        table.update_scan_status(&host_clone, status);
                    } else if let Some(ref pb) = pb {
                        pb.inc(1);
                        if result.vulnerable == Some(true) {
                            pb.suspend(|| {
                                println!();
                                output::print_result(&result, verbose, no_color);
                            });
                        } else if verbose && !quiet {
                            pb.suspend(|| {
                                println!();
                                output::print_result(&result, verbose, no_color);
                            });
                        }
                    }

                    result
                }
            })
            .buffer_unordered(cli.threads)
            .collect()
            .await;

        if let Some(pb) = pb {
            pb.finish_and_clear();
        }

        // Count results
        for result in &scan_results {
            if result.vulnerable == Some(true) {
                vulnerable_count += 1;
            }
            if result.error.is_some() && result.vulnerable.is_none() {
                error_count += 1;
            }
        }

        results = scan_results;
    }

    // Print final table if in crawl mode
    if let Some(ref table) = streaming_table {
        if !cli.quiet {
            table.print_final_table();
        }
    }

    // Print summary
    if !cli.quiet {
        output::print_summary(scan_urls.len(), vulnerable_count, error_count, cli.no_color);
    }

    // Save output
    if let Some(output_file) = &cli.output {
        if let Err(e) = output::save_results(&results, output_file, !cli.all_results, cli.no_color)
        {
            eprintln!("[ERROR] Failed to save results: {}", e);
        }
    }

    // Exit code
    if vulnerable_count > 0 {
        process::exit(1);
    }
}
