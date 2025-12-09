use crate::types::{ScanOutput, ScanResult};
use chrono::Utc;
use colored::Colorize;
use std::fs;
use std::io;

/// Print the tool banner
pub fn print_banner(_no_color: bool) {
    // Banner removed
}

/// Print scan configuration info
pub fn print_info(
    host_count: usize,
    paths: &Option<Vec<String>>,
    threads: usize,
    timeout: u64,
    safe_check: bool,
    windows: bool,
    waf_bypass: bool,
    waf_bypass_size: u32,
    vercel_waf_bypass: bool,
    insecure: bool,
    crawl_enabled: bool,
    proxy: &Option<String>,
    no_color: bool,
) {
    let cyan = |s: &str| {
        if no_color {
            s.to_string()
        } else {
            s.cyan().to_string()
        }
    };
    let yellow = |s: &str| {
        if no_color {
            s.to_string()
        } else {
            s.yellow().to_string()
        }
    };

    println!("{}", cyan(&format!("[*] Loaded {} host(s) to scan", host_count)));

    if let Some(p) = paths {
        println!(
            "{}",
            cyan(&format!("[*] Testing {} path(s): {}", p.len(), p.join(", ")))
        );
    }

    println!("{}", cyan(&format!("[*] Using {} thread(s)", threads)));
    println!("{}", cyan(&format!("[*] Timeout: {}s", timeout)));

    if safe_check {
        println!("{}", cyan("[*] Using safe side-channel check"));
    } else {
        println!("{}", cyan("[*] Using RCE PoC check"));
    }

    if windows {
        println!("{}", cyan("[*] Windows mode enabled (PowerShell payload)"));
    }

    if waf_bypass {
        println!(
            "{}",
            cyan(&format!("[*] WAF bypass enabled ({}KB junk data)", waf_bypass_size))
        );
    }

    if vercel_waf_bypass {
        println!("{}", cyan("[*] Vercel WAF bypass mode enabled"));
    }

    if insecure {
        println!("{}", yellow("[!] SSL verification disabled"));
    }

    if crawl_enabled {
        println!("{}", cyan("[*] Crawling mode enabled"));
    }

    if let Some(proxy_url) = proxy {
        println!("{}", cyan(&format!("[*] Using proxy: {}", proxy_url)));
    }

    println!();
}

/// Print crawl start message
pub fn print_crawl_start(no_color: bool) {
    let msg = "[*] Starting URL discovery...";
    if no_color {
        println!("{}", msg);
    } else {
        println!("{}", msg.cyan());
    }
}

/// Print crawl result for a host
pub fn print_crawl_result(host: &str, discovered: usize, no_color: bool) {
    let msg = format!("[*] Crawled {} - discovered {} URL(s)", host, discovered);
    if no_color {
        println!("{}", msg);
    } else {
        println!("{}", msg.cyan());
    }
}

/// Print result for a single host
pub fn print_result(result: &ScanResult, verbose: bool, no_color: bool) {
    let host = &result.host;
    let final_url = result.final_url.as_deref();
    let tested_url = result.tested_url.as_deref();
    let redirected = final_url.is_some()
        && tested_url.is_some()
        && final_url != tested_url;

    match result.vulnerable {
        Some(true) => {
            let status = if no_color {
                "[VULNERABLE]".to_string()
            } else {
                "[VULNERABLE]".red().bold().to_string()
            };
            println!(
                "{} {} - Status: {}",
                status,
                host,
                result.status_code.unwrap_or(0)
            );
            if redirected {
                println!("  -> Redirected to: {}", final_url.unwrap_or(""));
            }
        }
        Some(false) => {
            let status = if no_color {
                "[NOT VULNERABLE]".to_string()
            } else {
                "[NOT VULNERABLE]".green().to_string()
            };
            if let Some(code) = result.status_code {
                println!("{} {} - Status: {}", status, host, code);
            } else {
                let error_msg = result.error.as_deref().unwrap_or("");
                if error_msg.is_empty() {
                    println!("{} {}", status, host);
                } else {
                    println!("{} {} - {}", status, host, error_msg);
                }
            }
            if redirected && verbose {
                println!("  -> Redirected to: {}", final_url.unwrap_or(""));
            }
        }
        None => {
            let status = if no_color {
                "[ERROR]".to_string()
            } else {
                "[ERROR]".yellow().to_string()
            };
            let error_msg = result.error.as_deref().unwrap_or("Unknown error");
            println!("{} {} - {}", status, host, error_msg);
        }
    }

    if verbose {
        if let Some(response) = &result.response {
            let label = if no_color {
                "  Response snippet:".to_string()
            } else {
                "  Response snippet:".cyan().to_string()
            };
            println!("{}", label);
            for line in response.lines().take(10) {
                println!("    {}", line);
            }
        }
    }
}

/// Print scan summary
pub fn print_summary(total: usize, vulnerable: usize, errors: usize, no_color: bool) {
    let separator = if no_color {
        "=".repeat(60)
    } else {
        "=".repeat(60).cyan().to_string()
    };

    let title = if no_color {
        "SCAN SUMMARY".to_string()
    } else {
        "SCAN SUMMARY".bold().to_string()
    };

    println!();
    println!("{}", separator);
    println!("{}", title);
    println!("{}", separator);
    println!("  Total hosts scanned: {}", total);

    if vulnerable > 0 {
        let vuln_str = if no_color {
            format!("Vulnerable: {}", vulnerable)
        } else {
            format!("Vulnerable: {}", vulnerable).red().bold().to_string()
        };
        println!("  {}", vuln_str);
    } else {
        println!("  Vulnerable: {}", vulnerable);
    }

    println!("  Not vulnerable: {}", total - vulnerable - errors);
    println!("  Errors: {}", errors);
    println!("{}", separator);
}

/// Save results to JSON file
pub fn save_results(
    results: &[ScanResult],
    output_file: &str,
    vulnerable_only: bool,
    no_color: bool,
) -> io::Result<()> {
    let filtered: Vec<ScanResult> = if vulnerable_only {
        results
            .iter()
            .filter(|r| r.vulnerable == Some(true))
            .cloned()
            .collect()
    } else {
        results.to_vec()
    };

    let output = ScanOutput {
        scan_time: Utc::now().to_rfc3339(),
        total_results: filtered.len(),
        results: filtered,
    };

    let json = serde_json::to_string_pretty(&output)?;
    fs::write(output_file, json)?;

    let msg = format!("\n[+] Results saved to: {}", output_file);
    if no_color {
        println!("{}", msg);
    } else {
        println!("{}", msg.green());
    }

    Ok(())
}

