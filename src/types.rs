use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during scanning
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("SSL error: {0}")]
    SslError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Request timed out")]
    Timeout,
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Configuration for scanning
#[derive(Clone)]
#[allow(dead_code)]
pub struct ScanConfig {
    pub timeout_secs: u64,
    pub verify_ssl: bool,
    pub follow_redirects: bool,
    pub custom_headers: HashMap<String, String>,
    pub safe_check: bool,
    pub windows: bool,
    pub waf_bypass: bool,
    pub waf_bypass_size_kb: u32,
    pub vercel_waf_bypass: bool,
    pub paths: Option<Vec<String>>,
    pub verbose: bool,
    pub quiet: bool,
    pub no_color: bool,
    pub proxy: Option<String>,
}

/// Result of scanning a single host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub vulnerable: Option<bool>,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub request: Option<String>,
    pub response: Option<String>,
    pub final_url: Option<String>,
    pub tested_url: Option<String>,
    pub timestamp: String,
}

impl ScanResult {
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            vulnerable: None,
            status_code: None,
            error: None,
            request: None,
            response: None,
            final_url: None,
            tested_url: None,
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

/// JSON output structure for saving results
#[derive(Serialize)]
pub struct ScanOutput {
    pub scan_time: String,
    pub total_results: usize,
    pub results: Vec<ScanResult>,
}
