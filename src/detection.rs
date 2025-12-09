use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::header::HeaderMap;

/// Compiled regex for RCE detection - matches /login?a=11111 in X-Action-Redirect header
static RCE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r".*/login\?a=11111.*").expect("Failed to compile RCE regex")
});

/// Check if a response indicates vulnerability using safe side-channel detection
///
/// Returns true if:
/// - Status code is 500
/// - Body contains `E{"digest"`
/// - Server is NOT Netlify or Vercel (mitigated)
pub fn is_vulnerable_safe_check(status: u16, body: &str, headers: &HeaderMap) -> bool {
    // Must be 500 with specific error digest pattern
    if status != 500 || !body.contains(r#"E{"digest""#) {
        return false;
    }

    // Check for Vercel/Netlify mitigations (not valid findings)
    let server = headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let has_netlify_vary = headers.contains_key("netlify-vary");

    let is_mitigated = has_netlify_vary || server == "netlify" || server == "vercel";

    !is_mitigated
}

/// Check if a response indicates vulnerability using RCE PoC detection
///
/// Returns true if X-Action-Redirect header contains /login?a=11111
/// (result of 41*271 calculation)
pub fn is_vulnerable_rce_check(headers: &HeaderMap) -> bool {
    headers
        .get("x-action-redirect")
        .and_then(|v| v.to_str().ok())
        .map(|v| RCE_REGEX.is_match(v))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_rce_check_vulnerable() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-action-redirect",
            HeaderValue::from_static("/login?a=11111"),
        );
        assert!(is_vulnerable_rce_check(&headers));
    }

    #[test]
    fn test_rce_check_not_vulnerable() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-action-redirect",
            HeaderValue::from_static("/login?a=12345"),
        );
        assert!(!is_vulnerable_rce_check(&headers));
    }

    #[test]
    fn test_rce_check_no_header() {
        let headers = HeaderMap::new();
        assert!(!is_vulnerable_rce_check(&headers));
    }

    #[test]
    fn test_safe_check_vulnerable() {
        let headers = HeaderMap::new();
        assert!(is_vulnerable_safe_check(
            500,
            r#"E{"digest":"something"}"#,
            &headers
        ));
    }

    #[test]
    fn test_safe_check_wrong_status() {
        let headers = HeaderMap::new();
        assert!(!is_vulnerable_safe_check(
            200,
            r#"E{"digest":"something"}"#,
            &headers
        ));
    }

    #[test]
    fn test_safe_check_mitigated_vercel() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("vercel"));
        assert!(!is_vulnerable_safe_check(
            500,
            r#"E{"digest":"something"}"#,
            &headers
        ));
    }

    #[test]
    fn test_safe_check_mitigated_netlify() {
        let mut headers = HeaderMap::new();
        headers.insert("netlify-vary", HeaderValue::from_static("true"));
        assert!(!is_vulnerable_safe_check(
            500,
            r#"E{"digest":"something"}"#,
            &headers
        ));
    }
}
