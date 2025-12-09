# react2shell-scanner-rust

Detect CVE-2025-55182 & CVE-2025-66478 in Next.js/RSC applications.

## Install

```bash
cargo build --release
```

## Usage

```bash
./scanner -u https://example.com
./scanner -l hosts.txt -t 20 -o results.json
./scanner -u https://example.com --crawl --max-depth 3
./scanner -u https://example.com --proxy http://127.0.0.1:8080
./scanner -u https://example.com --safe-check
./scanner -u https://example.com --waf-bypass
./scanner -u https://example.com --windows
```

## Options

```
-u, --url           Single URL to check
-l, --list          File with hosts (one per line)
-t, --threads       Concurrent threads (default: 10)
-o, --output        Output JSON file
-k, --insecure      Skip SSL verification
-H, --header        Custom header
-v, --verbose       Show response details
-q, --quiet         Only show vulnerable hosts
--safe-check        Side-channel detection (no RCE)
--windows           PowerShell payload
--waf-bypass        Add junk data to evade WAF
--waf-bypass-size   Junk size in KB (default: 128)
--vercel-waf-bypass Vercel WAF bypass variant
--path              Custom path to test
--path-file         File with paths
--crawl             Crawl site before scanning
--max-depth         Crawl depth (default: 2)
--max-pages         Max pages to crawl (default: 100)
--ignore-robots     Ignore robots.txt
--proxy             Proxy URL (http/socks5)
```

## Credits

- [@maple3142](https://x.com/maple3142) - RCE PoC
- [Assetnote](https://x.com/assetnote) - Research Team
- [@xEHLE_](https://x.com/xEHLE_) - Header reflection
- [@Nagli](https://x.com/galnagli)
