use regex::Regex;
use spider::hashbrown::HashMap;
use spider::website::Website;
use std::time::Duration;
use tokio::sync::mpsc;

/// Configuration for crawling
pub struct CrawlConfig {
    pub max_depth: usize,
    pub max_pages: usize,
    pub respect_robots: bool,
    pub timeout_secs: u64,
}

/// Information about a discovered page
#[derive(Clone, Debug)]
pub struct PageInfo {
    pub url: String,
    pub title: Option<String>,
    pub status_code: Option<u16>,
}

/// Extract title from HTML content
fn extract_title(html: &str) -> Option<String> {
    let re = Regex::new(r"<title[^>]*>([^<]+)</title>").ok()?;
    re.captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Crawl a website with streaming - sends pages as they're discovered
pub async fn crawl_site_streaming(
    base_url: &str,
    config: &CrawlConfig,
    page_sender: mpsc::Sender<PageInfo>,
) {
    let mut website = Website::new(base_url);

    // Configure spider
    website.with_depth(config.max_depth);
    website.with_respect_robots_txt(config.respect_robots);

    // Set page budget
    let mut budget: HashMap<&str, u32> = HashMap::new();
    budget.insert("*", config.max_pages as u32);
    website.with_budget(Some(budget));

    // Scrape website with timeout
    let timeout = Duration::from_secs(config.timeout_secs);
    let scrape_result = tokio::time::timeout(timeout, website.scrape()).await;

    if scrape_result.is_err() {
        eprintln!("[!] Crawl timed out after {}s", config.timeout_secs);
    }

    // Get all pages and send them
    if let Some(pages) = website.get_pages() {
        for page in pages.iter() {
            let url = page.get_url().to_string();
            let html = page.get_html();
            let title = extract_title(&html);
            let _ = page_sender
                .send(PageInfo {
                    url,
                    title,
                    status_code: Some(page.status_code.as_u16()),
                })
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawl_config_defaults() {
        let config = CrawlConfig {
            max_depth: 2,
            max_pages: 100,
            respect_robots: true,
            timeout_secs: 60,
        };
        assert_eq!(config.max_depth, 2);
        assert_eq!(config.max_pages, 100);
        assert!(config.respect_robots);
        assert_eq!(config.timeout_secs, 60);
    }
}
