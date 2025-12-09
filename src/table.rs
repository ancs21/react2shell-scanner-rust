use comfy_table::{presets::UTF8_FULL, Cell, Color, ContentArrangement, Table};
use std::sync::{Arc, Mutex};

/// Scan status for a crawled page
#[derive(Clone, Debug, PartialEq)]
pub enum ScanStatus {
    Pending,
    Vulnerable,
    NotVulnerable,
    Error(String),
}


/// A single row in the crawl table
#[derive(Clone, Debug)]
pub struct CrawlTableRow {
    pub index: usize,
    pub url: String,
    pub title: Option<String>,
    pub http_status: Option<u16>,
    pub scan_status: ScanStatus,
}

impl CrawlTableRow {
    pub fn with_details(
        index: usize,
        url: String,
        title: Option<String>,
        http_status: Option<u16>,
    ) -> Self {
        Self {
            index,
            url,
            title,
            http_status,
            scan_status: ScanStatus::Pending,
        }
    }
}

/// Manages the streaming table display
pub struct StreamingTable {
    rows: Arc<Mutex<Vec<CrawlTableRow>>>,
    max_url_width: usize,
    max_title_width: usize,
}

impl StreamingTable {
    pub fn new(_no_color: bool) -> Self {
        Self {
            rows: Arc::new(Mutex::new(Vec::new())),
            max_url_width: 50,
            max_title_width: 25,
        }
    }

    /// Truncate string to max width with ellipsis (UTF-8 safe)
    fn truncate(s: &str, max_width: usize) -> String {
        let char_count = s.chars().count();
        if char_count <= max_width {
            s.to_string()
        } else if max_width > 3 {
            let truncated: String = s.chars().take(max_width - 3).collect();
            format!("{}...", truncated)
        } else {
            s.chars().take(max_width).collect()
        }
    }

    /// Add a new row (no streaming output)
    pub fn add_row(&self, row: CrawlTableRow) {
        let mut rows = self.rows.lock().unwrap();
        rows.push(row);
    }

    /// Update scan status for a row by URL (no streaming output)
    pub fn update_scan_status(&self, url: &str, status: ScanStatus) {
        let mut rows = self.rows.lock().unwrap();
        if let Some(row) = rows.iter_mut().find(|r| r.url == url) {
            row.scan_status = status;
        }
    }

    /// Print final summary table using comfy-table
    pub fn print_final_table(&self) {
        let rows = self.rows.lock().unwrap();

        if rows.is_empty() {
            return;
        }

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("#").fg(Color::Cyan),
                Cell::new("URL").fg(Color::Cyan),
                Cell::new("Title").fg(Color::Cyan),
                Cell::new("Status").fg(Color::Cyan),
                Cell::new("Scan Result").fg(Color::Cyan),
            ]);

        for row in rows.iter() {
            let scan_cell = match &row.scan_status {
                ScanStatus::Vulnerable => Cell::new("VULNERABLE").fg(Color::Red),
                ScanStatus::NotVulnerable => Cell::new("NOT VULNERABLE").fg(Color::Green),
                ScanStatus::Error(msg) => Cell::new(format!("ERROR: {}", msg)).fg(Color::Yellow),
                ScanStatus::Pending => Cell::new("Pending").fg(Color::DarkGrey),
            };

            // Color HTTP status: green for 2xx, red for 4xx/5xx
            let status_cell = match row.http_status {
                Some(status) if status >= 200 && status < 300 => {
                    Cell::new(status).fg(Color::Green)
                }
                Some(status) if status >= 400 => {
                    Cell::new(status).fg(Color::Red)
                }
                Some(status) => Cell::new(status),
                None => Cell::new("-"),
            };

            table.add_row(vec![
                Cell::new(row.index),
                Cell::new(Self::truncate(&row.url, self.max_url_width)),
                Cell::new(
                    row.title
                        .as_ref()
                        .map(|t| Self::truncate(t, self.max_title_width))
                        .unwrap_or_else(|| "-".to_string()),
                ),
                status_cell,
                scan_cell,
            ]);
        }

        println!("\n{}", table);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        assert_eq!(StreamingTable::truncate("hello", 10), "hello");
        assert_eq!(StreamingTable::truncate("hello world", 8), "hello...");
        assert_eq!(StreamingTable::truncate("hi", 2), "hi");
    }

    #[test]
    fn test_scan_status_to_string() {
        assert_eq!(ScanStatus::Pending.to_string(true), "Pending");
        assert_eq!(ScanStatus::Vulnerable.to_string(true), "VULNERABLE");
        assert_eq!(ScanStatus::NotVulnerable.to_string(true), "NOT VULNERABLE");
    }

    #[test]
    fn test_crawl_table_row_with_details() {
        let row = CrawlTableRow::with_details(
            1,
            "https://example.com".to_string(),
            Some("Example".to_string()),
            Some(200),
        );
        assert_eq!(row.index, 1);
        assert_eq!(row.url, "https://example.com");
        assert_eq!(row.title, Some("Example".to_string()));
        assert_eq!(row.http_status, Some(200));
        assert_eq!(row.scan_status, ScanStatus::Pending);
    }
}
