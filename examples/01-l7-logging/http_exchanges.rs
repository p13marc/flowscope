//! One log line per HTTP request/response pair.
//!
//! Uses [`flowscope::http::HttpExchangeParser`] (plan 107, 0.10) —
//! the aggregator that stitches each request to its response and
//! emits a single [`flowscope::http::HttpExchange`] event with
//! elapsed RTT and an [`flowscope::http::HttpOutcome`]
//! discriminant.
//!
//! Compare to `http_log.rs` which dumps the per-message
//! `HttpRequest` / `HttpResponse` stream — this version is what you
//! reach for when you want one access-log-shaped row per exchange.
//!
//! ```bash
//! cargo run --features http,pcap --example http_exchanges -- trace.pcap
//! ```
//!
//! Closes issues #32 (UTF-8 panic on User-Agent slice) and #37
//! (port to the high-level `flowscope::pcap::session_messages` shape).

use flowscope::http::{HttpExchangeParser, HttpOutcome};
use flowscope::pcap::session_messages;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    println!(
        "{:<8} {:<6} {:<24} {:<32} {:<8} {:>5} {:>9}",
        "outcome", "status", "src → dst", "host + method + path", "ua", "ms", "bytes"
    );

    for (key, ex) in session_messages::<HttpExchangeParser>(&path)? {
        let outcome = match ex.outcome {
            HttpOutcome::Completed if ex.is_success() => "2xx",
            HttpOutcome::Completed if ex.status_class() == Some(3) => "3xx",
            HttpOutcome::Completed if ex.is_error() => "err",
            HttpOutcome::Completed => "1xx",
            HttpOutcome::NoResponse => "no-resp",
            HttpOutcome::Reset => "rst",
            _ => "?",
        };
        let status = ex
            .response
            .as_ref()
            .map(|r| r.status.to_string())
            .unwrap_or_else(|| "-".to_string());
        let host = ex.request.host().unwrap_or("?");
        // BUGFIX (#32): truncate by char count, not byte index —
        // slicing on byte boundaries panics on multi-byte UTF-8.
        let ua = ex
            .request
            .user_agent()
            .map(|s| s.chars().take(8).collect::<String>())
            .unwrap_or_else(|| "-".to_string());
        let elapsed_ms = ex.elapsed.map(|d| d.as_secs_f64() * 1000.0).unwrap_or(0.0);
        let bytes = ex.response.as_ref().map(|r| r.body.len()).unwrap_or(0);
        println!(
            "{outcome:<8} {status:<6} {:<24} {:<32} {ua:<8} {elapsed_ms:>5.1} {bytes:>9}",
            format!("{} → {}", key.a.ip(), key.b.ip()),
            format!(
                "{host} {} {}",
                ex.request.method_str().unwrap_or("?"),
                ex.request.path_str().unwrap_or("?")
            ),
        );
    }

    Ok(())
}
