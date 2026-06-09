//! One log line per HTTP request/response pair.
//!
//! Uses [`flowscope::http::HttpExchangeParser`] (plan 107, 0.10)
//! — the aggregator that stitches each request to its response
//! and emits a single [`flowscope::http::HttpExchange`] event
//! with elapsed RTT and an [`flowscope::http::HttpOutcome`]
//! discriminant.
//!
//! Compare to `http_log.rs` which dumps the per-message
//! `HttpRequest` / `HttpResponse` stream — this version is what
//! you reach for when you want one access-log-shaped row per
//! exchange.
//!
//! ```bash
//! cargo run --features http,pcap --example http_exchanges
//! ```

use flowscope::extract::FiveTuple;
use flowscope::http::{HttpExchangeParser, HttpOutcome};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpExchangeParser::new());

    println!(
        "{:<8} {:<6} {:<24} {:<32} {:<8} {:>5} {:>9}",
        "outcome", "status", "src → dst", "host + method + path", "ua", "ms", "bytes"
    );

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in driver.track(&owned) {
            let SessionEvent::Application {
                key, message: ex, ..
            } = ev
            else {
                continue;
            };
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
            let ua = ex
                .request
                .user_agent()
                .map(|s| {
                    if s.len() > 8 {
                        s[..8].to_string()
                    } else {
                        s.to_string()
                    }
                })
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
    }
    Ok(())
}
