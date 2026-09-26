//! Prints the new-vs-0.24.1 table and applies the throughput gate
//! (median new/old wall-time ratio <= COMPAT_MAX_RATIO, default 1.03).
//! Exit status 1 when a gate fails.

use flowscope_compat::{Scenario, alloc::Counting, run_new, run_old};

#[global_allocator]
static A: Counting = Counting;

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let max_ratio: f64 = std::env::var("COMPAT_MAX_RATIO")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.03);
    let reps: usize = std::env::var("COMPAT_REPS").ok().and_then(|v| v.parse().ok()).unwrap_or(7);
    let only: Option<String> = std::env::args().nth(1);
    let mut failed = false;
    println!(
        "{:<18} {:>12} {:>12} {:>12} {:>12} {:>14} {:>14} {:>9} {:>9} {:>6}",
        "scenario", "blocks new", "blocks old", "peak new", "peak old", "retained new", "retained old", "ms new", "ms old", "ratio"
    );
    for s in Scenario::ALL {
        if let Some(o) = &only {
            if !s.name().contains(o.as_str()) {
                continue;
            }
        }
        let cap = s.traffic();
        let (mut tn, mut to) = (Vec::new(), Vec::new());
        let (mut cn, mut co) = (None, None);
        for r in 0..reps {
            // Alternate order so neither version always runs cold.
            let (a, b) = if r % 2 == 0 {
                let a = run_new::run(s, &cap);
                (a, run_old::run(s, &cap))
            } else {
                let b = run_old::run(s, &cap);
                (run_new::run(s, &cap), b)
            };
            tn.push(a.1.time.as_secs_f64());
            to.push(b.1.time.as_secs_f64());
            cn = Some(a);
            co = Some(b);
        }
        let (on, cn) = cn.unwrap();
        let (oo, co) = co.unwrap();
        let (mn, mo) = (median(tn), median(to));
        let ratio = mn / mo;
        let gate = ratio <= max_ratio;
        failed |= !gate;
        println!(
            "{:<18} {:>12} {:>12} {:>12} {:>12} {:>14} {:>14} {:>9.2} {:>9.2} {:>5.3}{}",
            s.name(),
            cn.blocks,
            co.blocks,
            cn.peak_bytes,
            co.peak_bytes,
            cn.retained_bytes,
            co.retained_bytes,
            mn * 1e3,
            mo * 1e3,
            ratio,
            if gate { "" } else { " FAIL" }
        );
        println!("    new {on:?}\n    old {oo:?}");
    }
    if failed {
        std::process::exit(1);
    }
}
