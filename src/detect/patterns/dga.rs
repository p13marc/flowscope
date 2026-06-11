//! DGA likelihood scorer via bigram log-likelihood.
//!
//! Scores the second-level domain (consumer-stripped TLD,
//! lowercased) against a bigram probability table computed from
//! a bundled English-baseline corpus. Outputs a `DgaScore` with
//! the log-likelihood plus auxiliary features (length, vowel
//! ratio, digit ratio, max consonant-run, character entropy)
//! suitable for composite scoring.
//!
//! Mean per-bigram log-likelihood:
//!
//! ```text
//!   S(domain) = (1 / (L − 1)) · Σ_{i=1..L−1} log P(c_{i+1} | c_i)
//! ```
//!
//! Higher (less negative) → more "natural" English-like;
//! lower → more DGA-like. Default verdict threshold:
//! `log_likelihood < -3.5`. Customize via [`DgaScorer::is_dga_with_threshold`].
//!
//! The embedded baseline corpus is a small curated set of
//! ~80 high-traffic English second-level domains
//! (google / facebook / amazon / etc.) — enough to distinguish
//! algorithmically-generated random strings from
//! human-readable domains. Consumers wanting tighter tuning
//! against a specific deployment compute their own reference
//! distribution from a representative SLD list and ship a
//! custom scorer.

use std::sync::OnceLock;

/// Alphabet classes: a-z (26) + 0-9 (10) + `-` (1) = 37.
const ALPHA_LEN: usize = 37;

/// Embedded English-baseline corpus — short, curated, all
/// lowercase, second-level only (no TLD, no subdomain).
const BASELINE_CORPUS: &str = "\
google facebook amazon youtube wikipedia twitter instagram linkedin \
microsoft apple netflix reddit github stackoverflow gmail outlook yahoo \
spotify discord twitch tumblr pinterest paypal ebay craigslist nytimes \
washingtonpost bloomberg cnn bbc forbes wallstreet medium quora \
slack zoom dropbox salesforce oracle cisco intel hewlettpackard \
ibm sony samsung huawei panasonic toshiba canon nikon adobe autodesk \
mozilla cloudflare digitalocean linode heroku atlassian docker kubernetes \
hashicorp grafana datadog newrelic splunk elastic redis postgres mysql \
mongodb cassandra rabbitmq kafka jenkins gitlab bitbucket sourceforge \
nasa whitehouse stanford harvard berkeley mit oxford cambridge unesco \
healthline mayoclinic webmd weather forecast espn nba mlb nfl bbc \
metro guardian timeout reuters bbcnews aljazeera bloomberg techcrunch \
arstechnica wired engadget verge polygon kotaku gizmodo lifehacker";

/// Compiled bigram log-likelihood table, initialised once per
/// program lifetime.
static BIGRAM_TABLE: OnceLock<[[f32; ALPHA_LEN]; ALPHA_LEN]> = OnceLock::new();

/// Default DGA scorer with the bundled English baseline.
pub struct DgaScorer {
    table: &'static [[f32; ALPHA_LEN]; ALPHA_LEN],
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DgaScore {
    /// Mean log-likelihood per bigram (natural log).
    /// More negative → more DGA-like.
    pub log_likelihood: f32,
    /// SLD length in characters (post-classification).
    pub length: u32,
    /// Ratio of vowels (`aeiou`) to total alphabetic characters.
    pub vowel_ratio: f32,
    /// Ratio of digits (`0-9`) to total characters.
    pub digit_ratio: f32,
    /// Length of the longest run of consecutive consonants.
    pub max_consonant_run: u32,
    /// Shannon entropy in bits/char over the classified
    /// alphabet (a-z, 0-9, `-`).
    pub char_entropy: f32,
}

impl DgaScorer {
    /// Construct with the bundled English-baseline bigram table.
    pub fn new() -> Self {
        Self {
            table: BIGRAM_TABLE.get_or_init(compile_baseline_table),
        }
    }

    /// Score `sld`. Returns a `DgaScore` whose
    /// `log_likelihood` is the mean per-bigram log-likelihood
    /// across classifiable characters.
    pub fn score(&self, sld: &str) -> DgaScore {
        let classified: Vec<usize> = sld.chars().filter_map(class).collect();
        let length = classified.len() as u32;
        if length < 2 {
            return DgaScore {
                log_likelihood: 0.0,
                length,
                vowel_ratio: 0.0,
                digit_ratio: 0.0,
                max_consonant_run: 0,
                char_entropy: 0.0,
            };
        }
        // Mean per-bigram log-likelihood.
        let mut sum_ll = 0.0f32;
        for w in classified.windows(2) {
            sum_ll += self.table[w[0]][w[1]];
        }
        let log_likelihood = sum_ll / (classified.len() - 1) as f32;
        // Auxiliary features.
        let mut alpha = 0u32;
        let mut vowels = 0u32;
        let mut digits = 0u32;
        let mut run = 0u32;
        let mut max_run = 0u32;
        for &c in &classified {
            if c < 26 {
                alpha += 1;
                if is_vowel(c) {
                    vowels += 1;
                    run = 0;
                } else {
                    run += 1;
                    if run > max_run {
                        max_run = run;
                    }
                }
            } else if (26..36).contains(&c) {
                digits += 1;
                run = 0;
            } else {
                run = 0;
            }
        }
        let vowel_ratio = if alpha > 0 {
            vowels as f32 / alpha as f32
        } else {
            0.0
        };
        let digit_ratio = digits as f32 / length as f32;
        DgaScore {
            log_likelihood,
            length,
            vowel_ratio,
            digit_ratio,
            max_consonant_run: max_run,
            char_entropy: char_entropy(&classified),
        }
    }

    /// Default-threshold verdict: `log_likelihood < -3.5`.
    /// Empirically separates the bundled baseline corpus from
    /// random DGA-like strings.
    pub fn is_dga(&self, sld: &str) -> bool {
        self.is_dga_with_threshold(sld, -3.5)
    }

    /// Verdict against a caller-supplied threshold.
    pub fn is_dga_with_threshold(&self, sld: &str, threshold: f32) -> bool {
        self.score(sld).log_likelihood < threshold
    }
}

#[cfg(feature = "tracker")]
impl DgaScore {
    /// Convert into the canonical [`OwnedAnomaly`](crate::OwnedAnomaly) shape with
    /// the given timestamp and (optionally) a flow key for
    /// 5-tuple context. DGA scoring is keyless on the detector
    /// side, but consumers usually have a flow key from the DNS
    /// query context — pass it here to populate `src_ip` / `dest_ip`
    /// / etc.
    ///
    /// Severity is `Info` by default; downstream consumers
    /// threshold on `log_likelihood` to escalate.
    ///
    /// Metrics emitted: `log_likelihood`, `length`,
    /// `vowel_ratio`, `digit_ratio`, `max_consonant_run`,
    /// `char_entropy`.
    ///
    /// Gated on the `tracker` feature — `OwnedAnomaly` lives
    /// there.
    pub fn into_anomaly(
        self,
        ts: crate::Timestamp,
        flow_key: Option<&dyn crate::KeyFields>,
    ) -> crate::OwnedAnomaly {
        let mut a = crate::OwnedAnomaly::new("DgaScorer", crate::event::Severity::Info, ts);
        if let Some(key) = flow_key {
            a = a.with_key(key);
        }
        a.with_metric("log_likelihood", self.log_likelihood as f64)
            .with_metric("length", self.length as f64)
            .with_metric("vowel_ratio", self.vowel_ratio as f64)
            .with_metric("digit_ratio", self.digit_ratio as f64)
            .with_metric("max_consonant_run", self.max_consonant_run as f64)
            .with_metric("char_entropy", self.char_entropy as f64)
    }
}

#[cfg(feature = "tracker")]
impl crate::DetectorScore for DgaScore {
    fn name(&self) -> &'static str {
        "DgaScorer"
    }

    fn into_anomaly(self, ts: crate::Timestamp) -> crate::OwnedAnomaly {
        self.into_anomaly(ts, None)
    }
}

impl Default for DgaScorer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Internal classification helpers ──────────────────────────

/// Map a char into our 37-class alphabet, or `None` for chars
/// we don't model (uppercase / punctuation / non-ASCII).
fn class(c: char) -> Option<usize> {
    match c {
        'a'..='z' => Some((c as usize) - ('a' as usize)),
        '0'..='9' => Some(26 + ((c as usize) - ('0' as usize))),
        '-' => Some(36),
        _ => None,
    }
}

fn is_vowel(c: usize) -> bool {
    // a, e, i, o, u
    matches!(c, 0 | 4 | 8 | 14 | 20)
}

fn char_entropy(classified: &[usize]) -> f32 {
    if classified.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; ALPHA_LEN];
    for &c in classified {
        counts[c] += 1;
    }
    let n = classified.len() as f32;
    let mut h = 0.0f32;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / n;
        h -= p * p.log2();
    }
    h
}

/// Compile the embedded baseline corpus into a Laplace-smoothed
/// bigram log-likelihood table.
///
/// Pseudo-count of 1 prevents −∞ for unseen bigrams; the natural
/// log of the smoothed probability is stored.
fn compile_baseline_table() -> [[f32; ALPHA_LEN]; ALPHA_LEN] {
    let mut counts = [[1u32; ALPHA_LEN]; ALPHA_LEN]; // Laplace +1
    for word in BASELINE_CORPUS.split_ascii_whitespace() {
        let classified: Vec<usize> = word.chars().filter_map(class).collect();
        for w in classified.windows(2) {
            counts[w[0]][w[1]] += 1;
        }
    }
    let mut table = [[0f32; ALPHA_LEN]; ALPHA_LEN];
    for (i, row) in counts.iter().enumerate() {
        let row_sum: u32 = row.iter().sum();
        for (j, &c) in row.iter().enumerate() {
            table[i][j] = (c as f32 / row_sum as f32).ln();
        }
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_domain_scores_higher_than_random() {
        let s = DgaScorer::new();
        let english = s.score("google").log_likelihood;
        let dga = s
            .score("xkjqzwvbpnmrtfg") // random consonant soup
            .log_likelihood;
        assert!(
            english > dga,
            "English domain should outscore DGA-like: english={english}, dga={dga}"
        );
    }

    #[test]
    fn baseline_corpus_domains_pass_threshold() {
        let s = DgaScorer::new();
        for domain in ["google", "facebook", "amazon", "youtube", "github"] {
            let score = s.score(domain);
            assert!(
                score.log_likelihood > -3.5,
                "{domain} should pass threshold, got {score:?}"
            );
        }
    }

    #[test]
    fn dga_like_strings_below_threshold() {
        let s = DgaScorer::new();
        for dga in ["xkjqzwvbpnmrtfg", "qzxwvbnmplkjhgf", "zxqwfvbgnmpkjh"] {
            assert!(
                s.is_dga(dga),
                "{dga} should classify as DGA, score={:?}",
                s.score(dga)
            );
        }
    }

    #[test]
    fn short_input_returns_zero_score() {
        let s = DgaScorer::new();
        let one = s.score("a");
        assert_eq!(one.length, 1);
        assert_eq!(one.log_likelihood, 0.0);
        let empty = s.score("");
        assert_eq!(empty.length, 0);
    }

    #[test]
    fn auxiliary_features_populated() {
        let s = DgaScorer::new();
        let sc = s.score("github");
        assert_eq!(sc.length, 6);
        assert!(sc.vowel_ratio > 0.0);
        assert_eq!(sc.digit_ratio, 0.0);
        assert!(sc.max_consonant_run >= 2);
        assert!(sc.char_entropy > 0.0);
    }

    #[test]
    fn digit_heavy_string_has_high_digit_ratio() {
        let s = DgaScorer::new();
        let sc = s.score("a1b2c3d4e5");
        assert!(sc.digit_ratio > 0.4);
    }

    #[test]
    fn custom_threshold_can_relax_or_tighten() {
        let s = DgaScorer::new();
        // "google" → log_likelihood is reasonably high; against
        // a very strict threshold it can still flag.
        assert!(!s.is_dga("google"));
        assert!(s.is_dga_with_threshold("google", 0.0));
    }

    #[test]
    fn non_ascii_characters_are_ignored() {
        let s = DgaScorer::new();
        let sc = s.score("gø∞gle");
        // Only g, g, l, e classify; ø / ∞ skip.
        assert!(sc.length >= 3);
    }
}
