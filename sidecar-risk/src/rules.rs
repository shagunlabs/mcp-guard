//! Edge-side Tier 2 rules (contract §6 + amendment A1). Pure, so every rule is unit-tested.
use crate::types::{ScoreResponse, SideEffect};
use crate::{combine, Outcome};

pub const T2_UNTRUSTED_CONTENT_CARRIED: &str = "T2_UNTRUSTED_CONTENT_CARRIED";
pub const T2_FRAGMENTED_EXFIL: &str = "T2_FRAGMENTED_EXFIL";
pub const T2_UNSCORABLE_PLACEHOLDER: &str = "T2_UNSCORABLE_PLACEHOLDER";
pub const T2_TIMEOUT: &str = "T2_TIMEOUT";
pub const T2_PARTIAL_READ: &str = "T2_PARTIAL_READ";
pub const T2_NEAR_THRESHOLD: &str = "T2_NEAR_THRESHOLD";
pub const T2_UNAVAILABLE: &str = "T2_UNAVAILABLE";
pub const T2_SEND_AFTER_UNTRUSTED: &str = "T2_SEND_AFTER_UNTRUSTED";
pub const T2_PURPOSE_MISMATCH: &str = "T2_PURPOSE_MISMATCH";

/// Fixed vocabulary that may appear in evidence / approver view. Anything else from the scorer is
/// dropped (no free text crosses). `T2_UNSCORABLE_PLACEHOLDER` is internal: never exported.
const EXPORTABLE: &[&str] = &[
    T2_UNTRUSTED_CONTENT_CARRIED,
    T2_FRAGMENTED_EXFIL,
    T2_TIMEOUT,
    T2_PARTIAL_READ,
    T2_NEAR_THRESHOLD,
    T2_UNAVAILABLE,
    T2_SEND_AFTER_UNTRUSTED,
    T2_PURPOSE_MISMATCH,
];
const INTERNAL: &[&str] = &[T2_UNSCORABLE_PLACEHOLDER];

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub threshold: f64,
    pub near_margin: f64,
    pub deadline_ms: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 0.50,
            near_margin: 0.03,
            deadline_ms: 10,
        }
    }
}

/// What the transport produced for one call.
#[derive(Debug, Clone)]
pub enum T2Result {
    Scored(Box<ScoreResponse>),
    /// Deadline missed, or the untrusted-output cache was not ready (treated as a timeout).
    Timeout {
        cache_not_ready: bool,
    },
    Unavailable,
}

/// Why Tier 2 escalated (for accounting: score-based catches vs failure/coverage escalations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    None,
    Score,
    NearThreshold,
    PartialRead,
    Timeout,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct Applied {
    pub outcome: Outcome,
    /// Tier 2's own effect (escalate-only), independent of Tier 1.
    pub tier2_escalate: bool,
    pub via: Vec<Via>,
    pub codes: Vec<String>,
    pub internal_codes: Vec<String>,
    pub score: Option<f64>,
    pub band: Option<String>,
    pub windows: (Option<i64>, Option<i64>),
}

impl Applied {
    /// The only Tier 2 data that leaves the scorer boundary: score, band, approver-visible codes.
    pub fn export(&self) -> serde_json::Value {
        serde_json::json!({"score": self.score, "band": self.band, "reason_codes": self.codes})
    }
}

fn push(v: &mut Vec<String>, c: &str) {
    if !v.iter().any(|x| x == c) {
        v.push(c.to_string());
    }
}

pub fn apply(tier1: Outcome, class: SideEffect, r: &T2Result, cfg: &Config) -> Applied {
    let mut codes = vec![];
    let mut internal = vec![];
    let mut via = vec![];
    let mut esc = false;
    let (mut score, mut band, mut windows) = (None, None, (None, None));
    let fail = |via_: Via, codes: &mut Vec<String>, via: &mut Vec<Via>| {
        push(
            codes,
            if via_ == Via::Timeout {
                T2_TIMEOUT
            } else {
                T2_UNAVAILABLE
            },
        );
        if class.tier2_required() {
            via.push(via_);
            true
        } else {
            false // read / write: none + log
        }
    };
    match r {
        T2Result::Timeout { .. } => esc |= fail(Via::Timeout, &mut codes, &mut via),
        T2Result::Unavailable => esc |= fail(Via::Unavailable, &mut codes, &mut via),
        T2Result::Scored(s) if !s.scored => {}
        T2Result::Scored(s) => {
            match s.score.filter(|x| x.is_finite() && (0.0..=1.0).contains(x)) {
                None => esc |= fail(Via::Unavailable, &mut codes, &mut via), // malformed / NaN
                Some(x) => {
                    score = Some(x);
                    band = s.band.clone();
                    for c in &s.reason_codes {
                        if EXPORTABLE.contains(&c.as_str()) {
                            push(&mut codes, c);
                        } else if INTERNAL.contains(&c.as_str()) {
                            push(&mut internal, c);
                        }
                    }
                    let fragment = s.reason_codes.iter().any(|c| c == T2_FRAGMENTED_EXFIL);
                    if x >= cfg.threshold || fragment {
                        esc = true;
                        via.push(Via::Score);
                    }
                    if (x - cfg.threshold).abs() <= cfg.near_margin + 1e-9 {
                        esc = true;
                        push(&mut codes, T2_NEAR_THRESHOLD);
                        via.push(Via::NearThreshold);
                    }
                    windows = s.windows();
                    // Mandatory partial-read rule for outbound sends (Edge-side, A1 §2).
                    if class == SideEffect::ExternalSend {
                        let partial = match windows {
                            (Some(r), Some(t)) => r < t,
                            _ => true, // missing or non-integer => unread
                        };
                        if partial {
                            esc = true;
                            push(&mut codes, T2_PARTIAL_READ);
                            via.push(Via::PartialRead);
                        }
                    }
                }
            }
        }
    }
    // Final join goes through combine(): escalate-only by construction.
    let lifted = if esc { 1.0 } else { 0.0 };
    let outcome = combine(tier1, lifted, cfg.threshold as f32);
    debug_assert!(outcome >= tier1);
    Applied {
        outcome,
        tier2_escalate: esc,
        via,
        codes,
        internal_codes: internal,
        score,
        band,
        windows,
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use serde_json::json;
    const C: Config = Config {
        threshold: 0.50,
        near_margin: 0.03,
        deadline_ms: 10,
    };
    fn resp(
        score: f64,
        codes: &[&str],
        read: serde_json::Value,
        total: serde_json::Value,
    ) -> T2Result {
        T2Result::Scored(Box::new(ScoreResponse {
            scored: true,
            score: Some(score),
            band: Some(if score >= 0.50 { "high" } else { "low" }.into()),
            reason_codes: codes.iter().map(|s| s.to_string()).collect(),
            windows_read: if read.is_null() { None } else { Some(read) },
            windows_total: if total.is_null() { None } else { Some(total) },
            ..Default::default()
        }))
    }
    use Outcome::*;
    use SideEffect::*;

    #[test]
    fn threshold_default() {
        assert_eq!(Config::default().threshold, 0.50);
        assert_eq!(Config::default().deadline_ms, 10);
        assert_eq!(
            apply(Allow, Write, &resp(0.60, &[], json!(1), json!(1)), &C).outcome,
            Escalate
        );
        assert_eq!(
            apply(Allow, Write, &resp(0.30, &[], json!(1), json!(1)), &C).outcome,
            Allow
        );
    }
    #[test]
    fn near_threshold_band() {
        for s in [0.44, 0.45, 0.4999, 0.50] {
            let a = apply(Allow, Write, &resp(s, &[], json!(1), json!(1)), &C);
            assert_eq!(a.outcome, Escalate, "{s}");
            assert!(a.codes.contains(&T2_NEAR_THRESHOLD.to_string()), "{s}");
        }
        let a = apply(Allow, Write, &resp(0.4399, &[], json!(1), json!(1)), &C);
        assert_eq!(a.outcome, Allow);
        let a = apply(Allow, Write, &resp(0.51, &[], json!(1), json!(1)), &C);
        assert!(!a.codes.contains(&T2_NEAR_THRESHOLD.to_string()));
    }
    #[test]
    fn partial_read_mandatory_for_outbound_send() {
        for (r, t) in [
            (json!(4), json!(7)),
            (json!(null), json!(7)),
            (json!(4), json!(null)),
            (json!("4"), json!(7)),
            (json!(1.5), json!(2)),
        ] {
            let a = apply(
                Allow,
                ExternalSend,
                &resp(0.10, &[], r.clone(), t.clone()),
                &C,
            );
            assert_eq!(a.outcome, Escalate, "{r} {t}");
            assert!(a.codes.contains(&T2_PARTIAL_READ.to_string()));
            assert_eq!(a.via, vec![Via::PartialRead]);
        }
        assert_eq!(
            apply(
                Allow,
                ExternalSend,
                &resp(0.10, &[], json!(3), json!(3)),
                &C
            )
            .outcome,
            Allow
        );
        // only for outbound sends
        assert_eq!(
            apply(Allow, Write, &resp(0.10, &[], json!(4), json!(7)), &C).outcome,
            Allow
        );
    }
    #[test]
    fn timeout_escalates_only_required_classes() {
        let to = T2Result::Timeout {
            cache_not_ready: false,
        };
        for c in [Destructive, Privilege, ExternalSend] {
            let a = apply(Allow, c, &to, &C);
            assert_eq!(a.outcome, Escalate);
            assert_eq!(a.codes, vec![T2_TIMEOUT.to_string()]);
        }
        for c in [Read, Write] {
            let a = apply(Allow, c, &to, &C);
            assert_eq!(a.outcome, Allow);
            assert_eq!(a.codes, vec![T2_TIMEOUT.to_string()]); // none + log
        }
        let nr = T2Result::Timeout {
            cache_not_ready: true,
        };
        assert_eq!(apply(Allow, ExternalSend, &nr, &C).outcome, Escalate);
    }
    #[test]
    fn malformed_or_nan_is_unavailable() {
        for s in [f64::NAN, 1.5, -0.1] {
            let a = apply(Allow, ExternalSend, &resp(s, &[], json!(1), json!(1)), &C);
            assert_eq!(a.outcome, Escalate);
            assert_eq!(a.codes, vec![T2_UNAVAILABLE.to_string()]);
        }
        assert_eq!(
            apply(Allow, Write, &T2Result::Unavailable, &C).outcome,
            Allow
        );
    }
    #[test]
    fn escalate_only_never_lowers_or_allows() {
        let cases = [
            resp(0.0, &[], json!(1), json!(1)),
            resp(1.0, &[T2_FRAGMENTED_EXFIL], json!(1), json!(1)),
            T2Result::Timeout {
                cache_not_ready: false,
            },
            T2Result::Unavailable,
        ];
        for r in &cases {
            for c in [Read, Write, ExternalSend, Destructive, Privilege] {
                assert_eq!(apply(Deny, c, r, &C).outcome, Deny);
                assert_eq!(apply(Escalate, c, r, &C).outcome, Escalate);
                assert!(apply(Allow, c, r, &C).outcome >= Allow);
            }
        }
    }
    #[test]
    fn fragment_rule_and_carry_code_exported() {
        let a = apply(
            Allow,
            ExternalSend,
            &resp(
                1.0,
                &[T2_FRAGMENTED_EXFIL, T2_SEND_AFTER_UNTRUSTED],
                json!(1),
                json!(1),
            ),
            &C,
        );
        assert_eq!(a.outcome, Escalate);
        assert!(a.codes.contains(&T2_FRAGMENTED_EXFIL.to_string()));
        let a = apply(
            Allow,
            ExternalSend,
            &resp(0.8, &[T2_UNTRUSTED_CONTENT_CARRIED], json!(1), json!(1)),
            &C,
        );
        assert_eq!(a.via, vec![Via::Score]);
        assert!(a.codes.contains(&T2_UNTRUSTED_CONTENT_CARRIED.to_string()));
    }
    #[test]
    fn placeholder_is_internal_and_unknown_codes_dropped() {
        let a = apply(
            Allow,
            ExternalSend,
            &resp(
                0.0,
                &[T2_UNSCORABLE_PLACEHOLDER, "free text: secret"],
                json!(1),
                json!(1),
            ),
            &C,
        );
        assert_eq!(a.outcome, Allow);
        assert!(a.codes.is_empty());
        assert_eq!(
            a.internal_codes,
            vec![T2_UNSCORABLE_PLACEHOLDER.to_string()]
        );
        let e = a.export();
        assert_eq!(e.as_object().unwrap().len(), 3);
        assert!(!e.to_string().contains("PLACEHOLDER") && !e.to_string().contains("secret"));
    }
    #[test]
    fn unscored_has_no_effect() {
        let r = T2Result::Scored(Box::new(ScoreResponse {
            scored: false,
            ..Default::default()
        }));
        assert_eq!(apply(Allow, ExternalSend, &r, &C).outcome, Allow);
    }
}
