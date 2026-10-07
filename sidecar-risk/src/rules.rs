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
/// Outbound send with untrusted output in its session but no scorable text field.
pub const T2_UNSCORABLE: &str = "T2_UNSCORABLE";

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
    T2_UNSCORABLE,
];
const INTERNAL: &[&str] = &[T2_UNSCORABLE_PLACEHOLDER];

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub threshold: f64,
    pub near_margin: f64,
    pub deadline_ms: u64,
    /// Periodic probe re-check interval through the same scorer queue (0 = off).
    pub recheck_secs: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            threshold: 0.50,
            near_margin: 0.03,
            deadline_ms: 10,
            recheck_secs: 60,
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
    Unscorable,
}

/// Per-call session facts the Edge knows independently of the scorer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ctx {
    /// The call's (mandate, session) has seen untrusted tool output.
    pub untrusted_in_session: bool,
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

fn fl(code: &str, v: Via, on: bool, codes: &mut Vec<String>, via: &mut Vec<Via>) -> bool {
    push(codes, code);
    if on && !via.contains(&v) {
        via.push(v);
    }
    on
}

/// Tier 2 rules. Every applicable reason is recorded (not just the first).
/// Failure / coverage rules (timeout, unavailable, partial read, unscorable) only act when the
/// call's session has seen untrusted output: with none, Tier 2 has nothing to judge, and Tier 1
/// (incl. taint) must behave exactly as with Tier 2 absent.
pub fn apply(tier1: Outcome, class: SideEffect, r: &T2Result, cfg: &Config, ctx: Ctx) -> Applied {
    let mut codes = vec![];
    let mut internal = vec![];
    let mut via: Vec<Via> = vec![];
    let mut esc = false;
    let (mut score, mut band, mut windows) = (None, None, (None, None));
    let u = ctx.untrusted_in_session;
    let required = class.tier2_required() && u;
    let send = class == SideEffect::ExternalSend && u;
    match r {
        T2Result::Timeout { .. } | T2Result::Unavailable => {
            let (c, v) = if matches!(r, T2Result::Timeout { .. }) {
                (T2_TIMEOUT, Via::Timeout)
            } else {
                (T2_UNAVAILABLE, Via::Unavailable)
            };
            esc |= fl(c, v, required, &mut codes, &mut via); // read / write: none + log
            // No reply in time => windows_read / windows_total missing => mandatory partial read.
            if send {
                esc |= fl(T2_PARTIAL_READ, Via::PartialRead, true, &mut codes, &mut via);
            }
        }
        T2Result::Scored(s) if !s.scored => {
            if send {
                esc |= fl(T2_UNSCORABLE, Via::Unscorable, true, &mut codes, &mut via);
            }
        }
        T2Result::Scored(s) => match s.score.filter(|x| x.is_finite() && (0.0..=1.0).contains(x)) {
            None => {
                esc |= fl(T2_UNAVAILABLE, Via::Unavailable, required, &mut codes, &mut via);
                if send {
                    esc |= fl(T2_PARTIAL_READ, Via::PartialRead, true, &mut codes, &mut via);
                }
            }
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
                    esc |= fl(T2_NEAR_THRESHOLD, Via::NearThreshold, true, &mut codes, &mut via);
                }
                windows = s.windows();
                // Mandatory partial-read rule for outbound sends (Edge-side, A1 §2).
                if class == SideEffect::ExternalSend {
                    let partial = match windows {
                        (Some(r), Some(t)) => r < t,
                        _ => true, // missing or non-integer => unread
                    };
                    if partial {
                        esc |= fl(T2_PARTIAL_READ, Via::PartialRead, true, &mut codes, &mut via);
                    }
                }
            }
        },
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
        recheck_secs: 60,
    };
    const U: Ctx = Ctx {
        untrusted_in_session: true,
    };
    const NOU: Ctx = Ctx {
        untrusted_in_session: false,
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
            apply(Allow, Write, &resp(0.60, &[], json!(1), json!(1)), &C, U).outcome,
            Escalate
        );
        assert_eq!(
            apply(Allow, Write, &resp(0.30, &[], json!(1), json!(1)), &C, U).outcome,
            Allow
        );
    }
    #[test]
    fn near_threshold_band() {
        for s in [0.44, 0.45, 0.4999, 0.50] {
            let a = apply(Allow, Write, &resp(s, &[], json!(1), json!(1)), &C, U);
            assert_eq!(a.outcome, Escalate, "{s}");
            assert!(a.codes.contains(&T2_NEAR_THRESHOLD.to_string()), "{s}");
        }
        let a = apply(Allow, Write, &resp(0.4399, &[], json!(1), json!(1)), &C, U);
        assert_eq!(a.outcome, Allow);
        let a = apply(Allow, Write, &resp(0.51, &[], json!(1), json!(1)), &C, U);
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
                U,
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
                &C,
                U
            )
            .outcome,
            Allow
        );
        // only for outbound sends
        assert_eq!(
            apply(Allow, Write, &resp(0.10, &[], json!(4), json!(7)), &C, U).outcome,
            Allow
        );
    }
    #[test]
    fn timeout_escalates_only_required_classes() {
        let to = T2Result::Timeout {
            cache_not_ready: false,
        };
        for c in [Destructive, Privilege, ExternalSend] {
            let a = apply(Allow, c, &to, &C, U);
            assert_eq!(a.outcome, Escalate);
            if c == ExternalSend {
                assert_eq!(a.codes, vec![T2_TIMEOUT.to_string(), T2_PARTIAL_READ.to_string()]);
                assert_eq!(a.via, vec![Via::Timeout, Via::PartialRead]);
            } else {
                assert_eq!(a.codes, vec![T2_TIMEOUT.to_string()]);
            }
        }
        for c in [Read, Write] {
            let a = apply(Allow, c, &to, &C, U);
            assert_eq!(a.outcome, Allow);
            assert_eq!(a.codes, vec![T2_TIMEOUT.to_string()]); // none + log
        }
        let nr = T2Result::Timeout {
            cache_not_ready: true,
        };
        assert_eq!(apply(Allow, ExternalSend, &nr, &C, U).outcome, Escalate);
    }
    #[test]
    fn malformed_or_nan_is_unavailable() {
        for s in [f64::NAN, 1.5, -0.1] {
            let a = apply(Allow, ExternalSend, &resp(s, &[], json!(1), json!(1)), &C, U);
            assert_eq!(a.outcome, Escalate);
            assert_eq!(a.codes, vec![T2_UNAVAILABLE.to_string(), T2_PARTIAL_READ.to_string()]);
        }
        assert_eq!(
            apply(Allow, Write, &T2Result::Unavailable, &C, U).outcome,
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
                assert_eq!(apply(Deny, c, r, &C, U).outcome, Deny);
                assert_eq!(apply(Escalate, c, r, &C, U).outcome, Escalate);
                assert!(apply(Allow, c, r, &C, U).outcome >= Allow);
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
            U,
        );
        assert_eq!(a.outcome, Escalate);
        assert!(a.codes.contains(&T2_FRAGMENTED_EXFIL.to_string()));
        let a = apply(
            Allow,
            ExternalSend,
            &resp(0.8, &[T2_UNTRUSTED_CONTENT_CARRIED], json!(1), json!(1)),
            &C,
            U,
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
            U,
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
        assert_eq!(apply(Allow, ExternalSend, &r, &C, NOU).outcome, Allow);
    }
    #[test]
    fn all_applicable_reasons_recorded() {
        // near threshold + over threshold + partial read on one send
        let a = apply(Allow, ExternalSend, &resp(0.49, &[], json!(4), json!(7)), &C, U);
        assert_eq!(a.via, vec![Via::Score, Via::NearThreshold, Via::PartialRead]);
        assert!(a.codes.contains(&T2_NEAR_THRESHOLD.to_string()));
        assert!(a.codes.contains(&T2_PARTIAL_READ.to_string()));
        let a = apply(Allow, ExternalSend, &T2Result::Timeout { cache_not_ready: true }, &C, U);
        assert_eq!(a.via, vec![Via::Timeout, Via::PartialRead]);
    }
    #[test]
    fn unscorable_send_escalates_only_with_untrusted_in_session() {
        let r = T2Result::Scored(Box::new(ScoreResponse {
            scored: false,
            ..Default::default()
        }));
        let a = apply(Allow, ExternalSend, &r, &C, U);
        assert_eq!(a.outcome, Escalate);
        assert_eq!(a.codes, vec![T2_UNSCORABLE.to_string()]);
        assert_eq!(a.via, vec![Via::Unscorable]);
        let a = apply(Allow, ExternalSend, &r, &C, NOU);
        assert_eq!(a.outcome, Allow);
        assert!(a.codes.is_empty());
        assert_eq!(apply(Allow, Write, &r, &C, U).outcome, Allow);
    }
    #[test]
    fn failure_rules_inert_without_untrusted_in_session() {
        // Tier 2 down / slow must not change Tier 1 when there is nothing untrusted to judge.
        for r in [T2Result::Unavailable, T2Result::Timeout { cache_not_ready: false }] {
            for c in [Read, Write, ExternalSend, Destructive, Privilege] {
                let a = apply(Allow, c, &r, &C, NOU);
                assert_eq!(a.outcome, Allow, "{c:?}");
                assert!(!a.tier2_escalate);
            }
        }
    }
}
