//! Tier 2 risk sidecar: types, Edge-side rules, model allowlist and local transport.
//!
//! Invariants:
//! - **Escalate-only.** Tier 2 can raise `Allow` to `Escalate`; it never lowers anything and never
//!   produces `Allow` or `Deny` (`combine`, and `rules::apply` which ends in `combine`).
//! - **Data plane only.** The scorer process runs next to the Edge (unix socket, never TCP off-box).
//!   Only `score`, `band` and approver-visible reason codes leave in evidence (`Applied::export`).
//! - **One scoring session per sidecar** (no parallel INT8 ORT sessions: HANDOFF §6).
pub mod allowlist;
pub mod client;
pub mod config;
pub mod rules;
pub mod types;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Allow,
    Escalate,
    Deny,
}

/// Combine Tier 1 with a Tier 2 score. Tier 2 can raise Allow to Escalate; it can never lower anything.
pub fn combine(tier1: Outcome, score: f32, escalate_threshold: f32) -> Outcome {
    if tier1 == Outcome::Allow && (score >= escalate_threshold || score.is_nan()) {
        Outcome::Escalate
    } else {
        tier1
    }
}

/// Tier 2 model identity. The scorer is a MiniLM bi-encoder (contract amendment A1 §5); the
/// injection classifiers below are the contract §5 candidates for output scoring, not used yet.
pub mod models {
    /// Tier 2 carry-over scorer (Apache-2.0), INT8 ONNX export; digest pinned in the allowlist.
    pub const SCORER_MODEL: &str = "sentence-transformers/all-MiniLM-L6-v2";
    pub const SCORER_MODEL_REVISION: &str = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41";
    pub const SCORER_VERSION: &str = "t2-scorer-0.1.0";
    /// Output-injection signal, default candidate (Apache-2.0). Not wired.
    pub const DEFAULT_INJECTION_MODEL: &str = "protectai/deberta-v3-base-prompt-injection-v2";
    /// Opt-in only (Llama 4 Community License): Meta Prompt Guard 2 (22M per contract §5). Not wired.
    pub const OPT_IN_INJECTION_MODEL: &str = "meta-llama/Llama-Prompt-Guard-2-22M";
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: f32 = 0.50;
    #[test]
    fn ml_never_allows() {
        for s in [0.0, 0.46, 0.50, 0.5, 1.0, f32::NAN] {
            assert_ne!(combine(Outcome::Deny, s, T), Outcome::Allow);
            assert_eq!(combine(Outcome::Deny, s, T), Outcome::Deny);
            assert_eq!(combine(Outcome::Escalate, s, T), Outcome::Escalate);
        }
        assert_eq!(combine(Outcome::Allow, 0.50, T), Outcome::Escalate);
        assert_eq!(combine(Outcome::Allow, 0.46, T), Outcome::Allow);
        assert_eq!(combine(Outcome::Allow, f32::NAN, T), Outcome::Escalate);
    }
}
