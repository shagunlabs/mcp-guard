//! Tier 2 risk sidecar interface. Invariant: the scorer can only escalate, never allow.
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ml_never_allows() {
        for s in [0.0, 0.5, 1.0, f32::NAN] {
            assert_ne!(combine(Outcome::Deny, s, 0.7), Outcome::Allow);
            assert_ne!(combine(Outcome::Escalate, s, 0.7), Outcome::Allow);
        }
        assert_eq!(combine(Outcome::Allow, 0.9, 0.7), Outcome::Escalate);
        assert_eq!(combine(Outcome::Allow, f32::NAN, 0.7), Outcome::Escalate);
    }
}

/// Tier 2 prompt-injection classifier choices (run on CPU inside the customer's data plane).
pub mod models {
    /// Default: ProtectAI DeBERTa-based prompt-injection classifier v2 (Apache-2.0).
    pub const DEFAULT_INJECTION_MODEL: &str = "protectai/deberta-v3-base-prompt-injection-v2";
    /// Opt-in only (Llama 4 Community License, not Apache-2.0): Meta Prompt Guard 2.
    pub const OPT_IN_INJECTION_MODEL: &str = "meta-llama/Llama-Prompt-Guard-2-86M";
}
