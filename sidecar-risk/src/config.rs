//! Versioned scorer config: scorer version + weights reference + threshold travel together, pinned
//! (`scorer-config.v0.json`). A new config (e.g. V1) is swapped in by file, no code change. The
//! `config_version` is recorded in every decision record and bench result.
use serde::{Deserialize, Serialize};

/// Default (compiled-in) config: the research `t2-v0-pooled`, pinned to the `handoff/probe_refs.json`.
pub const PINNED_V0: &str = include_str!("../scorer-config.t2-v0-pooled.json");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScorerConfig {
    /// Must equal the scorer's own id for `scorer_config` (the research CONFIGS), e.g. `t2-v0-pooled`.
    pub config_version: String,
    /// Key into scorer.py CONFIGS (`v0` | `v1`).
    pub scorer_config: String,
    pub scorer_version: String,
    /// Must also be on the model allowlist.
    pub model_sha256: String,
    /// Relative to the scorer directory; None = weights pinned inside scorer.py CONFIGS (V1).
    #[serde(default)]
    pub weights_file: Option<String>,
    #[serde(default)]
    pub weights_sha256: Option<String>,
    pub threshold: f64,
    pub near_margin: f64,
    /// Startup self-check: fixed probes with pinned reference scores (the research file; relative to the
    /// scorer dir). Missing file or any score outside `probe_tolerance` => refuse to start.
    pub probe_reference_file: String,
    /// Pin of the reference file once delivered (None = placeholder: not yet pinned).
    #[serde(default)]
    pub probe_reference_sha256: Option<String>,
    pub probe_tolerance: f64,
}

impl ScorerConfig {
    pub fn parse(s: &str) -> Result<Self, String> {
        let c: Self = serde_json::from_str(s).map_err(|e| e.to_string())?;
        if !(0.0..=1.0).contains(&c.threshold) || !(0.0..0.5).contains(&c.near_margin) {
            return Err(format!("bad threshold/margin in {}", c.config_version));
        }
        if c.weights_file.is_some() != c.weights_sha256.is_some() {
            return Err("weights_file and weights_sha256 go together".into());
        }
        for h in std::iter::once(&c.model_sha256).chain(c.weights_sha256.iter()) {
            if h.len() != 64 || !h.chars().all(|x| x.is_ascii_hexdigit()) {
                return Err(format!("bad sha256 {h}"));
            }
        }
        Ok(c)
    }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn pinned_v0() {
        let c = ScorerConfig::parse(PINNED_V0).unwrap();
        assert_eq!(c.config_version, "t2-v0-pooled");
        assert_eq!(c.scorer_config, "v0");
        assert_eq!(c.threshold, 0.50);
        assert_eq!(c.near_margin, 0.03);
        assert_eq!(c.probe_tolerance, 0.005);
        assert_eq!(c.probe_reference_file, "handoff/probe_refs.json");
        assert!(c.probe_reference_sha256.is_some());
        assert_eq!(
            c.model_sha256,
            crate::allowlist::parse(crate::allowlist::PINNED).unwrap()[0]
        );
    }
    #[test]
    fn v1_file() {
        let c = ScorerConfig::parse(include_str!("../scorer-config.t2-v1-perwin.json")).unwrap();
        assert_eq!(c.config_version, "t2-v1-perwin");
        assert_eq!(c.threshold, 0.50);
        assert!(c.weights_file.is_none());
    }
    #[test]
    fn rejects_bad() {
        let mut v: serde_json::Value = serde_json::from_str(PINNED_V0).unwrap();
        v["threshold"] = serde_json::json!(1.5);
        assert!(ScorerConfig::parse(&v.to_string()).is_err());
    }
}
