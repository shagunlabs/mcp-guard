//! Mandate v0 canonical JSON model (spec/mandate-v0.md). Biscuit compilation lands in M1.
use serde::{Deserialize, Serialize};
pub mod token;

pub const SPEC_ID: &str = "sentryra.mandate/v0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Escalate,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub tool: String,
    pub resource: String,
    pub effect: Effect,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constraints: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mandate {
    pub mandate_id: String,
    pub spec: String,
    pub tenant: String,
    pub principal: serde_json::Value,
    pub agent: serde_json::Value,
    pub purpose: String,
    pub scopes: Vec<Scope>,
    pub default_effect: Effect,
    pub not_before: String,
    pub expires_at: String,
    /// Trusted call context signed into the mandate (e.g. `{"ticket.requester": "a@x"}`), used to
    /// resolve `$name` bindings in scope constraints. Takes precedence over host-supplied context.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MandateError {
    WrongSpec,
    DefaultNotDeny,
    NoScopes,
    EscalateWithoutApprovers(usize),
    Parse(String),
}

impl Mandate {
    pub fn from_json(s: &str) -> Result<Self, MandateError> {
        let m: Mandate = serde_json::from_str(s).map_err(|e| MandateError::Parse(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }
    /// Structural invariants of v0 (signature checks are M1).
    pub fn validate(&self) -> Result<(), MandateError> {
        if self.spec != SPEC_ID {
            return Err(MandateError::WrongSpec);
        }
        if self.default_effect != Effect::Deny {
            return Err(MandateError::DefaultNotDeny);
        }
        if self.scopes.is_empty() {
            return Err(MandateError::NoScopes);
        }
        for (i, s) in self.scopes.iter().enumerate() {
            if s.effect == Effect::Escalate && s.approvers.is_empty() {
                return Err(MandateError::EscalateWithoutApprovers(i));
            }
        }
        Ok(())
    }
    /// Exact-match scope lookup; anything unmatched is the default (deny). Wildcards are M1+.
    pub fn effect_for(&self, tool: &str, resource: &str) -> Effect {
        let rank = |e: Effect| match e {
            Effect::Allow => 0,
            Effect::Escalate => 1,
            Effect::Deny => 2,
        };
        self.scopes
            .iter()
            .filter(|s| s.tool == tool && s.resource == resource)
            .map(|s| s.effect)
            .max_by_key(|e| rank(*e)) // strictest wins: deny > escalate > allow
            .unwrap_or(self.default_effect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EX: &str = include_str!("../../../spec/examples/mandate-v0.json");
    #[test]
    fn example_parses() {
        Mandate::from_json(EX).unwrap();
    }
    #[test]
    fn default_deny() {
        let m = Mandate::from_json(EX).unwrap();
        assert_eq!(
            m.effect_for("k8s.delete", "cluster:prod/ns:billing"),
            Effect::Deny
        );
        assert_eq!(
            m.effect_for("k8s.apply", "cluster:staging/ns:billing"),
            Effect::Allow
        );
        assert_eq!(
            m.effect_for("k8s.apply", "cluster:prod/ns:billing"),
            Effect::Escalate
        );
    }
    #[test]
    fn rejects_default_allow() {
        let bad = EX.replace(
            "\"default_effect\": \"deny\"",
            "\"default_effect\": \"allow\"",
        );
        assert_eq!(
            Mandate::from_json(&bad).unwrap_err(),
            MandateError::DefaultNotDeny
        );
    }
}
