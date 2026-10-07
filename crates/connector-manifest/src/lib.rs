//! Connector manifest format v0 (spec/connector-manifest-v0.md).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust { Trusted, Untrusted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub resource_template: String,
    /// Whether this tool has side effects (decided, fail-closed) or is read-only.
    pub consequential: bool,
    /// Trust label for the tool's *output*; untrusted outputs are fingerprinted for taint (M5).
    #[serde(default = "untrusted")]
    pub output_trust: Trust,
    /// Argument names that are sinks (e.g. recipients, URLs) and must be checked for taint.
    #[serde(default)]
    pub sink_args: Vec<String>,
}
fn untrusted() -> Trust { Trust::Untrusted }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub spec: String,
    pub connector: String,
    pub version: String,
    pub tools: Vec<ToolDef>,
}

impl Manifest {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> { serde_json::from_str(s) }
    pub fn tool(&self, name: &str) -> Option<&ToolDef> { self.tools.iter().find(|t| t.name == name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn example_parses_and_defaults_untrusted() {
        let m = Manifest::from_json(include_str!("../../../spec/examples/connector-github.json")).unwrap();
        let t = m.tool("github.get_issue").unwrap();
        assert_eq!(t.output_trust, Trust::Untrusted);
        assert!(m.tool("github.merge_pull_request").unwrap().consequential);
    }
}
