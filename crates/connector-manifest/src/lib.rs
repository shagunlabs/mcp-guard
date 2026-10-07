//! Connector manifest format v0 (spec/connector-manifest-v0.md).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    Trusted,
    Untrusted,
}

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
    /// Argument mappings: argument name -> semantic kind. Mandate constraints are evaluated
    /// against arguments by kind (e.g. `recipient_domains` applies to every `email` argument).
    #[serde(default)]
    pub args: std::collections::BTreeMap<String, ArgKind>,
}

/// Semantic kind of a tool argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgKind {
    Email,
    Url,
    Host,
    Path,
    Branch,
    Amount,
    Cmd,
    Sql,
    User,
    Group,
    Region,
    Text,
    Other,
}

impl ArgKind {
    /// Fallback when a manifest has no explicit mapping: infer from conventional argument names.
    /// Manifests SHOULD declare `args` explicitly; inference is documented and conservative.
    pub fn infer(arg: &str) -> ArgKind {
        let a = arg.to_ascii_lowercase();
        let is = |xs: &[&str]| xs.contains(&a.as_str());
        if is(&[
            "to",
            "cc",
            "bcc",
            "email",
            "recipient",
            "recipients",
            "reply_to",
            "from",
        ]) {
            ArgKind::Email
        } else if is(&["url", "uri", "endpoint", "webhook", "link"]) {
            ArgKind::Url
        } else if is(&["host", "hostname", "domain"]) {
            ArgKind::Host
        } else if is(&["path", "file", "filename", "filepath", "dir", "directory"]) {
            ArgKind::Path
        } else if is(&["branch", "base", "head", "ref", "target_branch"]) {
            ArgKind::Branch
        } else if is(&["amount", "value", "price", "total", "sum"]) {
            ArgKind::Amount
        } else if is(&["cmd", "command", "script", "shell"]) {
            ArgKind::Cmd
        } else if is(&["sql", "query_sql", "statement"]) {
            ArgKind::Sql
        } else if is(&[
            "user",
            "username",
            "user_id",
            "member",
            "new_owner",
            "owner",
            "assignee",
        ]) {
            ArgKind::User
        } else if is(&["group", "team", "role", "permission", "policy"]) {
            ArgKind::Group
        } else if is(&["region", "regions", "zone", "cluster"]) {
            ArgKind::Region
        } else if is(&[
            "body",
            "text",
            "content",
            "message",
            "comment",
            "note",
            "summary",
            "description",
        ]) {
            ArgKind::Text
        } else {
            ArgKind::Other
        }
    }
    /// Kinds where copying attacker-controlled data is dangerous by default (exfil / control targets).
    pub fn is_default_sink(self) -> bool {
        matches!(
            self,
            ArgKind::Email
                | ArgKind::Url
                | ArgKind::Host
                | ArgKind::Path
                | ArgKind::Cmd
                | ArgKind::Sql
                | ArgKind::User
                | ArgKind::Branch
        )
    }
}

impl ToolDef {
    pub fn kind_of(&self, arg: &str) -> ArgKind {
        self.args
            .get(arg)
            .copied()
            .unwrap_or_else(|| ArgKind::infer(arg))
    }
}
fn untrusted() -> Trust {
    Trust::Untrusted
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub spec: String,
    pub connector: String,
    pub version: String,
    pub tools: Vec<ToolDef>,
}

impl Manifest {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
    pub fn tool(&self, name: &str) -> Option<&ToolDef> {
        self.tools.iter().find(|t| t.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn example_parses_and_defaults_untrusted() {
        let m = Manifest::from_json(include_str!("../../../spec/examples/connector-github.json"))
            .unwrap();
        let t = m.tool("github.get_issue").unwrap();
        assert_eq!(t.output_trust, Trust::Untrusted);
        assert!(m.tool("github.merge_pull_request").unwrap().consequential);
    }
}
