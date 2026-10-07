//! Typed request/response for the Tier 2 scorer (contract §2/§4 + amendment A1).
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Side-effect class from the signed connector catalogue (never from the agent or MCP server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffect {
    Read,
    Write,
    ExternalSend,
    Destructive,
    Privilege,
}

impl SideEffect {
    /// Parse a catalogue label. Unknown or missing => destructive (fail closed, contract §2).
    pub fn parse(s: Option<&str>) -> Self {
        match s
            .map(|x| x.trim().to_ascii_lowercase().replace('-', "_"))
            .as_deref()
        {
            Some("read") | Some("read_only") => Self::Read,
            Some("write") => Self::Write,
            Some("external_send") => Self::ExternalSend,
            Some("privilege") | Some("privilege_change") => Self::Privilege,
            _ => Self::Destructive,
        }
    }
    /// Classes where a Tier 2 failure (timeout, unavailable, malformed) escalates (contract §6).
    pub fn tier2_required(self) -> bool {
        matches!(
            self,
            Self::Destructive | Self::Privilege | Self::ExternalSend
        )
    }
    /// Wire label understood by the scorer.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ExternalSend => "external_send",
            Self::Destructive => "destructive",
            Self::Privilege => "privilege",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreRequest {
    pub op: &'static str, // "score"
    pub id: u64,
    pub session: String,
    pub purpose: String,
    pub tool: String,
    pub side_effect: &'static str,
    pub resource: String,
    pub args: Value,
}

/// Scorer response. `windows_read` / `windows_total` stay raw JSON so a missing or non-integer
/// value is detectable (A1 §2: either missing => unread).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoreResponse {
    #[serde(default)]
    pub id: u64,
    /// false = the scorer did not score this call (not a text sink / nothing untrusted seen yet).
    #[serde(default)]
    pub scored: bool,
    #[serde(default)]
    pub score: Option<f64>,
    #[serde(default)]
    pub band: Option<String>,
    #[serde(default)]
    pub escalate: bool,
    #[serde(default)]
    pub reason_codes: Vec<String>,
    #[serde(default)]
    pub coverage: Option<String>,
    #[serde(default)]
    pub windows_read: Option<Value>,
    #[serde(default)]
    pub windows_total: Option<Value>,
    /// Window filter only: windows the filter skipped (each one counts as unread).
    #[serde(default)]
    pub windows_skipped: Option<Value>,
    #[serde(default)]
    pub model_version: Option<String>,
    #[serde(default)]
    pub model_digest: Option<String>,
    #[serde(default)]
    pub latency_us: Option<u64>,
}

impl ScoreResponse {
    pub fn windows(&self) -> (Option<i64>, Option<i64>) {
        let i = |v: &Option<Value>| {
            v.as_ref()
                .and_then(|x| x.as_i64().filter(|_| x.is_i64() || x.is_u64()))
        };
        (i(&self.windows_read), i(&self.windows_total))
    }
    /// `windows_skipped` as an integer; missing or non-integer => None.
    pub fn skipped(&self) -> Option<i64> {
        self.windows_skipped
            .as_ref()
            .and_then(|x| x.as_i64().filter(|_| x.is_i64() || x.is_u64()))
    }
}
