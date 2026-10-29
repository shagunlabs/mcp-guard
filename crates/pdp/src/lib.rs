//! M2 Tier 1 decision core: Biscuit mandate + signed tool catalogue + Cedar + SQL parse + taint,
//! in shadow or enforce mode, with every decision written to the signed evidence chain.
use sentryra_sidecar_risk as t2;
/// Per-run state key (Tier 1 taint store and Tier 2 session): the VERIFIED mandate id (from the
/// Biscuit, never a token hash) plus the host-supplied `context.session_id` (or "-").
pub fn state_key(mandate_id: &str, context: Option<&bindings::Context>) -> String {
    let s = context
        .and_then(|c| c.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    format!("mdt:{mandate_id}/s:{s}")
}

#[derive(Debug, PartialEq, Eq)]
pub enum IngestError {
    /// Mandate did not verify (signature, expiry, revocation).
    Mandate,
    /// No allowed (or shadow) decision with this id for this mandate/session/tool, or already used.
    UnknownDecision,
}

pub mod bindings;
pub mod constraints;
mod consumed;
pub mod long_send;
pub mod receipts;
pub mod sql;
pub mod taint;

use cedar_policy::{
    Authorizer, Context, Decision as CDecision, Entities, EntityUid, PolicySet, Request,
};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sentryra_connector_manifest::{ArgKind, Manifest, ToolDef, Trust};
use sentryra_evidence::{Chain, Entry, NewEntry};
use sentryra_mandate::{token, Effect};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DecideRequest {
    /// Base64 Biscuit mandate (audience: this Edge).
    pub mandate: String,
    pub tool: String,
    #[serde(default)]
    pub args: serde_json::Value,
    /// Override "now" (RFC 3339 UTC) for replay/testing only.
    #[serde(default)]
    pub now: Option<String>,
    /// Signed approval receipt for a previously escalated identical action.
    #[serde(default)]
    pub receipt: Option<receipts::Receipt>,
    /// Trusted call context from the host (never from the agent or tool outputs), used to resolve
    /// `$name` bindings in mandate constraints. The signed mandate `context` wins on conflict.
    #[serde(default)]
    pub context: Option<bindings::Context>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecideResponse {
    pub decision_id: String,
    /// What Tier 1 decided.
    pub decision: String,
    /// Whether the decision is enforced (enforce mode) or only logged (shadow mode).
    pub enforced: bool,
    pub mode: Mode,
    pub resource: String,
    pub reasons: Vec<String>,
    pub policy_ids: Vec<String>,
    pub tainted: bool,
    /// Result obligations from the granting scopes, e.g. `row_cap=100` (enforced by the proxy).
    pub obligations: Vec<String>,
    /// For escalations: the only thing that leaves the Edge is the decision ID + this deep link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_link: Option<String>,
    pub evidence_seq: u64,
    pub entry_hash: String,
}

/// A held escalation. Raw arguments live only here, in the customer-side Edge.
#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub decision_id: String,
    pub tool: String,
    pub resource: String,
    pub args: serde_json::Value,
    pub reasons: Vec<String>,
    pub tainted_args: Vec<String>,
    pub action_hash: String,
    /// Mandate escalate scopes that triggered this hold, each with its signed `approvers` list.
    /// Empty when the hold came only from the default policy (e.g. `sql-dml-escalate`), from
    /// Tier 2, or from a token issued before approvers were signed in: any non-empty name is
    /// then accepted. The name is self-declared over the shared bearer token, so matching it
    /// against this list is a consistency check, not authentication.
    pub escalation_scopes: Vec<EscalationScope>,
    #[serde(skip)]
    mandate_id: String,
    #[serde(skip)]
    principal: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EscalationScope {
    pub tool: String,
    pub resource: String,
    pub approvers: Vec<String>,
}

/// Why `Engine::approve` did not issue a receipt.
#[derive(Debug, PartialEq, Eq)]
pub enum ApproveError {
    /// This Edge does not hold the approval key.
    NoApprovalKey,
    /// No pending approval with this id.
    NotFound,
    /// The supplied approver name is empty.
    EmptyName,
    /// The hold came from a mandate escalate scope and the supplied (self-declared) name is not
    /// one of that scope's listed approvers. Recorded in evidence; no receipt issued.
    NotListed,
    /// The pending approval was denied; it can no longer be approved.
    Denied,
}
impl std::fmt::Display for ApproveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct Config {
    pub root: biscuit_auth::PublicKey,
    pub catalogue_key: VerifyingKey,
    /// (manifest JSON bytes, hex ed25519 signature over the bytes)
    pub manifests: Vec<(Vec<u8>, String)>,
    pub policies: String,
    pub evidence_key: SigningKey,
    pub salt_key: Vec<u8>,
    pub mode: Mode,
    pub evidence_path: Option<std::path::PathBuf>,
    pub edge_url: String,
    pub revoked: HashSet<String>,
    /// Verifies approval receipts.
    pub approval_vk: VerifyingKey,
    /// Present only when this Edge also acts as the approval service (local/self-hosted).
    pub approval_sk: Option<SigningKey>,
}

struct State {
    chain: Chain,
    /// Taint stores keyed by `state_key` (verified mandate id + session).
    taint: HashMap<String, taint::Store>,
    /// Decisions whose tool may have run (allow, or any decision in shadow mode): decision_id ->
    /// (state key, tool). An output can be ingested once, only against one of these.
    ran: HashMap<String, (String, String)>,
    ran_order: std::collections::VecDeque<String>,
    pending: HashMap<String, PendingApproval>,
    file: Option<std::fs::File>,
    counter: u64,
    /// Used receipt ids -> receipt expiry (ms). Persisted (when there is an evidence path) to
    /// `<evidence>.consumed-receipts`, so a receipt stays single-use across restarts.
    consumed: HashMap<String, u64>,
    consumed_file: Option<std::fs::File>,
    /// Escalation decision ids denied via `deny`: never approvable again, and any receipt
    /// already issued for them is refused.
    denied: HashSet<String>,
}

pub struct Engine {
    root: biscuit_auth::PublicKey,
    tools: HashMap<String, ToolDef>,
    policies: PolicySet,
    authorizer: Authorizer,
    pub mode: Mode,
    edge_url: String,
    revoked: HashSet<String>,
    approval_vk: VerifyingKey,
    approval_sk: Option<SigningKey>,
    state: Mutex<State>,
    /// Optional Tier 2 sidecar (escalate-only). `diag` asks for per-window raw scores (bench).
    tier2: Option<(std::sync::Arc<t2::client::Client>, bool)>,
    t2_export: bool,
}

#[derive(Debug)]
pub struct EngineError(pub String);
impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn stricter(a: Effect, b: Effect) -> Effect {
    let r = |e: Effect| match e {
        Effect::Allow => 0,
        Effect::Escalate => 1,
        Effect::Deny => 2,
    };
    if r(a) >= r(b) {
        a
    } else {
        b
    }
}

fn now_rfc3339() -> (u64, String) {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    (ms, rfc3339(ms / 1000))
}

fn rfc3339(secs: u64) -> String {
    // civil-from-days (Howard Hinnant), UTC
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

impl Engine {
    pub fn new(c: Config) -> Result<Self, EngineError> {
        let mut tools = HashMap::new();
        for (bytes, sig) in &c.manifests {
            let sig = hex::decode(sig)
                .ok()
                .and_then(|b| Signature::from_slice(&b).ok());
            match sig {
                Some(s) if c.catalogue_key.verify(bytes, &s).is_ok() => {}
                _ => {
                    return Err(EngineError(
                        "tool catalogue manifest signature invalid".into(),
                    ))
                }
            }
            let m: Manifest =
                serde_json::from_slice(bytes).map_err(|e| EngineError(e.to_string()))?;
            for t in m.tools {
                tools.insert(t.name.clone(), t);
            }
        }
        let policies =
            PolicySet::from_str(&c.policies).map_err(|e| EngineError(format!("cedar: {e}")))?;
        let file = match &c.evidence_path {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(p)
                    .map_err(|e| EngineError(e.to_string()))?,
            ),
            None => None,
        };
        let (consumed, consumed_file) = match &c.evidence_path {
            Some(p) => consumed::open(&consumed::path_for(p), wall_ms())
                .map_err(|e| EngineError(format!("consumed receipts file: {e}")))?,
            None => (HashMap::new(), None),
        };
        Ok(Self {
            root: c.root,
            tools,
            policies,
            authorizer: Authorizer::new(),
            mode: c.mode,
            edge_url: c.edge_url,
            revoked: c.revoked,
            approval_vk: c.approval_vk,
            approval_sk: c.approval_sk,
            state: Mutex::new(State {
                chain: Chain::new(c.evidence_key, c.salt_key),
                taint: HashMap::new(),
                ran: HashMap::new(),
                ran_order: Default::default(),
                pending: HashMap::new(),
                file,
                counter: 0,
                consumed,
                consumed_file,
                denied: HashSet::new(),
            }),
            tier2: None,
            t2_export: false,
        })
    }

    /// Attach the Tier 2 sidecar. One sidecar (one scoring session) per Edge process.
    pub fn set_tier2(&mut self, c: std::sync::Arc<t2::client::Client>, diag: bool) {
        self.tier2 = Some((c, diag));
    }

    /// DEV ONLY: request the Tier 2 feature export for calls whose VERIFIED mandate context marks
    /// a bench/dev fixture (`sentryra_fixture: "bench" | "dev"`). No-op unless the build has the
    /// `dev-export` feature (see `Client::dev_export_compiled`).
    pub fn set_tier2_dev_export(&mut self, on: bool) {
        self.t2_export = on && t2::client::Client::dev_export_compiled();
    }

    pub fn tier2(&self) -> Option<&std::sync::Arc<t2::client::Client>> {
        self.tier2.as_ref().map(|t| &t.0)
    }

    pub fn evidence_public_key_hex(&self) -> String {
        hex::encode(self.state.lock().unwrap().chain.verifying_key().to_bytes())
    }

    pub fn entries(&self) -> Vec<Entry> {
        self.state.lock().unwrap().chain.entries.clone()
    }

    pub fn pending(&self, id: &str) -> Option<PendingApproval> {
        self.state.lock().unwrap().pending.get(id).cloned()
    }

    /// Output trust for a tool's result. Unknown tools are untrusted.
    pub fn output_untrusted(&self, tool: &str) -> bool {
        self.tools
            .get(tool)
            .map(|t| t.output_trust == Trust::Untrusted)
            .unwrap_or(true)
    }

    /// Verified mandate id of a token (signature, revocation, expiry), or None.
    pub fn verified_mandate_id(&self, mandate: &str) -> Option<String> {
        self.verified_mandate_id_at(mandate, None)
    }

    /// As `verified_mandate_id`, at an explicit time (replay / tests only).
    pub fn verified_mandate_id_at(&self, mandate: &str, now: Option<&str>) -> Option<String> {
        let now = now.map(String::from).unwrap_or_else(|| now_rfc3339().1);
        token::verify(mandate, self.root, &self.revoked, "", "", &now)
            .ok()
            .map(|v| v.mandate_id)
    }

    fn ingest_keyed(&self, key: &str, tool: &str, text: &str) {
        // Tier 1 taint ingest is unconditional and independent of Tier 2 (availability or verdicts).
        if self.output_untrusted(tool) {
            self.state
                .lock()
                .unwrap()
                .taint
                .entry(key.to_string())
                .or_default()
                .ingest(text);
            if let Some((c, _)) = &self.tier2 {
                c.ingest(key, text); // async: embedded in the sidecar, off the response path
            }
        }
    }

    /// Proxy path: record a relayed tool output (the proxy holds the one mandate it runs under).
    /// Keyed by the verified mandate id + session; an unverifiable mandate records nothing.
    pub fn observe_output_in(
        &self,
        mandate: &str,
        context: Option<&bindings::Context>,
        tool: &str,
        text: &str,
    ) {
        self.observe_output_at(mandate, context, tool, text, None)
    }

    /// As `observe_output_in`, verifying the mandate at an explicit time (replay / tests only).
    pub fn observe_output_at(
        &self,
        mandate: &str,
        context: Option<&bindings::Context>,
        tool: &str,
        text: &str,
        now: Option<&str>,
    ) {
        if let Some(id) = self.verified_mandate_id_at(mandate, now) {
            self.ingest_keyed(&state_key(&id, context), tool, text);
        }
    }

    /// Serve path (`POST /v1/outputs`): ingest a tool output reported by the caller. Accepted only
    /// for a verified mandate and a prior decision of THIS Edge that let the tool run (allow, or
    /// shadow), for the same mandate/session and tool, once.
    pub fn ingest_output(
        &self,
        mandate: &str,
        context: Option<&bindings::Context>,
        decision_id: &str,
        tool: &str,
        text: &str,
    ) -> Result<(), IngestError> {
        let id = self
            .verified_mandate_id(mandate)
            .ok_or(IngestError::Mandate)?;
        let key = state_key(&id, context);
        {
            let mut st = self.state.lock().unwrap();
            match st.ran.get(decision_id) {
                Some((k, t)) if *k == key && t == tool => {
                    st.ran.remove(decision_id);
                }
                _ => return Err(IngestError::UnknownDecision),
            }
        }
        self.ingest_keyed(&key, tool, text);
        Ok(())
    }

    fn resource_for(&self, def: Option<&ToolDef>, args: &serde_json::Value) -> String {
        if let Some(r) = args.get("resource").and_then(|v| v.as_str()) {
            return r.to_string();
        }
        let Some(d) = def else {
            return "unknown".into();
        };
        let mut r = d.resource_template.clone();
        while let (Some(a), Some(b)) = (r.find('{'), r.find('}')) {
            if b < a {
                break;
            }
            let key = &r[a + 1..b];
            let val = args
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            r.replace_range(a..=b, &val);
        }
        r
    }

    pub fn decide(&self, req: &DecideRequest) -> DecideResponse {
        let (ts_ms, now) = match &req.now {
            Some(n) => (0, n.clone()),
            None => now_rfc3339(),
        };
        let def = self.tools.get(&req.tool);
        let resource = self.resource_for(def, &req.args);
        let mut reasons = vec![];

        // Mandate (Biscuit): signature, revocation, expiry, attenuation; then signed scope constraints.
        let verified = token::verify(
            &req.mandate,
            self.root,
            &self.revoked,
            &req.tool,
            &resource,
            &now,
        );
        // Trusted text (the principal's purpose) never counts as taint.
        let trusted: HashSet<String> = verified
            .as_ref()
            .map(|v| taint::atoms_of(&v.purpose))
            .unwrap_or_default();
        // Tables the mandate allows (`sql.tables` in any matching scope) are trusted SQL identifiers:
        // an allowed table name appearing in untrusted text does not taint a query.
        // The free-text `purpose` does NOT clear SQL identifiers: only structured constraint values
        // (`sql.tables`) and string values of the signed mandate `context` may.
        let sql_trusted: HashSet<String> = {
            let mut t: HashSet<String> = HashSet::new();
            if let Ok(v) = verified.as_ref() {
                let ctx = bindings::merge(&v.context, None, "");
                for val in ctx.values() {
                    let vs = match val {
                        serde_json::Value::Array(a) => a.clone(),
                        x => vec![x.clone()],
                    };
                    t.extend(
                        vs.iter()
                            .filter_map(|x| x.as_str())
                            .map(|x| x.trim().to_lowercase()),
                    );
                }
                for (_, c) in &v.scopes {
                    if let Some(a) = c.get("sql.tables").and_then(|x| x.as_array()) {
                        t.extend(a.iter().filter_map(|x| x.as_str()).map(|x| {
                            let x = x.trim().to_lowercase();
                            x.rsplit('.').next().unwrap_or(&x).to_string()
                        }));
                    }
                }
            }
            t
        };
        // Which string arguments carry values derived from untrusted output seen in this run.
        let fixture = verified
            .as_ref()
            .ok()
            .and_then(|v| v.context.get("sentryra_fixture"))
            .and_then(|v| v.as_str())
            .is_some_and(|f| f == "bench" || f == "dev");
        let skey = state_key(
            verified
                .as_ref()
                .map(|v| v.mandate_id.as_str())
                .unwrap_or("!unverified"),
            req.context.as_ref(),
        );
        let tainted_any: HashSet<String> = {
            let st = self.state.lock().unwrap();
            let empty = taint::Store::default();
            let store = st.taint.get(&skey).unwrap_or(&empty);
            req.args
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter(|(k, v)| {
                            let kind = def
                                .map(|d| d.kind_of(k))
                                .unwrap_or_else(|| ArgKind::infer(k));
                            let vals: Vec<String> = match v {
                                serde_json::Value::Array(a) => a
                                    .iter()
                                    .map(|x| {
                                        x.as_str()
                                            .map(String::from)
                                            .unwrap_or_else(|| x.to_string())
                                    })
                                    .collect(),
                                serde_json::Value::String(s) => vec![s.clone()],
                                serde_json::Value::Number(n) => vec![n.to_string()],
                                _ => vec![],
                            };
                            let tr = if kind == ArgKind::Sql {
                                &sql_trusted
                            } else {
                                &trusted
                            };
                            vals.iter().any(|s| store.is_tainted(kind, s, tr))
                        })
                        .map(|(k, _)| k.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut ddl_mandated = false;
        let mut obligations: Vec<String> = vec![];
        let base = constraints::baseline(&req.args, def);
        reasons.extend(base.reasons.iter().cloned());
        let mut vouched: HashSet<String> = HashSet::new();
        // Mandate escalate scopes whose constraints did not deny (candidates for "who may approve").
        let mut escalation_scopes: Vec<EscalationScope> = vec![];
        let purpose = verified
            .as_ref()
            .map(|v| v.purpose.clone())
            .unwrap_or_default();
        let (mandate_id, principal, mut mandate_effect) = match verified {
            Ok(v) => {
                if v.scopes.is_empty() {
                    reasons.push("mandate: no scope for this tool/resource (default deny)".into());
                }
                // Each matching scope grants only if its constraints pass; strictest surviving effect wins.
                let mut best: Option<Effect> = None;
                let ctx = bindings::merge(&v.context, req.context.as_ref(), &v.principal);
                for (i, (eff, c)) in v.scopes.iter().enumerate() {
                    let c = &bindings::resolve(c, &ctx);
                    let o = constraints::eval(c, &req.args, def, &|a| tainted_any.contains(a));
                    reasons.extend(o.reasons.iter().cloned());
                    let e = match o.verdict {
                        constraints::Verdict::Deny => continue,
                        constraints::Verdict::Escalate if *eff == Effect::Allow => Effect::Escalate,
                        _ => *eff,
                    };
                    if *eff == Effect::Escalate {
                        if let Some(m) = v.scope_meta.get(i) {
                            escalation_scopes.push(EscalationScope {
                                tool: req.tool.clone(),
                                resource: m.resource.clone(),
                                approvers: m.approvers.clone(),
                            });
                        }
                    }
                    vouched.extend(o.vouched);
                    obligations.extend(o.obligations);
                    ddl_mandated |= o.ddl_ok;
                    best = Some(best.map_or(e, |b| stricter(b, e)));
                }
                (v.mandate_id, v.principal, best.unwrap_or(Effect::Deny))
            }
            Err(e) => {
                reasons.push(format!("mandate invalid: {e}"));
                (String::new(), String::new(), Effect::Deny)
            }
        };
        if base.verdict == constraints::Verdict::Deny {
            mandate_effect = Effect::Deny;
        }
        if mandate_effect != Effect::Escalate {
            escalation_scopes.clear();
        }
        // Scopes without a signed list (old tokens) add no restriction.
        escalation_scopes.retain(|s| !s.approvers.is_empty());
        let in_catalogue = def.is_some();
        if !in_catalogue {
            reasons.push("tool not in signed catalogue: treated as destructive".into());
        }

        // Typed argument analysis. Any call carrying a `sql` argument is parsed, whatever the tool is called.
        let sql = if req.args.get("sql").is_some() || req.tool.ends_with(".query") {
            let text = req.args.get("sql").and_then(|v| v.as_str()).unwrap_or("");
            sql::classify(text)
        } else {
            sql::Class::default()
        };
        if sql.has_ddl {
            reasons.push(format!("sql: DDL statement ({})", sql.kinds.join(",")));
        }
        if sql.has_dml {
            reasons.push(format!(
                "sql: DML ({}) needs human approval",
                sql.kinds.join(",")
            ));
        }
        if mandate_effect == Effect::Escalate {
            reasons.push("mandate: scope requires approval".into());
        }
        if sql.parse_error {
            reasons.push("sql: does not parse (fail closed)".into());
        }
        // Sinks: the arguments declared in the signed manifest; uncatalogued tools default to
        // "every argument is a sink".
        let sinks: Vec<String> = match def {
            Some(d) => d.sink_args.clone(),
            None => req
                .args
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default(),
        };
        let tainted_args: Vec<String> = sinks
            .iter()
            .filter(|k| tainted_any.contains(*k))
            .cloned()
            .collect();
        // A tainted value that passed an explicit principal-chosen allowlist (e.g. recipient_domains)
        // is recorded as a signal but does not escalate on its own.
        let unvouched: Vec<&String> = tainted_args
            .iter()
            .filter(|a| !vouched.contains(*a))
            .collect();
        if !tainted_args.is_empty() {
            reasons.push(format!(
                "taint: {} copied from untrusted tool output{}",
                tainted_args.join(","),
                if unvouched.is_empty() {
                    " (within an explicit mandate allowlist: signal only)"
                } else {
                    ""
                }
            ));
        }

        // Cedar.
        let me = match mandate_effect {
            Effect::Allow => "allow",
            Effect::Escalate => "escalate",
            Effect::Deny => "deny",
        };
        let ctx = serde_json::json!({
            "mandate_effect": me,
            "in_catalogue": in_catalogue,
            "sink_tainted": !unvouched.is_empty(),
            "sql": {"is_sql": sql.is_sql, "has_ddl": sql.has_ddl, "ddl_mandated": ddl_mandated, "has_dml": sql.has_dml, "parse_error": sql.parse_error},
        });
        let (mut decision, mut policy_ids) = self.cedar(&req.tool, &resource, &principal, ctx);
        if decision == "deny" && reasons.is_empty() {
            reasons.push("no permit matched (default deny)".into());
        }

        // LONG_SEND_HOLD (Tier 1, deterministic, no model; independent of Tier 2 and of speed): an
        // outbound send in a session that has seen untrusted tool output, whose text could take
        // more than one Tier 2 window, escalates. Recorded alongside every other reason; never
        // lowers a deny. A session has seen untrusted output iff `ingest_keyed` created its taint
        // store entry (any untrusted output, even one with no taintable content).
        if def.is_some_and(|d| {
            t2::types::SideEffect::parse(d.side_effect_class.as_deref())
                == t2::types::SideEffect::ExternalSend
        }) && self.state.lock().unwrap().taint.contains_key(&skey)
        {
            let n = long_send::outbound_tokens(&req.args, def);
            if long_send::is_long(n) {
                reasons.push(format!(
                    "{}: outbound_send after untrusted tool output in this session; outbound text token bound {n} > {} (one Tier 2 window): held for approval (Tier 1, deterministic){}",
                    long_send::REASON_CODE,
                    long_send::T2_WINDOW_TOKENS,
                    if decision == "deny" { " (decision stays deny)" } else { "" }
                ));
                if decision != "deny" {
                    decision = "escalate".into();
                    policy_ids.push(long_send::POLICY_ID.into());
                }
            }
        }

        // Tier 2 (escalate-only): may raise allow -> escalate; never lowers, never allows.
        if let Some((c, diag)) = &self.tier2 {
            let class = t2::types::SideEffect::parse(match def {
                Some(d) => d.side_effect_class.as_deref().or(Some(if d.consequential {
                    "write"
                } else {
                    "read"
                })),
                None => None, // uncatalogued => destructive
            });
            let tier1 = match decision.as_str() {
                "allow" => t2::Outcome::Allow,
                "escalate" => t2::Outcome::Escalate,
                _ => t2::Outcome::Deny,
            };
            let mut a = req.args.clone();
            if let Some(o) = a.as_object_mut() {
                o.remove("resource");
            }
            let key = &skey;
            let export = self.t2_export && fixture;
            let (rid, res) = c.score_ex(
                key, &purpose, &req.tool, class, &resource, &a, *diag, export,
            );
            let ctx = t2::rules::Ctx {
                untrusted_in_session: c.has_untrusted(key),
            };
            let ap = t2::rules::apply(tier1, class, &res, &c.cfg, ctx);
            let via: Vec<String> = ap.via.iter().map(|v| format!("{v:?}")).collect();
            reasons.push(format!(
                "tier2: {} req={rid} class={} cfg={} via=[{}] {}",
                if ap.tier2_escalate {
                    "escalate"
                } else {
                    "none"
                },
                class.wire(),
                c.config_version,
                via.join(","),
                ap.export()
            ));
            if ap.outcome == t2::Outcome::Escalate && tier1 == t2::Outcome::Allow {
                decision = "escalate".into();
                policy_ids.push("tier2-escalate".into());
            }
            debug_assert!(!(tier1 != t2::Outcome::Allow && decision == "allow"));
        }

        // Approval receipt: can turn an escalate into allow, exactly once, for exactly this action.
        let ahash = receipts::action_hash(&mandate_id, &req.tool, &resource, &req.args);
        let mut approval: Option<String> = None;
        let mut escalation_decision_id: Option<String> = None;
        if let Some(r) = &req.receipt {
            if decision != "escalate" {
                reasons.push(format!("receipt ignored: a receipt can only resolve an escalation (decision is {decision})"));
            } else {
                let mut st = self.state.lock().unwrap();
                let res = receipts::check(r, &self.approval_vk, &ahash, wall_ms()).and_then(|_| {
                    if st.denied.contains(&r.decision_id) {
                        Err(receipts::ReceiptError::Denied)
                    } else if st.consumed.contains_key(&r.apr_id) {
                        Err(receipts::ReceiptError::AlreadyUsed)
                    } else {
                        Ok(())
                    }
                });
                // Persist the id BEFORE accepting the receipt; if that fails, refuse (fail closed).
                let res = res.and_then(|_| {
                    let now = wall_ms();
                    let st = &mut *st;
                    consumed::record(&mut st.consumed, st.consumed_file.as_mut(), r, now)
                        .map_err(|_| receipts::ReceiptError::NotPersisted)
                });
                match res {
                    Ok(()) => {
                        decision = "allow".into();
                        policy_ids.push("approval-receipt".into());
                        reasons.push(format!(
                            "approved by {} ({}, single-use, consumed)",
                            r.approver, r.apr_id
                        ));
                        approval =
                            Some(hex::encode(Sha256::digest(serde_json::to_vec(r).unwrap())));
                        // Signed into the receipt by the approval key: links this allow record to
                        // the escalation record it resolves.
                        escalation_decision_id = Some(r.decision_id.clone());
                    }
                    Err(e) => reasons.push(format!("receipt rejected: {e:?}")),
                }
            }
        }

        let enforced = self.mode == Mode::Enforce;
        let mut st = self.state.lock().unwrap();
        st.counter += 1;
        let decision_id = format!("dec_{:016x}{:04x}", ts_ms, st.counter);
        let mode_s = if enforced { "enforce" } else { "shadow" };
        let e = st.chain.append(NewEntry {
            ts_ms,
            decision_id: &decision_id,
            mandate_id: &mandate_id,
            tool: &req.tool,
            resource: &resource,
            args: &req.args,
            principal: &principal,
            tainted: !tainted_args.is_empty(),
            decision: &decision,
            mode: mode_s,
            enforced,
            policy_ids: policy_ids.clone(),
            reasons: reasons.clone(),
            approval: approval.clone(),
            escalation_decision_id,
        });
        let (seq, entry_hash) = (e.seq, e.entry_hash.clone());
        let line = serde_json::to_string(e).unwrap();
        write_line(&mut st, &line);
        if decision == "allow" || !enforced {
            st.ran
                .insert(decision_id.clone(), (skey.clone(), req.tool.clone()));
            st.ran_order.push_back(decision_id.clone());
            while st.ran_order.len() > 100_000 {
                if let Some(old) = st.ran_order.pop_front() {
                    st.ran.remove(&old);
                }
            }
        }
        let approval_link = if decision == "escalate" {
            st.pending.insert(
                decision_id.clone(),
                PendingApproval {
                    decision_id: decision_id.clone(),
                    tool: req.tool.clone(),
                    resource: resource.clone(),
                    args: req.args.clone(),
                    reasons: reasons.clone(),
                    tainted_args: tainted_args.clone(),
                    action_hash: ahash,
                    escalation_scopes,
                    mandate_id: mandate_id.clone(),
                    principal: principal.clone(),
                },
            );
            Some(format!("{}/v1/approvals/{}", self.edge_url, decision_id))
        } else {
            None
        };
        DecideResponse {
            decision_id,
            decision,
            enforced,
            mode: self.mode,
            resource,
            reasons,
            policy_ids,
            tainted: !tainted_args.is_empty(),
            obligations,
            approval_link,
            evidence_seq: seq,
            entry_hash,
        }
    }

    /// Approval service (in the MVP the Edge hosts it; in production the control plane signs with
    /// the tenant approval key). Issues a signed, single-use receipt bound to the pending action.
    ///
    /// `approver` is SELF-DECLARED: the caller holds the one shared approver bearer token and
    /// types a name. If the hold came from a mandate escalate scope, the name must exactly match
    /// one of that scope's signed `approvers` (every such scope, if several matched); otherwise
    /// the attempt is refused with an evidence record and no receipt. This is a consistency check
    /// between the mandate and the receipt, NOT authentication of the person approving.
    pub fn approve(
        &self,
        decision_id: &str,
        approver: &str,
    ) -> Result<receipts::Receipt, ApproveError> {
        let sk = self
            .approval_sk
            .as_ref()
            .ok_or(ApproveError::NoApprovalKey)?;
        let mut st = self.state.lock().unwrap();
        if st.denied.contains(decision_id) {
            return Err(ApproveError::Denied);
        }
        let p = st
            .pending
            .get(decision_id)
            .cloned()
            .ok_or(ApproveError::NotFound)?;
        if approver.trim().is_empty() {
            return Err(ApproveError::EmptyName);
        }
        let not_listed: Vec<&EscalationScope> = p
            .escalation_scopes
            .iter()
            .filter(|s| !s.approvers.iter().any(|a| a == approver))
            .collect();
        if !not_listed.is_empty() {
            let reasons = not_listed
                .iter()
                .map(|s| {
                    format!(
                        "approval refused: self-declared approver {approver:?} is not in the approvers list {:?} of mandate escalate scope {} {} (escalation {decision_id}; no receipt issued; name not authenticated)",
                        s.approvers, s.tool, s.resource
                    )
                })
                .collect();
            self.record_approval_event(
                &mut st,
                &p,
                "deny",
                vec!["approval-refused-approver-not-listed".into()],
                reasons,
            );
            return Err(ApproveError::NotListed);
        }
        let now = wall_ms();
        let r = receipts::Receipt {
            spec: "sentryra.approval-receipt/v0".into(),
            apr_id: format!("apr_{:x}{}", now, &p.action_hash[..8]),
            decision_id: decision_id.into(),
            action_hash: p.action_hash.clone(),
            approver: approver.into(),
            issued_ms: now,
            expires_ms: now + receipts::RECEIPT_TTL_MS,
            sig: String::new(),
        };
        Ok(receipts::sign(r, sk))
    }

    /// Deny a pending escalation. `approver` is SELF-DECLARED (shared bearer token), like in
    /// `approve`; any non-empty name may deny. Removes the pending approval, writes a signed
    /// evidence record (decision `deny`, policy `approval-denied`) naming the self-declared denier
    /// and the optional reason, and makes later approves of this id fail. The agent's retry has
    /// no receipt, so it is held again as a new escalation.
    pub fn deny(
        &self,
        decision_id: &str,
        approver: &str,
        reason: Option<&str>,
    ) -> Result<(), ApproveError> {
        let mut st = self.state.lock().unwrap();
        if st.denied.contains(decision_id) {
            return Err(ApproveError::Denied);
        }
        let p = st
            .pending
            .get(decision_id)
            .cloned()
            .ok_or(ApproveError::NotFound)?;
        if approver.trim().is_empty() {
            return Err(ApproveError::EmptyName);
        }
        let reason: String = reason
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .unwrap_or("(none given)")
            .chars()
            .take(500)
            .collect();
        st.pending.remove(decision_id);
        st.denied.insert(decision_id.to_string());
        self.record_approval_event(
            &mut st,
            &p,
            "deny",
            vec!["approval-denied".into()],
            vec![format!(
                "approval denied by self-declared approver {approver:?} (name not authenticated); escalation {decision_id}; reason: {reason}"
            )],
        );
        Ok(())
    }

    /// Append an evidence record about an approval-service event (refusal, denial) for a pending
    /// escalation. Raw args are HMAC'd like every other entry.
    fn record_approval_event(
        &self,
        st: &mut State,
        p: &PendingApproval,
        decision: &str,
        policy_ids: Vec<String>,
        reasons: Vec<String>,
    ) {
        let ts_ms = wall_ms();
        st.counter += 1;
        let id = format!("dec_{:016x}{:04x}", ts_ms, st.counter);
        let enforced = self.mode == Mode::Enforce;
        let e = st.chain.append(NewEntry {
            ts_ms,
            decision_id: &id,
            mandate_id: &p.mandate_id,
            tool: &p.tool,
            resource: &p.resource,
            args: &p.args,
            principal: &p.principal,
            tainted: !p.tainted_args.is_empty(),
            decision,
            mode: if enforced { "enforce" } else { "shadow" },
            enforced,
            policy_ids,
            reasons,
            approval: None,
            escalation_decision_id: Some(p.decision_id.clone()),
        });
        let line = serde_json::to_string(e).unwrap();
        write_line(st, &line);
    }

    fn cedar(
        &self,
        tool: &str,
        resource: &str,
        principal: &str,
        ctx: serde_json::Value,
    ) -> (String, Vec<String>) {
        let q = |s: &str| serde_json::to_string(s).unwrap();
        let p = EntityUid::from_str(&format!(
            "Principal::{}",
            q(if principal.is_empty() {
                "anonymous"
            } else {
                principal
            })
        ));
        let a = EntityUid::from_str(&format!("Action::{}", q(tool)));
        let r = EntityUid::from_str(&format!("Resource::{}", q(resource)));
        let (Ok(p), Ok(a), Ok(r)) = (p, a, r) else {
            return ("deny".into(), vec!["cedar-request-error".into()]);
        };
        let Ok(c) = Context::from_json_value(ctx, None) else {
            return ("deny".into(), vec!["cedar-context-error".into()]);
        };
        let Ok(req) = Request::new(p, a, r, c, None) else {
            return ("deny".into(), vec!["cedar-request-error".into()]);
        };
        let resp = self
            .authorizer
            .is_authorized(&req, &self.policies, &Entities::empty());
        let ids: Vec<String> = resp
            .diagnostics()
            .reason()
            .map(|id| {
                self.policies
                    .annotation(id, "id")
                    .unwrap_or(id.as_ref())
                    .to_string()
            })
            .collect();
        if resp.diagnostics().errors().next().is_some() {
            return ("deny".into(), vec!["cedar-evaluation-error".into()]);
        }
        let d = match resp.decision() {
            CDecision::Deny => "deny",
            CDecision::Allow => {
                if resp
                    .diagnostics()
                    .reason()
                    .any(|id| self.policies.annotation(id, "effect") == Some("escalate"))
                {
                    "escalate"
                } else {
                    "allow"
                }
            }
        };
        (d.into(), ids)
    }
}

fn write_line(st: &mut State, line: &str) {
    if let Some(f) = st.file.as_mut() {
        let _ = writeln!(f, "{line}").and_then(|_| f.flush());
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_long_send;
