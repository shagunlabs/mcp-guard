//! M2 Tier 1 decision core: Biscuit mandate + signed tool catalogue + Cedar + SQL parse + taint,
//! in shadow or enforce mode, with every decision written to the signed evidence chain.
pub mod constraints;
pub mod receipts;
pub mod sql;
pub mod taint;

use cedar_policy::{
    Authorizer, Context, Decision as CDecision, Entities, EntityUid, PolicySet, Request,
};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use sentryra_connector_manifest::{Manifest, ToolDef, Trust};
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
    taint: taint::Store,
    pending: HashMap<String, PendingApproval>,
    file: Option<std::fs::File>,
    counter: u64,
    consumed: HashSet<String>,
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
                taint: taint::Store::default(),
                pending: HashMap::new(),
                file,
                counter: 0,
                consumed: HashSet::new(),
            }),
        })
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

    /// Record a relayed tool output for taint tracking (only if the tool's output is untrusted).
    pub fn observe_output(&self, tool: &str, text: &str) {
        if self.output_untrusted(tool) {
            self.state.lock().unwrap().taint.ingest(text);
        }
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
        // Which string arguments carry fingerprints of untrusted output seen in this run.
        let tainted_any: HashSet<String> = {
            let st = self.state.lock().unwrap();
            req.args
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter(|(_, v)| {
                            let vals: Vec<&str> = match v {
                                serde_json::Value::Array(a) => {
                                    a.iter().filter_map(|x| x.as_str()).collect()
                                }
                                serde_json::Value::String(s) => vec![s.as_str()],
                                _ => vec![],
                            };
                            vals.iter().any(|s| st.taint.is_tainted(s))
                        })
                        .map(|(k, _)| k.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut ddl_mandated = false;
        let base = constraints::baseline(&req.args, def);
        reasons.extend(base.reasons.iter().cloned());
        let mut vouched: HashSet<String> = HashSet::new();
        let (mandate_id, principal, mut mandate_effect) = match token::verify(
            &req.mandate,
            self.root,
            &self.revoked,
            &req.tool,
            &resource,
            &now,
        ) {
            Ok(v) => {
                if v.scopes.is_empty() {
                    reasons.push("mandate: no scope for this tool/resource (default deny)".into());
                }
                // Each matching scope grants only if its constraints pass; strictest surviving effect wins.
                let mut best: Option<Effect> = None;
                for (eff, c) in &v.scopes {
                    let o = constraints::eval(c, &req.args, def, &|a| tainted_any.contains(a));
                    reasons.extend(o.reasons.iter().cloned());
                    let e = match o.verdict {
                        constraints::Verdict::Deny => continue,
                        constraints::Verdict::Escalate if *eff == Effect::Allow => Effect::Escalate,
                        _ => *eff,
                    };
                    vouched.extend(o.vouched);
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
        // Taint is only relevant for sink arguments declared in the signed manifest.
        // (Uncatalogued tools are escalated anyway.)
        let sinks: Vec<String> = def.map(|d| d.sink_args.clone()).unwrap_or_default();
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

        // Approval receipt: can turn an escalate into allow, exactly once, for exactly this action.
        let ahash = receipts::action_hash(&mandate_id, &req.tool, &resource, &req.args);
        let mut approval: Option<String> = None;
        if let Some(r) = &req.receipt {
            if decision != "escalate" {
                reasons.push(format!("receipt ignored: a receipt can only resolve an escalation (decision is {decision})"));
            } else {
                let mut st = self.state.lock().unwrap();
                let res = receipts::check(r, &self.approval_vk, &ahash, wall_ms()).and_then(|_| {
                    if st.consumed.contains(&r.apr_id) {
                        Err(receipts::ReceiptError::AlreadyUsed)
                    } else {
                        Ok(())
                    }
                });
                match res {
                    Ok(()) => {
                        st.consumed.insert(r.apr_id.clone());
                        decision = "allow".into();
                        policy_ids.push("approval-receipt".into());
                        reasons.push(format!(
                            "approved by {} ({}, single-use, consumed)",
                            r.approver, r.apr_id
                        ));
                        approval =
                            Some(hex::encode(Sha256::digest(serde_json::to_vec(r).unwrap())));
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
        });
        let (seq, entry_hash) = (e.seq, e.entry_hash.clone());
        let line = serde_json::to_string(e).unwrap();
        if let Some(f) = st.file.as_mut() {
            let _ = writeln!(f, "{line}").and_then(|_| f.flush());
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
            approval_link,
            evidence_seq: seq,
            entry_hash,
        }
    }

    /// Approval service (in the MVP the Edge hosts it; in production the control plane signs with
    /// the tenant approval key). Issues a signed, single-use receipt bound to the pending action.
    pub fn approve(
        &self,
        decision_id: &str,
        approver: &str,
    ) -> Result<receipts::Receipt, EngineError> {
        let sk = self
            .approval_sk
            .as_ref()
            .ok_or_else(|| EngineError("this Edge has no approval key".into()))?;
        let st = self.state.lock().unwrap();
        let p = st
            .pending
            .get(decision_id)
            .ok_or_else(|| EngineError("no such pending approval".into()))?;
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

#[cfg(test)]
mod tests;
