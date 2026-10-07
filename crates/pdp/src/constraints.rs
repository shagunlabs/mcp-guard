//! Generic mandate-constraint evaluation (Tier 1, deterministic).
//!
//! Constraints live in the signed mandate scope and use the **mandate v0 constraint vocabulary**
//! (dotted keys, see `spec/mandate-v0.md` and `VOCABULARY`). They are applied to call arguments by
//! semantic kind (manifest `args` mapping, falling back to `ArgKind::infer`) or, for allowlist keys,
//! by conventional argument names (`names_for`). Unknown keys escalate (fail closed). `..` path
//! traversal is always denied. `$`-prefixed values are context bindings the MVP cannot resolve: escalate.
use crate::sql;
use sentryra_connector_manifest::{ArgKind, ToolDef};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Pass,
    Escalate,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    /// Arguments that passed an explicit allowlist chosen by the principal.
    pub vouched: HashSet<String>,
    /// The block explicitly authorised the DDL verbs in this statement (sql.statement_types).
    pub ddl_ok: bool,
    /// Obligations to apply to the result (e.g. row_cap). Not yet enforced by the proxy.
    pub obligations: Vec<String>,
}

impl Outcome {
    fn new() -> Self {
        Self {
            verdict: Verdict::Pass,
            reasons: vec![],
            vouched: HashSet::new(),
            ddl_ok: false,
            obligations: vec![],
        }
    }
    fn deny(&mut self, r: String) {
        self.verdict = self.verdict.max(Verdict::Deny);
        self.reasons.push(r);
    }
    fn escalate(&mut self, r: String) {
        self.verdict = self.verdict.max(Verdict::Escalate);
        self.reasons.push(r);
    }
}

/// Glob: `*` matches within a path segment, `**` across segments, `?` one char.
pub fn glob(pat: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) if p.get(1) == Some(&b'*') => {
                (0..=s.len()).any(|i| go(&p[2..], &s[i..]))
            }
            (Some(b'*'), _) => (0..=s.len())
                .take_while(|&i| i == 0 || s[i - 1] != b'/')
                .any(|i| go(&p[1..], &s[i..])),
            (Some(b'?'), Some(c)) if *c != b'/' => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(pat.as_bytes(), s.as_bytes())
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().flat_map(strings).collect(),
        Value::String(s) => vec![s.clone()],
        Value::Null => vec![],
        other => vec![other.to_string()],
    }
}

fn list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    }
}

fn host_of(kind: ArgKind, v: &str) -> Option<String> {
    let v = v.trim();
    let h = match kind {
        ArgKind::Email => v
            .rsplit_once('@')
            .map(|(_, d)| d.trim_end_matches('>').to_string())?,
        ArgKind::Url => {
            let rest = v.split_once("://").map(|(_, r)| r)?;
            let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
            let auth = auth.rsplit_once('@').map(|(_, h)| h).unwrap_or(auth);
            auth.split(':').next().unwrap_or("").to_string()
        }
        ArgKind::Host => v.to_string(),
        _ => return None,
    };
    Some(h.to_lowercase().trim_end_matches('.').to_string())
}

fn domain_ok(host: &str, allowed: &[String]) -> bool {
    host.is_ascii()
        && !host.is_empty()
        && allowed.iter().any(|d| {
            let d = d.to_lowercase();
            host == d || host.ends_with(&format!(".{d}"))
        })
}

fn args_of_kind<'a>(
    args: &'a Value,
    def: Option<&ToolDef>,
    kinds: &[ArgKind],
) -> Vec<(&'a String, &'a Value)> {
    args.as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| {
                    let kind = def
                        .map(|d| d.kind_of(k))
                        .unwrap_or_else(|| ArgKind::infer(k));
                    kinds.contains(&kind)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `s` (already stripped of brackets/quotes/`mailto:`) is shaped like an email address.
fn email_shaped(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && local
            .chars()
            .all(|c| c.is_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(c))
        && domain
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
        && !domain.starts_with(['.', '-'])
}

/// Address-shaped tokens embedded anywhere in one string, normalised (trimmed, lowercased,
/// `mailto:` removed). Handles `Name <a@b>`, `a@b, c@d`, `mailto:a@b`, quoted forms.
fn address_tokens(s: &str) -> Vec<String> {
    s.split(|c: char| c.is_whitespace() || ",;<>\"'()[]".contains(c))
        .map(|t| {
            let t = t.trim().to_lowercase();
            t.strip_prefix("mailto:").map(String::from).unwrap_or(t)
        })
        .filter(|t| email_shaped(t))
        .collect()
}

/// Every address-shaped string anywhere in `v` (nested arrays / objects included).
fn addresses_in(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.extend(address_tokens(s)),
        Value::Array(a) => a.iter().for_each(|x| addresses_in(x, out)),
        Value::Object(o) => o.values().for_each(|x| addresses_in(x, out)),
        _ => {}
    }
}

/// Fail-closed recipient checks shared by `mail.recipients` and `mail.recipient_domains` (`key`).
/// `accept(addr)` says whether a normalised address satisfies the constraint.
/// - catalogue declares the tool `external_send` but declares no `email` argument: escalate;
/// - no recipient (`email`-kind) argument with a value in the call: escalate;
/// - any OTHER argument (not `email`, not free `text` such as `body`, which is content rather
///   than routing) holding an address-shaped value anywhere (e.g. `forward_to`, `target`,
///   `subject`, nested objects, `mailto:` URLs): an address the constraint rejects denies; an
///   accepted address still escalates, because the field is not a recognised recipient field.
///   Such a call is never allowed through.
///
/// The `email`-kind arguments themselves are checked by the caller.
fn recipients_fail_closed(
    o: &mut Outcome,
    key: &str,
    args: &Value,
    def: Option<&ToolDef>,
    accept: &dyn Fn(&str) -> bool,
) {
    if let Some(d) = def {
        if d.side_effect_class.as_deref() == Some("external_send")
            && !d.args.values().any(|k| *k == ArgKind::Email)
        {
            o.escalate(format!(
                "constraint: {key} set but catalogue declares no recipient (email) argument for outbound send `{}`",
                d.name
            ));
        }
    }
    let n_values: usize = args_of_kind(args, def, &[ArgKind::Email])
        .iter()
        .map(|(_, v)| match v {
            Value::Null => 0,
            x => list(x).len(),
        })
        .sum();
    if n_values == 0 {
        o.escalate(format!(
            "constraint: {key} set but no recipient field found"
        ));
    }
    let empty = serde_json::Map::new();
    for (an, v) in args.as_object().unwrap_or(&empty) {
        let kind = def
            .map(|d| d.kind_of(an))
            .unwrap_or_else(|| ArgKind::infer(an));
        if kind == ArgKind::Email || kind.is_free_text() {
            continue;
        }
        let mut found = vec![];
        addresses_in(v, &mut found);
        if found.is_empty() {
            continue;
        }
        if found.iter().any(|a| !accept(a)) {
            o.deny(format!("constraint: `{an}` holds an address not in {key}"));
        } else {
            o.escalate(format!(
                "constraint: `{an}` holds an address but is not a recognised recipient field"
            ));
        }
    }
}

/// `mail.recipients` (exact-address allowlist). An unresolved `$binding` escalates; every value of
/// every `email`-kind argument (`from` included) must be in the list, else deny; plus the shared
/// fail-closed checks in `recipients_fail_closed`.
fn mail_recipients(o: &mut Outcome, val: &Value, args: &Value, def: Option<&ToolDef>) {
    let allowed_raw = list(val);
    let unresolved = allowed_raw
        .iter()
        .any(|a| a.as_str().is_some_and(|s| s.starts_with('$')));
    if unresolved {
        o.escalate(
            "constraint: `mail.recipients` uses a context binding the Edge cannot resolve yet"
                .into(),
        );
        return;
    }
    let allowed: Vec<String> = allowed_raw
        .iter()
        .map(|a| match a {
            Value::String(s) => s.trim().to_lowercase(),
            x => x.to_string(),
        })
        .collect();
    recipients_fail_closed(o, "mail.recipients", args, def, &|a| {
        allowed.iter().any(|x| x == a)
    });
    for (an, v) in args_of_kind(args, def, &[ArgKind::Email]) {
        let ok = list(v).iter().all(|x| {
            x.as_str()
                .is_some_and(|s| allowed.contains(&s.trim().to_lowercase()))
        });
        if ok {
            o.vouched.insert(an.clone());
        } else {
            o.deny(format!("constraint: `{an}` value not in mail.recipients"));
        }
    }
}

/// Rules that apply whether or not the mandate has constraints.
pub fn baseline(args: &Value, def: Option<&ToolDef>) -> Outcome {
    let mut o = Outcome::new();
    for (k, v) in args_of_kind(args, def, &[ArgKind::Path]) {
        for s in strings(v) {
            if s.split(['/', '\\']).any(|seg| seg == "..") {
                o.deny(format!("constraint: path traversal in `{k}`"));
            }
        }
    }
    o
}

/// Default argument names each vocabulary key applies to (in addition to manifest arg kinds).
fn names_for(key: &str) -> &'static [&'static str] {
    match key {
        "mail.query" => &["q", "query"],
        "repo.numbers" => &["number", "pr", "issue", "pull_number"],
        "repo.permissions" => &["permission", "role"],
        "chat.channels" => &["channel", "channel_id"],
        "idp.groups" => &["group", "groups"],
        "idp.users" => &["user", "username", "user_id"],
        "db.tenants" => &["tenant", "tenant_id"],
        "deploy.regions" => &["region", "regions"],
        "deploy.builds" => &["build", "version"],
        "amount.currency" => &["currency"],
        _ => &[],
    }
}

/// Every vocabulary key Tier 1 understands (mandate v0, see spec/mandate-v0.md).
pub const VOCABULARY: &[&str] = &[
    "amount.currency",
    "amount.max",
    "chat.channels",
    "db.tenants",
    "deploy.builds",
    "deploy.regions",
    "fs.path_prefix",
    "idp.groups",
    "idp.users",
    "mail.query",
    "mail.recipient_domains",
    "mail.recipients",
    "max_rows",
    "repo.branches",
    "repo.numbers",
    "repo.permissions",
    "shell.cmd_prefix",
    "sql.statement_types",
    "sql.tables",
    "untainted_args",
];

/// Lexically normalise a path (resolve `.` and `..`); None if it escapes the root.
fn normalise(p: &str) -> Option<String> {
    let abs = p.starts_with('/');
    let mut out: Vec<&str> = vec![];
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop()?;
            }
            s => out.push(s),
        }
    }
    Some(format!("{}{}", if abs { "/" } else { "" }, out.join("/")))
}

/// Evaluate one scope's constraint block. `tainted(arg)` reports whether an argument value was
/// copied from untrusted tool output in this run. `ddl_ok` is set if the block explicitly
/// authorises the DDL verbs present.
pub fn eval(
    c: &Value,
    args: &Value,
    def: Option<&ToolDef>,
    tainted: &dyn Fn(&str) -> bool,
) -> Outcome {
    let mut o = Outcome::new();
    let Some(map) = c.as_object() else { return o };
    let empty = serde_json::Map::new();
    let argmap = args.as_object().unwrap_or(&empty);
    let by_names = |key: &str| -> Vec<(&String, &Value)> {
        let n = names_for(key);
        argmap
            .iter()
            .filter(|(k, _)| n.contains(&k.as_str()))
            .collect()
    };
    for (key, val) in map {
        let k = key.as_str();
        match k {
            "sql.statement_types" => {
                let allowed: HashSet<String> =
                    strings(val).iter().map(|s| s.to_uppercase()).collect();
                for (an, v) in args_of_kind(args, def, &[ArgKind::Sql]) {
                    let cl = sql::classify(v.as_str().unwrap_or(""));
                    if cl.parse_error {
                        o.deny(format!("constraint: `{an}` does not parse"));
                    }
                    for kd in cl.classes() {
                        let ok = allowed.contains(&kd)
                            || (kd == "DDL"
                                && cl.ddl_verbs().iter().all(|vb| allowed.contains(vb)));
                        if kd == "DDL" && ok {
                            o.ddl_ok = true;
                        }
                        if !ok {
                            o.deny(format!(
                                "constraint: statement type {kd} not in sql.statement_types"
                            ));
                        }
                    }
                }
            }
            "sql.tables" => {
                let allowed: HashSet<String> =
                    strings(val).iter().map(|s| s.to_lowercase()).collect();
                for (_, v) in args_of_kind(args, def, &[ArgKind::Sql]) {
                    for t in sql::tables(v.as_str().unwrap_or("")) {
                        if !allowed.contains(&t) {
                            o.deny(format!("constraint: table `{t}` not in sql.tables"));
                        }
                    }
                }
            }
            // Result-size obligation applied to the tool *output* (row cap), not a pre-call argument check.
            "max_rows" => {
                if val.as_u64().is_none() {
                    o.escalate("constraint: max_rows is not a non-negative integer".into());
                } else {
                    o.obligations.push(format!("row_cap={val}"));
                }
            }
            "amount.max" => {
                let Some(max) = val.as_f64() else {
                    o.escalate("constraint: amount.max is not a number".into());
                    continue;
                };
                for (an, v) in args_of_kind(args, def, &[ArgKind::Amount]) {
                    match v
                        .as_f64()
                        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
                    {
                        Some(x) if x.is_finite() && (0.0..=max).contains(&x) => {}
                        Some(x) => o.deny(format!(
                            "constraint: `{an}` = {x} outside 0..={max} (amount.max)"
                        )),
                        None => o.deny(format!("constraint: `{an}` is not a number")),
                    }
                }
            }
            "shell.cmd_prefix" => {
                let prefixes = strings(val);
                for (an, v) in args_of_kind(args, def, &[ArgKind::Cmd]) {
                    let cmd = v.as_str().unwrap_or("").trim();
                    if cmd.chars().any(|ch| ";|&`$<>\n\\(){}".contains(ch)) {
                        o.deny(format!("constraint: shell metacharacters in `{an}`"));
                    } else if !prefixes
                        .iter()
                        .any(|p| cmd == p || cmd.starts_with(&format!("{p} ")))
                    {
                        o.deny(format!(
                            "constraint: `{an}` does not start with an allowed shell.cmd_prefix"
                        ));
                    }
                }
            }
            "mail.recipient_domains" => {
                let allowed = strings(val);
                recipients_fail_closed(&mut o, k, args, def, &|a| {
                    host_of(ArgKind::Email, a).is_some_and(|h| domain_ok(&h, &allowed))
                });
                for (an, v) in args_of_kind(args, def, &[ArgKind::Email]) {
                    let mut ok = true;
                    for s in strings(v) {
                        match host_of(ArgKind::Email, &s) {
                            Some(h) if domain_ok(&h, &allowed) => {}
                            Some(h) => {
                                ok = false;
                                o.deny(format!(
                                    "constraint: `{an}` domain {} not in mail.recipient_domains",
                                    if h.is_ascii() {
                                        h
                                    } else {
                                        "<non-ASCII>".into()
                                    }
                                ));
                            }
                            None => {
                                ok = false;
                                o.deny(format!("constraint: `{an}` has no parseable domain"));
                            }
                        }
                    }
                    if ok {
                        o.vouched.insert(an.clone());
                    }
                }
            }
            "mail.recipients" => mail_recipients(&mut o, val, args, def),
            "idp.users" | "mail.query" | "repo.numbers" | "repo.permissions" | "chat.channels"
            | "idp.groups" | "db.tenants" | "deploy.regions" | "deploy.builds"
            | "amount.currency" => {
                let allowed = list(val);
                let targets: Vec<(&String, &Value)> = by_names(k);
                if allowed
                    .iter()
                    .any(|a| a.as_str().is_some_and(|s| s.starts_with('$')))
                {
                    if !targets.is_empty() {
                        o.escalate(format!(
                            "constraint: `{k}` uses a context binding the Edge cannot resolve yet"
                        ));
                    }
                    continue;
                }
                let norm = |v: &Value| match v {
                    Value::String(s) => {
                        Value::String(if k.starts_with("mail.") || k == "amount.currency" {
                            s.trim().to_lowercase()
                        } else {
                            s.trim().to_string()
                        })
                    }
                    Value::Number(n) => n
                        .as_f64()
                        .map(|f| serde_json::json!(f))
                        .unwrap_or(v.clone()),
                    o => o.clone(),
                };
                let allowed: Vec<Value> = allowed.iter().map(norm).collect();
                for (an, v) in targets {
                    if list(v).iter().all(|x| allowed.contains(&norm(x))) {
                        o.vouched.insert(an.clone());
                    } else {
                        o.deny(format!("constraint: `{an}` value not in {k}"));
                    }
                }
            }
            "fs.path_prefix" => {
                let prefixes = strings(val);
                for (an, v) in args_of_kind(args, def, &[ArgKind::Path]) {
                    for s in strings(v) {
                        let ok = normalise(&s).is_some_and(|n| {
                            prefixes.iter().any(|p| {
                                let p = p.trim_end_matches('/');
                                n == p || n.starts_with(&format!("{p}/"))
                            })
                        });
                        if !ok {
                            o.deny(format!("constraint: `{an}` outside fs.path_prefix"));
                        }
                    }
                }
            }
            "repo.branches" => {
                let pats = strings(val);
                for (an, v) in args_of_kind(args, def, &[ArgKind::Branch]) {
                    if strings(v).iter().all(|s| pats.iter().any(|p| glob(p, s))) {
                        o.vouched.insert(an.clone());
                    } else {
                        o.deny(format!("constraint: `{an}` not matched by repo.branches"));
                    }
                }
            }
            "untainted_args" => {
                for an in strings(val) {
                    if argmap.contains_key(&an) && tainted(&an) {
                        o.deny(format!("constraint: `{an}` must be untainted but was copied from untrusted output"));
                    }
                }
            }
            "requires_approval" if val.as_bool() == Some(true) => {
                o.escalate("constraint: scope requires approval".into())
            }
            _ => o.escalate(format!("constraint: unsupported key `{k}` (fail closed)")),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn vt(c: Value, a: Value, t: &[&str]) -> Verdict {
        let mut b = baseline(&a, None);
        let tl: Vec<String> = t.iter().map(|s| s.to_string()).collect();
        let e = eval(&c, &a, None, &|x| tl.iter().any(|y| y == x));
        b.verdict = b.verdict.max(e.verdict);
        b.verdict
    }
    fn v(c: Value, a: Value) -> Verdict {
        vt(c, a, &[])
    }
    #[test]
    fn vocabulary_is_complete() {
        for k in VOCABULARY {
            let r = eval(&json!({*k: []}), &json!({}), None, &|_| false);
            assert!(!r.reasons.iter().any(|x| x.contains("unsupported")), "{k}");
        }
        assert_eq!(v(json!({"frobnicate": 1}), json!({})), Verdict::Escalate);
    }
    #[test]
    fn domains() {
        let c = json!({"mail.recipient_domains": ["acme.example"]});
        assert_eq!(
            v(c.clone(), json!({"to": "bob@acme.example"})),
            Verdict::Pass
        );
        assert_eq!(
            v(c.clone(), json!({"to": "bob@eu.acme.example"})),
            Verdict::Pass
        );
        assert_eq!(v(c.clone(), json!({"to": "x@evil.example"})), Verdict::Deny);
        assert_eq!(
            v(c.clone(), json!({"to": "x@acme.example.evil.example"})),
            Verdict::Deny
        );
        assert_eq!(
            v(c.clone(), json!({"to": "x@notacme.example"})),
            Verdict::Deny
        );
        assert_eq!(
            v(c.clone(), json!({"to": "ops@acm\u{043e}.example"})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "bob@acme.example", "bcc": "a@relay.example"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(c.clone(), json!({"email": "a@relay.example"})),
            Verdict::Deny
        );
        assert_eq!(
            v(c, json!({"to": ["bob@acme.example", "a@relay.example"]})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"mail.recipients": ["$ticket.requester"]}),
                json!({"to": "a@b.example"})
            ),
            Verdict::Escalate
        );
        assert_eq!(
            v(
                json!({"mail.recipients": ["A@b.example"]}),
                json!({"to": "a@b.example"})
            ),
            Verdict::Pass
        );
    }
    #[test]
    fn recipients_fail_closed() {
        let c = json!({"mail.recipients": ["req@c.example"]});
        assert_eq!(v(c.clone(), json!({"to": " REQ@c.example"})), Verdict::Pass);
        assert_eq!(v(c.clone(), json!({"body": "hi"})), Verdict::Escalate);
        assert_eq!(v(c.clone(), json!({})), Verdict::Escalate);
        assert_eq!(v(c.clone(), json!({"to": []})), Verdict::Escalate);
        assert_eq!(
            v(c.clone(), json!({"address": "req@c.example"})),
            Verdict::Escalate
        );
        assert_eq!(
            v(c.clone(), json!({"target": "x@evil.example"})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "req@c.example", "forward_to": "x@evil.example"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "req@c.example", "forward_to": "req@c.example"})
            ),
            Verdict::Escalate
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "req@c.example", "body": "cc x@evil.example"})
            ),
            Verdict::Pass
        );
        assert_eq!(
            v(c, json!({"to": "req@c.example", "from": "s@acme.example"})),
            Verdict::Deny
        );
        assert!(address_tokens("Bob <B@X.example>, mailto:c@y.example").len() == 2);
        assert!(address_tokens("https://user@host/x").is_empty());
        assert!(address_tokens("no address here @ all").is_empty());
    }
    #[test]
    fn domains_fail_closed() {
        let c = json!({"mail.recipient_domains": ["acme.example"]});
        assert_eq!(v(c.clone(), json!({"to": "a@acme.example"})), Verdict::Pass);
        assert_eq!(v(c.clone(), json!({"body": "hi"})), Verdict::Escalate);
        assert_eq!(v(c.clone(), json!({})), Verdict::Escalate);
        assert_eq!(v(c.clone(), json!({"to": []})), Verdict::Escalate);
        assert_eq!(v(c.clone(), json!({"to": null})), Verdict::Escalate);
        assert_eq!(
            v(c.clone(), json!({"address": "a@acme.example"})),
            Verdict::Escalate
        );
        assert_eq!(
            v(c.clone(), json!({"target": "x@evil.example"})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "a@acme.example", "forward_to": "x@evil.example"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "a@acme.example", "forward_to": "b@eu.acme.example"})
            ),
            Verdict::Escalate
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"to": "a@acme.example", "body": "cc x@evil.example"})
            ),
            Verdict::Pass
        );
        assert_eq!(
            v(c, json!({"to": "a@acme.example", "from": "s@evil.example"})),
            Verdict::Deny
        );
    }
    #[test]
    fn amounts() {
        let c = json!({"amount.max": 40.0, "amount.currency": "INR"});
        assert_eq!(
            v(c.clone(), json!({"amount": 40, "currency": "INR"})),
            Verdict::Pass
        );
        assert_eq!(
            v(c.clone(), json!({"amount": "40.00", "currency": "inr"})),
            Verdict::Pass
        );
        assert_eq!(
            v(c.clone(), json!({"amount": 40.01, "currency": "INR"})),
            Verdict::Deny
        );
        assert_eq!(
            v(c.clone(), json!({"amount": 10, "currency": "USD"})),
            Verdict::Deny
        );
        assert_eq!(v(c.clone(), json!({"amount": -5})), Verdict::Deny);
        assert_eq!(v(c, json!({"amount": "lots"})), Verdict::Deny);
    }
    #[test]
    fn commands() {
        let c = json!({"shell.cmd_prefix": ["pytest"]});
        assert_eq!(v(c.clone(), json!({"cmd": "pytest -q"})), Verdict::Pass);
        assert_eq!(v(c.clone(), json!({"cmd": "pytestx"})), Verdict::Deny);
        assert_eq!(
            v(c.clone(), json!({"cmd": "pytest; curl evil"})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"cmd": "pytest $(cat ~/.aws/credentials)"})
            ),
            Verdict::Deny
        );
        assert_eq!(v(c, json!({"cmd": "curl https://x"})), Verdict::Deny);
    }
    #[test]
    fn branches_paths() {
        assert_eq!(
            v(
                json!({"repo.branches": ["feature/*"]}),
                json!({"branch": "feature/x"})
            ),
            Verdict::Pass
        );
        assert_eq!(
            v(
                json!({"repo.branches": ["feature/*"]}),
                json!({"base": "main"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"repo.branches": ["feature/*"]}),
                json!({"branch": "feature/x/y"})
            ),
            Verdict::Deny
        );
        let p = json!({"fs.path_prefix": "/app/docs/"});
        assert_eq!(
            v(p.clone(), json!({"path": "/app/docs/a.md"})),
            Verdict::Pass
        );
        assert_eq!(
            v(p.clone(), json!({"path": "/app/docsx/a.md"})),
            Verdict::Deny
        );
        assert_eq!(v(p.clone(), json!({"path": "/etc/passwd"})), Verdict::Deny);
        assert_eq!(
            v(p, json!({"path": "/app/docs/../../etc/x"})),
            Verdict::Deny
        );
        assert_eq!(v(json!({}), json!({"path": "../../etc/x"})), Verdict::Deny);
    }
    #[test]
    fn sql_constraints() {
        let c = json!({"sql.statement_types": ["SELECT"]});
        assert_eq!(v(c.clone(), json!({"sql": "SELECT 1"})), Verdict::Pass);
        assert_eq!(
            v(c.clone(), json!({"sql": "SELECT 1; TRUNCATE audit"})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                c.clone(),
                json!({"sql": "WITH x AS (DELETE FROM o RETURNING id) SELECT * FROM x"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"sql.tables": ["users"]}),
                json!({"sql": "UPDATE settings SET a=1"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"sql.tables": ["users"]}),
                json!({"sql": "SELECT * FROM users u JOIN orders o ON u.id=o.uid"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"sql.tables": ["users", "orders"]}),
                json!({"sql": "SELECT * FROM users u JOIN orders o ON u.id=o.uid"})
            ),
            Verdict::Pass
        );
        let d = eval(
            &json!({"sql.statement_types": ["DROP"]}),
            &json!({"sql": "DROP TABLE t"}),
            None,
            &|_| false,
        );
        assert!(d.ddl_ok && d.verdict == Verdict::Pass);
        let d = eval(
            &json!({"sql.statement_types": ["DROP"]}),
            &json!({"sql": "TRUNCATE t"}),
            None,
            &|_| false,
        );
        assert!(!d.ddl_ok && d.verdict == Verdict::Deny);
    }
    #[test]
    fn allowlists_bindings_taint() {
        assert_eq!(
            v(
                json!({"idp.groups": ["engineering"]}),
                json!({"user": "a", "group": "engineering"})
            ),
            Verdict::Pass
        );
        assert_eq!(
            v(
                json!({"idp.groups": ["engineering"]}),
                json!({"group": "super-admins"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(json!({"repo.numbers": [77]}), json!({"pr": 78})),
            Verdict::Deny
        );
        assert_eq!(
            v(json!({"repo.numbers": [77]}), json!({"pr": 77})),
            Verdict::Pass
        );
        assert_eq!(
            v(
                json!({"deploy.regions": ["ap-1"]}),
                json!({"regions": ["*"]})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"chat.channels": ["#exec"]}),
                json!({"channel": "#general"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(json!({"db.tenants": ["a"]}), json!({"tenant": "b"})),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"mail.query": ["is:unread"]}),
                json!({"q": "in:anywhere"})
            ),
            Verdict::Deny
        );
        assert_eq!(
            v(
                json!({"idp.users": ["$ticket.requester"]}),
                json!({"user": "ceo"})
            ),
            Verdict::Escalate
        );
        assert_eq!(
            vt(
                json!({"untainted_args": ["cmd"]}),
                json!({"cmd": "x"}),
                &["cmd"]
            ),
            Verdict::Deny
        );
        assert_eq!(
            vt(json!({"untainted_args": ["cmd"]}), json!({"cmd": "x"}), &[]),
            Verdict::Pass
        );
        assert_eq!(v(json!({"max_rows": 10}), json!({})), Verdict::Pass);
    }
}
