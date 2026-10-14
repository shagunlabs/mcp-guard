//! `sentryra-edge mandate new`: build a signed mandate from a small YAML/JSON spec.
//!
//! Recipient default: when the spec signs a `ticket.requester` context field, every
//! `external_send` tool scope without its own recipient rule gets
//! `mail.recipients: ["$ticket.requester"]` (resolved by the Edge from the signed context).
//! Override per tool with `recipients: [..]` (explicit allowlist) or `recipients: escalate`
//! (opt-out: every send through that scope is held for approval). Context VALUES are never
//! printed or logged; summaries name context keys only.
use sentryra_mandate::{Effect, Mandate, Scope, SPEC_ID};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const REQUESTER: &str = "ticket.requester";
pub const REQUESTER_BINDING: &str = "$ticket.requester";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    #[serde(default)]
    pub mandate_id: Option<String>,
    pub tenant: String,
    pub principal: String,
    pub agent: String,
    pub purpose: String,
    /// Validity from now, e.g. `30m`, `8h`, `2d` (default `8h`). Ignored if `expires_at` is set.
    #[serde(default)]
    pub ttl: Option<String>,
    #[serde(default)]
    pub not_before: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Signed trusted context (flat dotted keys or nested objects).
    #[serde(default)]
    pub context: Map<String, Value>,
    pub tools: Vec<ToolSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSpec {
    pub tool: String,
    #[serde(default = "star")]
    pub resource: String,
    #[serde(default = "allow")]
    pub effect: Effect,
    #[serde(default)]
    pub approvers: Vec<String>,
    /// Side-effect class; if absent, taken from `--catalogue` (signed manifest) when given.
    #[serde(default)]
    pub class: Option<String>,
    #[serde(default)]
    pub recipients: Option<Recipients>,
    #[serde(default)]
    pub constraints: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Recipients {
    List(Vec<String>),
    Mode(String),
}

fn star() -> String {
    "*".into()
}
fn allow() -> Effect {
    Effect::Allow
}

/// What the builder decided for each scope (no context values).
#[derive(Debug, PartialEq, Eq)]
pub enum RecipientRule {
    NotASend,
    Defaulted,
    Explicit,
    FromConstraints,
    EscalateAll,
    /// external_send with no recipient rule and no requester context: left to other constraints.
    None,
}

pub fn parse_spec(text: &str, is_yaml: bool) -> Result<Spec, String> {
    if is_yaml {
        serde_yaml::from_str(text).map_err(|e| format!("spec: {}", redact(&e.to_string())))
    } else {
        serde_json::from_str(text).map_err(|e| format!("spec: {}", redact(&e.to_string())))
    }
}

/// Parser messages can quote input; keep only the position/kind, never spec values.
fn redact(e: &str) -> String {
    match (e.find(" at line "), e.find(':')) {
        (Some(i), _) => format!("invalid spec{}", &e[i..]),
        (None, Some(i)) => format!("invalid spec ({})", &e[..i]),
        _ => "invalid spec".into(),
    }
}

fn has_context_key(ctx: &Map<String, Value>, dotted: &str) -> bool {
    if ctx.get(dotted).is_some_and(|v| !v.is_null()) {
        return true;
    }
    let mut cur = Value::Object(ctx.clone());
    for p in dotted.split('.') {
        match cur.get(p) {
            Some(v) => cur = v.clone(),
            None => return false,
        }
    }
    !cur.is_null()
}

fn context_keys(ctx: &Map<String, Value>, prefix: &str, out: &mut Vec<String>) {
    for (k, v) in ctx {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            Value::Object(m) => context_keys(m, &key, out),
            _ => out.push(key),
        }
    }
}

fn ttl_secs(s: &str) -> Result<u64, String> {
    let (n, u) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = n
        .parse()
        .map_err(|_| format!("bad ttl `{s}` (use e.g. 30m, 8h, 2d)"))?;
    let m = match u {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err(format!("bad ttl `{s}` (use e.g. 30m, 8h, 2d)")),
    };
    if n == 0 || n * m > 30 * 86400 {
        return Err("ttl must be between 1s and 30d".into());
    }
    Ok(n * m)
}

pub fn rfc3339(secs: u64) -> String {
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

/// Build (unsigned) mandate. `classes`: tool name -> side_effect_class from a signed catalogue.
/// `now`: unix seconds. Returns the mandate plus one rule per scope (same order).
pub fn build(
    spec: Spec,
    classes: &BTreeMap<String, String>,
    now: u64,
) -> Result<(Mandate, Vec<(String, RecipientRule)>), String> {
    if spec.tools.is_empty() {
        return Err("spec: `tools` is empty".into());
    }
    let has_req = has_context_key(&spec.context, REQUESTER);
    let mut scopes = vec![];
    let mut rules = vec![];
    for t in spec.tools {
        let class = t.class.clone().or_else(|| classes.get(&t.tool).cloned());
        let is_send = class.as_deref() == Some("external_send");
        let mut c = t.constraints.clone().unwrap_or_default();
        let mut effect = t.effect;
        let has_rule =
            c.contains_key("mail.recipients") || c.contains_key("mail.recipient_domains");
        let rule = match (&t.recipients, is_send) {
            (Some(_), false) => {
                return Err(format!(
                    "tool `{}`: `recipients` is only valid for external_send tools (set `class: external_send` or pass --catalogue)",
                    t.tool
                ))
            }
            (Some(_), true) if has_rule => {
                return Err(format!(
                    "tool `{}`: give `recipients` or a mail.recipients/mail.recipient_domains constraint, not both",
                    t.tool
                ))
            }
            (Some(Recipients::List(l)), true) => {
                if l.is_empty() {
                    return Err(format!(
                        "tool `{}`: empty recipients list (use `recipients: escalate` to hold every send)",
                        t.tool
                    ));
                }
                if l.iter().any(|r| r == REQUESTER_BINDING) && !has_req {
                    return Err(format!(
                        "tool `{}`: recipients uses {REQUESTER_BINDING} but the spec has no {REQUESTER} context",
                        t.tool
                    ));
                }
                c.insert("mail.recipients".into(), json!(l));
                RecipientRule::Explicit
            }
            (Some(Recipients::Mode(m)), true) if m == "escalate" => {
                if effect == Effect::Deny {
                    return Err(format!("tool `{}`: recipients: escalate on a deny scope", t.tool));
                }
                if t.approvers.is_empty() {
                    return Err(format!(
                        "tool `{}`: recipients: escalate needs `approvers`",
                        t.tool
                    ));
                }
                effect = Effect::Escalate;
                RecipientRule::EscalateAll
            }
            (Some(Recipients::Mode(m)), true) => {
                return Err(format!(
                    "tool `{}`: unknown recipients mode `{m}` (a list, or `escalate`)",
                    t.tool
                ))
            }
            (None, false) => RecipientRule::NotASend,
            (None, true) if has_rule => RecipientRule::FromConstraints,
            (None, true) if has_req => {
                c.insert("mail.recipients".into(), json!([REQUESTER_BINDING]));
                RecipientRule::Defaulted
            }
            (None, true) => RecipientRule::None,
        };
        rules.push((t.tool.clone(), rule));
        scopes.push(Scope {
            tool: t.tool,
            resource: t.resource,
            effect,
            approvers: t.approvers,
            constraints: if c.is_empty() {
                None
            } else {
                Some(Value::Object(c))
            },
        });
    }
    let nbf = spec
        .not_before
        .unwrap_or_else(|| rfc3339(now.saturating_sub(60)));
    let exp = match (spec.expires_at, spec.ttl) {
        (Some(e), _) => e,
        (None, t) => rfc3339(now + ttl_secs(t.as_deref().unwrap_or("8h"))?),
    };
    let id = spec.mandate_id.unwrap_or_else(|| {
        let mut b = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        format!("mdt_{}", hex::encode(b))
    });
    let m = Mandate {
        mandate_id: id,
        spec: SPEC_ID.into(),
        tenant: spec.tenant,
        principal: json!({"id": spec.principal}),
        agent: json!({"id": spec.agent}),
        purpose: spec.purpose,
        scopes,
        default_effect: Effect::Deny,
        not_before: nbf,
        expires_at: exp,
        context: spec.context,
    };
    m.validate().map_err(|e| format!("mandate: {e:?}"))?;
    Ok((m, rules))
}

/// Human summary for stderr: ids, scopes, context KEYS only (never values).
pub fn summary(m: &Mandate, rules: &[(String, RecipientRule)]) -> String {
    let mut keys = vec![];
    context_keys(&m.context, "", &mut keys);
    let mut s = format!(
        "mandate {}: {} scope(s), valid {} .. {}, signed context keys: [{}]\n",
        m.mandate_id,
        m.scopes.len(),
        m.not_before,
        m.expires_at,
        keys.join(", ")
    );
    for (tool, r) in rules {
        let what = match r {
            RecipientRule::NotASend => continue,
            RecipientRule::Defaulted => "mail.recipients defaulted to [$ticket.requester]",
            RecipientRule::Explicit => "explicit recipients",
            RecipientRule::FromConstraints => "recipients from constraints",
            RecipientRule::EscalateAll => "recipients opt-out: every send escalates",
            RecipientRule::None => {
                "WARNING: external_send with no recipient rule (no ticket.requester context)"
            }
        };
        s.push_str(&format!("  {tool}: {what}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: u64 = 1_790_000_000;

    fn spec(extra_tool: &str, ctx: &str) -> Spec {
        let t = format!(
            r#"{{"tenant":"t","principal":"p@x","agent":"a","purpose":"reply","context":{ctx},
            "tools":[{{"tool":"ticket.read"}},{extra_tool}]}}"#
        );
        parse_spec(&t, false).unwrap()
    }
    fn send_scope(m: &Mandate) -> &Scope {
        m.scopes.iter().find(|s| s.tool == "mail.send").unwrap()
    }
    const REQ: &str = r#"{"ticket.requester":"secret-req@cust.example"}"#;

    #[test]
    fn defaults_to_requester_binding() {
        let (m, r) = build(
            spec(r#"{"tool":"mail.send","class":"external_send"}"#, REQ),
            &BTreeMap::new(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            send_scope(&m).constraints,
            Some(json!({"mail.recipients": ["$ticket.requester"]}))
        );
        assert_eq!(r[1].1, RecipientRule::Defaulted);
        assert_eq!(r[0].1, RecipientRule::NotASend);
        assert!(m.scopes[0].constraints.is_none());
    }
    #[test]
    fn class_from_catalogue_and_nested_context() {
        let cls = BTreeMap::from([("mail.send".to_string(), "external_send".to_string())]);
        let (m, _) = build(
            spec(
                r#"{"tool":"mail.send"}"#,
                r#"{"ticket":{"requester":"r@x"}}"#,
            ),
            &cls,
            NOW,
        )
        .unwrap();
        assert_eq!(
            send_scope(&m).constraints,
            Some(json!({"mail.recipients": ["$ticket.requester"]}))
        );
    }
    #[test]
    fn no_default_without_requester_context_or_send_class() {
        let (m, r) = build(
            spec(r#"{"tool":"mail.send","class":"external_send"}"#, "{}"),
            &BTreeMap::new(),
            NOW,
        )
        .unwrap();
        assert!(send_scope(&m).constraints.is_none());
        assert_eq!(r[1].1, RecipientRule::None);
        let (m, _) = build(spec(r#"{"tool":"mail.send"}"#, REQ), &BTreeMap::new(), NOW).unwrap();
        assert!(send_scope(&m).constraints.is_none());
    }
    #[test]
    fn explicit_recipients_override() {
        let (m, r) = build(
            spec(
                r#"{"tool":"mail.send","class":"external_send","recipients":["ops@acme.example"]}"#,
                REQ,
            ),
            &BTreeMap::new(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            send_scope(&m).constraints,
            Some(json!({"mail.recipients": ["ops@acme.example"]}))
        );
        assert_eq!(r[1].1, RecipientRule::Explicit);
        // an explicit constraint also wins over the default
        let (m, r) = build(
            spec(
                r#"{"tool":"mail.send","class":"external_send","constraints":{"mail.recipient_domains":["cust.example"]}}"#,
                REQ,
            ),
            &BTreeMap::new(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            send_scope(&m).constraints,
            Some(json!({"mail.recipient_domains": ["cust.example"]}))
        );
        assert_eq!(r[1].1, RecipientRule::FromConstraints);
    }
    #[test]
    fn opt_out_escalates_all_sends() {
        let (m, r) = build(
            spec(
                r#"{"tool":"mail.send","class":"external_send","recipients":"escalate","approvers":["lead@acme.example"]}"#,
                REQ,
            ),
            &BTreeMap::new(),
            NOW,
        )
        .unwrap();
        let s = send_scope(&m);
        assert_eq!(s.effect, Effect::Escalate);
        assert!(s.constraints.is_none());
        assert_eq!(r[1].1, RecipientRule::EscalateAll);
        let e = build(
            spec(
                r#"{"tool":"mail.send","class":"external_send","recipients":"escalate"}"#,
                REQ,
            ),
            &BTreeMap::new(),
            NOW,
        )
        .unwrap_err();
        assert!(e.contains("approvers"), "{e}");
    }
    #[test]
    fn rejects_bad_specs() {
        let b = |t: &str, c: &str| build(spec(t, c), &BTreeMap::new(), NOW).unwrap_err();
        assert!(b(r#"{"tool":"mail.send","recipients":["a@x"]}"#, REQ).contains("only valid"));
        assert!(b(
            r#"{"tool":"mail.send","class":"external_send","recipients":[]}"#,
            REQ
        )
        .contains("empty"));
        assert!(b(
            r#"{"tool":"mail.send","class":"external_send","recipients":"nobody"}"#,
            REQ
        )
        .contains("unknown recipients mode"));
        assert!(b(
            r#"{"tool":"mail.send","class":"external_send","recipients":["$ticket.requester"]}"#,
            "{}"
        )
        .contains("no ticket.requester"));
        assert!(b(
            r#"{"tool":"mail.send","class":"external_send","recipients":["a@x"],"constraints":{"mail.recipients":["b@x"]}}"#,
            REQ
        )
        .contains("not both"));
        assert!(parse_spec(r#"{"tenant":"t","bogus":1}"#, false).is_err());
    }
    #[test]
    fn times_and_ttl() {
        let mut s = spec(r#"{"tool":"mail.send"}"#, "{}");
        s.ttl = Some("2h".into());
        let (m, _) = build(s, &BTreeMap::new(), NOW).unwrap();
        assert_eq!(m.not_before, rfc3339(NOW - 60));
        assert_eq!(m.expires_at, rfc3339(NOW + 7200));
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert!(ttl_secs("31d").is_err() && ttl_secs("x").is_err() && ttl_secs("0h").is_err());
    }
    #[test]
    fn yaml_spec_and_summary_never_has_context_values() {
        let y = "tenant: t\nprincipal: p@x\nagent: a\npurpose: reply\ncontext:\n  ticket.requester: secret-req@cust.example\n  session: {user: hidden-user}\ntools:\n  - tool: mail.send\n    class: external_send\n";
        let (m, r) = build(parse_spec(y, true).unwrap(), &BTreeMap::new(), NOW).unwrap();
        let s = summary(&m, &r);
        assert!(
            s.contains("ticket.requester") && s.contains("session.user"),
            "{s}"
        );
        assert!(
            !s.contains("secret-req") && !s.contains("hidden-user"),
            "{s}"
        );
        assert!(s.contains("defaulted"));
    }
    #[test]
    fn parse_errors_do_not_echo_values() {
        let e = parse_spec(
            r#"{"tenant":"t","principal":"p","agent":"a","purpose":"x","context":{"ticket.requester":"leak@x"},"tools":"leak@x"}"#,
            false,
        )
        .unwrap_err();
        assert!(!e.contains("leak@x"), "{e}");
        let e = parse_spec(
            "tenant: t\ncontext:\n  ticket.requester: leak@x\ntools: leak@x\n",
            true,
        )
        .unwrap_err();
        assert!(!e.contains("leak@x"), "{e}");
    }
}
