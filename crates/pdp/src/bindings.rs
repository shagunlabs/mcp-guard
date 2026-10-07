//! `$name` context bindings in mandate constraints (e.g. `"idp.users": ["$ticket.requester"]`).
//!
//! Bindings resolve only from trusted sources: the signed mandate `context` (wins on conflict),
//! the host-supplied request context the Edge receives out of band (proxy `--context` /
//! `SENTRYRA_CONTEXT`, or `context` on `/v1/decide`), and the built-in `$principal.id`. Tool
//! outputs and agent arguments are never consulted. A binding that does not resolve stays `$...`
//! and the constraint evaluator escalates it (fail closed).
use serde_json::{Map, Value};

pub type Context = Map<String, Value>;

/// Merge trusted context: mandate first (signed), then host context for keys the mandate lacks.
pub fn merge(mandate: &Context, host: Option<&Context>, principal: &str) -> Context {
    let mut c = Context::new();
    if !principal.is_empty() {
        c.insert("principal.id".into(), Value::String(principal.into()));
    }
    if let Some(h) = host {
        for (k, v) in h {
            c.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in mandate {
        c.insert(k.clone(), v.clone());
    }
    c.retain(|_, v| usable(v));
    c
}

/// Only strings, numbers, and arrays of those are usable binding values.
fn usable(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.trim().is_empty() && !s.starts_with('$'),
        Value::Number(_) => true,
        Value::Array(a) => !a.is_empty() && a.iter().all(|x| usable(x) && !x.is_array()),
        _ => false,
    }
}

fn binding_name(s: &str) -> Option<&str> {
    let n = s.strip_prefix('$')?;
    (!n.is_empty()
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-'))
    .then_some(n)
}

/// Substitute resolvable bindings inside constraint allowlists. Array elements that resolve to an
/// array are spliced in. Unresolved bindings are left as-is (the evaluator escalates them).
pub fn resolve(c: &Value, ctx: &Context) -> Value {
    match c {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), resolve(v, ctx)))
                .collect(),
        ),
        Value::Array(a) => {
            let mut out = vec![];
            for x in a {
                match x.as_str().and_then(binding_name).and_then(|n| ctx.get(n)) {
                    Some(Value::Array(vs)) => out.extend(vs.iter().cloned()),
                    Some(v) => out.push(v.clone()),
                    None => out.push(resolve(x, ctx)),
                }
            }
            Value::Array(out)
        }
        Value::String(s) => match binding_name(s).and_then(|n| ctx.get(n)) {
            Some(v) => v.clone(),
            None => c.clone(),
        },
        _ => c.clone(),
    }
}

#[cfg(test)]
mod t {
    use super::*;
    use serde_json::json;
    fn ctx(v: Value) -> Context {
        v.as_object().unwrap().clone()
    }
    #[test]
    fn resolves_and_splices() {
        let c = ctx(json!({"ticket.requester": "a@x.example", "team": ["u1", "u2"]}));
        let r = resolve(
            &json!({"mail.recipients": ["$ticket.requester"], "idp.users": ["$team", "u3"]}),
            &c,
        );
        assert_eq!(
            r,
            json!({"mail.recipients": ["a@x.example"], "idp.users": ["u1", "u2", "u3"]})
        );
    }
    #[test]
    fn unresolved_left_alone() {
        let r = resolve(
            &json!({"idp.users": ["$ticket.requester"]}),
            &Context::new(),
        );
        assert_eq!(r, json!({"idp.users": ["$ticket.requester"]}));
    }
    #[test]
    fn mandate_wins_and_junk_dropped() {
        let m = ctx(json!({"ticket.requester": "signed@x"}));
        let h = ctx(
            json!({"ticket.requester": "host@x", "session.user": "s1", "bad": {"o": 1}, "loop": "$x"}),
        );
        let c = merge(&m, Some(&h), "p@x");
        assert_eq!(c["ticket.requester"], "signed@x");
        assert_eq!(c["session.user"], "s1");
        assert_eq!(c["principal.id"], "p@x");
        assert!(!c.contains_key("bad") && !c.contains_key("loop"));
    }
}
