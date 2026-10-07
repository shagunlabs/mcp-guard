//! Minimal stdio MCP proxy: sits between an MCP client (agent) and an MCP server.
//! Every `tools/call` is decided by Tier 1 first; results from untrusted tools are fingerprinted for taint.
use sentryra_pdp::{DecideRequest, Engine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

fn text_of(result: &Value) -> String {
    result
        .get("content")
        .and_then(|c| c.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

type Inflight = Arc<Mutex<HashMap<String, (String, Option<usize>)>>>;

/// Enforce a `row_cap` obligation on a tools/call result: every text part that is a JSON array (or
/// an object with a `rows` array) is truncated to `cap` rows; non-JSON text is truncated to `cap`
/// non-empty lines. Returns true if anything was cut. The cut is flagged in `_meta`.
pub fn apply_row_cap(result: &mut Value, cap: usize) -> bool {
    let mut cut = false;
    if let Some(parts) = result.get_mut("content").and_then(|c| c.as_array_mut()) {
        for p in parts.iter_mut() {
            let Some(t) = p.get("text").and_then(|t| t.as_str()).map(String::from) else {
                continue;
            };
            let new = match serde_json::from_str::<Value>(&t) {
                Ok(Value::Array(mut a)) if a.len() > cap => {
                    a.truncate(cap);
                    Some(Value::Array(a).to_string())
                }
                Ok(Value::Object(mut o))
                    if o.get("rows")
                        .and_then(|r| r.as_array())
                        .is_some_and(|r| r.len() > cap) =>
                {
                    if let Some(Value::Array(r)) = o.get_mut("rows") {
                        r.truncate(cap);
                    }
                    Some(Value::Object(o).to_string())
                }
                Ok(_) => None,
                Err(_) => {
                    let lines: Vec<&str> = t.lines().filter(|l| !l.trim().is_empty()).collect();
                    (lines.len() > cap).then(|| lines[..cap].join("\n"))
                }
            };
            if let Some(n) = new {
                p["text"] = Value::String(n);
                cut = true;
            }
        }
    }
    // Always annotate when a cap applied, so clients/auditors can see it was enforced.
    if result.is_object() {
        result["_meta"]["com.sentryra/row_cap"] = json!({"cap": cap, "truncated": cut});
    }
    cut
}

pub fn run(
    e: Arc<Engine>,
    mandate: String,
    context: Option<sentryra_pdp::bindings::Context>,
    cmd: &[String],
) -> i32 {
    let mut child = match Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(x) => {
            eprintln!("cannot start MCP server: {x}");
            return 2;
        }
    };
    let mut to_server = child.stdin.take().unwrap();
    let from_server = BufReader::new(child.stdout.take().unwrap());
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let inflight: Inflight = Arc::default();

    let (e2, out2, inf2) = (e.clone(), out.clone(), inflight.clone());
    let (m2, c2) = (mandate.clone(), context.clone());
    let reader = std::thread::spawn(move || {
        for line in from_server.lines().map_while(Result::ok) {
            let mut line = line;
            if let Ok(mut v) = serde_json::from_str::<Value>(&line) {
                let id = v.get("id").map(|i| i.to_string()).unwrap_or_default();
                let entry = inf2.lock().unwrap().remove(&id);
                if let Some((tool, cap)) = entry {
                    if let (Some(cap), Some(r)) = (cap, v.get_mut("result")) {
                        apply_row_cap(r, cap);
                        line = v.to_string();
                    }
                    if let Some(r) = v.get("result") {
                        e2.observe_output_in(&m2, c2.as_ref(), &tool, &text_of(r));
                    }
                }
            }
            let mut o = out2.lock().unwrap();
            let _ = writeln!(o, "{line}").and_then(|_| o.flush());
        }
    });

    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue, // never forward unparseable frames
        };
        if v.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
            let p = v.get("params").cloned().unwrap_or_default();
            let tool = p
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args = p.get("arguments").cloned().unwrap_or(json!({}));
            let d = e.decide(&DecideRequest {
                mandate: mandate.clone(),
                tool: tool.clone(),
                args,
                now: None,
                // An approved retry carries its signed receipt in `_meta`.
                receipt: p
                    .get("_meta")
                    .and_then(|m| m.get("com.sentryra/receipt"))
                    .and_then(|r| serde_json::from_value(r.clone()).ok()),
                // host-supplied only; any `_meta` context from the agent is ignored
                context: context.clone(),
            });
            eprintln!(
                "[sentryra] {} {} -> {}{} (policies: {}) {}",
                d.decision_id,
                tool,
                d.decision.to_uppercase(),
                if d.enforced {
                    ""
                } else {
                    " [shadow: not enforced]"
                },
                d.policy_ids.join(","),
                d.reasons.join("; ")
            );
            if d.enforced && d.decision != "allow" {
                let msg = match &d.approval_link {
                    Some(link) => format!("Sentryra: pending approval, decision {}. Approver link: {link}. Retry the same call after approval.", d.decision_id),
                    None => format!("Sentryra: blocked, decision {}. Reasons: {}", d.decision_id, d.reasons.join("; ")),
                };
                let resp = json!({"jsonrpc": "2.0", "id": v.get("id"), "result": {"isError": true, "content": [{"type": "text", "text": msg}],
                    "_meta": {"com.sentryra/decision": {"decision_id": d.decision_id, "decision": d.decision}}}});
                let mut o = out.lock().unwrap();
                let _ = writeln!(o, "{resp}").and_then(|_| o.flush());
                continue;
            }
            if let Some(id) = v.get("id") {
                let cap = d
                    .obligations
                    .iter()
                    .filter_map(|o| o.strip_prefix("row_cap="))
                    .filter_map(|n| n.parse().ok())
                    .min();
                inflight.lock().unwrap().insert(id.to_string(), (tool, cap));
            }
        }
        if writeln!(to_server, "{line}")
            .and_then(|_| to_server.flush())
            .is_err()
        {
            break;
        }
    }
    drop(to_server);
    let _ = reader.join();
    child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn row_cap_truncates() {
        let mut r = json!({"content": [{"type": "text", "text": "[[1],[2],[3]]"}]});
        assert!(apply_row_cap(&mut r, 2));
        assert_eq!(r["content"][0]["text"], "[[1],[2]]");
        assert_eq!(r["_meta"]["com.sentryra/row_cap"]["truncated"], true);
        let mut r = json!({"content": [{"type": "text", "text": "a\nb\nc"}]});
        assert!(apply_row_cap(&mut r, 1));
        assert_eq!(r["content"][0]["text"], "a");
        let mut r = json!({"content": [{"type": "text", "text": "[[1]]"}]});
        assert!(!apply_row_cap(&mut r, 5));
    }
}
