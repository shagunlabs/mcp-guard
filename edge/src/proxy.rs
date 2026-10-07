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

pub fn run(e: Arc<Engine>, mandate: String, cmd: &[String]) -> i32 {
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
    let inflight: Arc<Mutex<HashMap<String, String>>> = Arc::default();

    let (e2, out2, inf2) = (e.clone(), out.clone(), inflight.clone());
    let reader = std::thread::spawn(move || {
        for line in from_server.lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                let id = v.get("id").map(|i| i.to_string()).unwrap_or_default();
                if let Some(tool) = inf2.lock().unwrap().remove(&id) {
                    if let Some(r) = v.get("result") {
                        e2.observe_output(&tool, &text_of(r));
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
                inflight.lock().unwrap().insert(id.to_string(), tool);
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
