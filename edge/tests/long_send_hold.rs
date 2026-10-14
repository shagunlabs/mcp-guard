//! LONG_SEND_HOLD end to end through `sentryra-edge serve`: an external_send after untrusted tool
//! output (ingested via /v1/outputs) whose text exceeds one Tier 2 window escalates. Same result
//! with Tier 2 off and in the score-only configuration (no-probe diagnostic, 600 s deadline).
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sentryra-edge");

fn run(args: &[&str]) -> String {
    let o = Command::new(BIN).args(args).output().unwrap();
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}

fn http(port: u16, path: &str, auth: Option<&str>, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let a = auth
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n{a}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut r = String::new();
    s.read_to_string(&mut r).unwrap();
    (
        r[9..12].parse().unwrap(),
        r.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

struct Srv(Child);
impl Drop for Srv {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn scenario(tag: &str, port: u16, extra: &[&str]) {
    let d = std::env::temp_dir().join(format!("edge-lsh-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let keys = d.join("keys");
    run(&["keygen", keys.to_str().unwrap()]);
    let cat = d.join("catalogue.json");
    std::fs::write(&cat, serde_json::json!({"spec":"sentryra.connector/v0","connector":"support","version":"0.0.1","tools":[
        {"name":"ticket.read","resource_template":"tickets","consequential":false,"output_trust":"untrusted","sink_args":[],"side_effect_class":"read"},
        {"name":"mail.send","resource_template":"mail","consequential":true,"output_trust":"trusted","sink_args":["to"],"side_effect_class":"external_send",
         "args":{"to":"email","body":"text"}}]}).to_string()).unwrap();
    run(&[
        "sign-catalogue",
        keys.to_str().unwrap(),
        cat.to_str().unwrap(),
    ]);
    let ingest = std::fs::read_to_string(keys.join("ingest.token"))
        .unwrap()
        .trim()
        .to_string();
    let m = d.join("m.json");
    std::fs::write(&m, serde_json::json!({
        "mandate_id": format!("mdt_{tag}"), "spec": "sentryra.mandate/v0", "tenant": "t", "principal": {"id": "p@x"}, "agent": {"id": "a"},
        "purpose": "Reply to the customer",
        "scopes": [{"tool": "ticket.read", "resource": "*", "effect": "allow"},
                   {"tool": "mail.send", "resource": "*", "effect": "allow", "constraints": {"mail.recipient_domains": ["cust.example"]}}],
        "default_effect": "deny", "not_before": "2020-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"}).to_string()).unwrap();
    let tok = run(&["issue", keys.to_str().unwrap(), m.to_str().unwrap()])
        .trim()
        .to_string();
    let addr = format!("127.0.0.1:{port}");
    let mut args = vec![
        "serve",
        keys.to_str().unwrap(),
        "--catalogue",
        cat.to_str().unwrap(),
        "--policies",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../policies/default.cedar"),
        "--addr",
        &addr,
        "--no-evidence",
    ];
    args.extend_from_slice(extra);
    let _srv = Srv(Command::new(BIN)
        .args(&args)
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let decide = |tool: &str, a: serde_json::Value| -> serde_json::Value {
        let b = serde_json::json!({"mandate": tok, "tool": tool, "args": a, "context": {"session_id": "s1"}});
        let (c, body) = http(port, "/v1/decide", None, &b.to_string());
        assert_eq!(c, 200, "{body}");
        serde_json::from_str(&body).unwrap()
    };
    let long = "word ".repeat(129);
    let held = |r: &serde_json::Value| {
        r["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str().unwrap().starts_with("LONG_SEND_HOLD"))
    };

    let r = decide(
        "mail.send",
        serde_json::json!({"to": "a@cust.example", "body": long}),
    );
    assert!(!held(&r), "{tag}: no untrusted output yet: {r}");
    let rd = decide("ticket.read", serde_json::json!({}));
    assert_eq!(rd["decision"], "allow", "{tag}: {rd}");
    let ob = serde_json::json!({"mandate": tok, "decision_id": rd["decision_id"], "tool": "ticket.read",
        "output": "Customer: please reply.", "context": {"session_id": "s1"}});
    let (c, b) = http(port, "/v1/outputs", Some(&ingest), &ob.to_string());
    assert!(c / 100 == 2, "{tag}: ingest {c} {b}");
    let r = decide(
        "mail.send",
        serde_json::json!({"to": "a@cust.example", "body": "word ".repeat(128)}),
    );
    assert!(!held(&r), "{tag}: one window is not long: {r}");
    let r = decide(
        "mail.send",
        serde_json::json!({"to": "a@cust.example", "body": long}),
    );
    assert_eq!(r["decision"], "escalate", "{tag}: {r}");
    assert!(held(&r), "{tag}: {r}");
    assert!(
        r["policy_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "long-send-hold"),
        "{tag}: {r}"
    );
}

#[test]
fn long_send_hold_tier1_only() {
    scenario("t1", 19400 + (std::process::id() % 400) as u16, &[]);
}

#[test]
fn long_send_hold_score_only_config() {
    // score-only pass settings (bench run.py --score-only-noprobe): 600 s deadline, no probe.
    // The scorer dir does not exist, so Tier 2 is unavailable; the hold is Tier 1 and still applies.
    let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/no-such-scorer");
    scenario(
        "so",
        19800 + (std::process::id() % 400) as u16,
        &[
            "--tier2-scorer",
            missing.to_str().unwrap(),
            "--tier2-deadline-ms",
            "600000",
            "--tier2-diagnostic-no-probe",
        ],
    );
}
