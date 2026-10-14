//! `sentryra-edge mandate new` end to end: build + sign from YAML/JSON specs, then decide through
//! `serve`. Default recipients bind to the signed `ticket.requester`; explicit lists override; the
//! `recipients: escalate` opt-out holds every send. Context values never appear on stdout/stderr.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sentryra-edge");
const SECRET: &str = "requester-7f3a@cust.example";

fn run(args: &[&str]) -> (bool, String, String) {
    let o = Command::new(BIN).args(args).output().unwrap();
    (
        o.status.success(),
        String::from_utf8(o.stdout).unwrap(),
        String::from_utf8(o.stderr).unwrap(),
    )
}

fn http(port: u16, body: &str) -> serde_json::Value {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "POST /v1/decide HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut r = String::new();
    s.read_to_string(&mut r).unwrap();
    assert_eq!(&r[9..12], "200", "{r}");
    serde_json::from_str(r.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

struct Srv(Child);
impl Drop for Srv {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn setup(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let d = std::env::temp_dir().join(format!("edge-mnew-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let keys = d.join("keys");
    assert!(run(&["keygen", keys.to_str().unwrap()]).0);
    let cat = d.join("catalogue.json");
    std::fs::write(&cat, serde_json::json!({"spec":"sentryra.connector/v0","connector":"support","version":"0.0.1","tools":[
        {"name":"ticket.read","resource_template":"tickets","consequential":false,"output_trust":"untrusted","sink_args":[],"side_effect_class":"read"},
        {"name":"mail.send","resource_template":"mail","consequential":true,"output_trust":"trusted","sink_args":["to"],"side_effect_class":"external_send",
         "args":{"to":"email","body":"text"}}]}).to_string()).unwrap();
    assert!(
        run(&[
            "sign-catalogue",
            keys.to_str().unwrap(),
            cat.to_str().unwrap()
        ])
        .0
    );
    (d, keys, cat)
}

fn build(keys: &Path, cat: &Path, spec: &Path) -> String {
    let (ok, out, err) = run(&[
        "mandate",
        "new",
        keys.to_str().unwrap(),
        spec.to_str().unwrap(),
        "--catalogue",
        cat.to_str().unwrap(),
    ]);
    assert!(ok, "{err}");
    assert!(
        !out.contains(SECRET) && !err.contains(SECRET),
        "context value leaked"
    );
    assert!(err.contains("ticket.requester"), "{err}");
    out.trim().to_string()
}

fn yaml(recipients: &str) -> String {
    format!("tenant: t\nprincipal: p@acme.example\nagent: support-bot\npurpose: Reply to the customer\nttl: 1h\ncontext:\n  ticket.requester: {SECRET}\ntools:\n  - tool: ticket.read\n  - tool: mail.send\n{recipients}")
}

#[test]
fn mandate_new_recipients_end_to_end() {
    let (d, keys, cat) = setup("e2e");
    let s_default = d.join("default.yaml");
    std::fs::write(&s_default, yaml("")).unwrap();
    let s_explicit = d.join("explicit.json");
    std::fs::write(
        &s_explicit,
        serde_json::json!({"tenant":"t","principal":"p@acme.example","agent":"support-bot",
        "purpose":"Reply","context":{"ticket":{"requester":SECRET}},
        "tools":[{"tool":"mail.send","recipients":["ops@acme.example"]}]})
        .to_string(),
    )
    .unwrap();
    let s_opt = d.join("optout.yml");
    std::fs::write(
        &s_opt,
        yaml("    recipients: escalate\n    approvers: [lead@acme.example]\n"),
    )
    .unwrap();
    let t_default = build(&keys, &cat, &s_default);
    let t_explicit = build(&keys, &cat, &s_explicit);
    let t_opt = build(&keys, &cat, &s_opt);

    let port = 18900 + (std::process::id() % 500) as u16;
    let addr = format!("127.0.0.1:{port}");
    let _srv = Srv(Command::new(BIN)
        .args([
            "serve",
            keys.to_str().unwrap(),
            "--catalogue",
            cat.to_str().unwrap(),
            "--addr",
            &addr,
            "--no-evidence",
        ])
        .stderr(Stdio::null())
        .spawn()
        .unwrap());
    for _ in 0..200 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let send = |tok: &str, to: &str| {
        http(
            port,
            &serde_json::json!({"mandate": tok, "tool": "mail.send",
            "args": {"to": to, "body": "Thanks, fixed."}, "context": {"session_id": "s1"}})
            .to_string(),
        )["decision"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(send(&t_default, SECRET), "allow");
    assert_eq!(send(&t_default, "attacker@evil.example"), "deny");
    assert_eq!(send(&t_explicit, "ops@acme.example"), "allow");
    assert_eq!(send(&t_explicit, SECRET), "deny");
    assert_eq!(send(&t_opt, SECRET), "escalate");
    assert_eq!(send(&t_opt, "ops@acme.example"), "escalate");
}

#[test]
fn mandate_new_rejects_bad_input_without_leaking() {
    let (d, keys, cat) = setup("bad");
    let s = d.join("bad.yaml");
    std::fs::write(&s, yaml("    recipients: escalate\n")).unwrap(); // no approvers
    let (ok, out, err) = run(&[
        "mandate",
        "new",
        keys.to_str().unwrap(),
        s.to_str().unwrap(),
        "--catalogue",
        cat.to_str().unwrap(),
    ]);
    assert!(!ok && out.is_empty() && err.contains("approvers"), "{err}");
    assert!(!err.contains(SECRET));
    // unsigned catalogue is refused
    std::fs::write(format!("{}.sig", cat.display()), "00".repeat(64)).unwrap();
    std::fs::write(&s, yaml("")).unwrap();
    let (ok, _, err) = run(&[
        "mandate",
        "new",
        keys.to_str().unwrap(),
        s.to_str().unwrap(),
        "--catalogue",
        cat.to_str().unwrap(),
    ]);
    assert!(!ok && err.contains("does not verify"), "{err}");
}
