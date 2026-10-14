//! LONG_SEND_HOLD (Tier 1): an external_send after untrusted tool output whose outbound text is
//! longer than one Tier 2 window escalates, with Tier 2 off, on, fast or slow.
use super::*;
use biscuit_auth::KeyPair;
use ed25519_dalek::Signer;
use sentryra_mandate::Mandate;

const NOW: &str = "2026-10-07T13:00:00Z";

fn ls_engine() -> (Engine, String) {
    let root = KeyPair::new();
    let cat = SigningKey::generate(&mut rand::rngs::OsRng);
    let man = serde_json::json!({"spec":"sentryra.connector/v0","connector":"support","version":"0.0.1","tools":[
        {"name":"ticket.read","resource_template":"tickets","consequential":false,"output_trust":"untrusted","sink_args":[],"side_effect_class":"read"},
        {"name":"mail.send","resource_template":"mail","consequential":true,"output_trust":"trusted","sink_args":["to"],"side_effect_class":"external_send",
         "args":{"to":"email","body":"text","subject":"text"}},
        {"name":"doc.write","resource_template":"docs","consequential":true,"output_trust":"trusted","sink_args":[],"side_effect_class":"write",
         "args":{"body":"text"}}
    ]}).to_string().into_bytes();
    let sig = hex::encode(cat.sign(&man).to_bytes());
    let e = Engine::new(Config {
        root: root.public(),
        catalogue_key: cat.verifying_key(),
        manifests: vec![(man, sig)],
        policies: include_str!("../../../policies/default.cedar").into(),
        evidence_key: SigningKey::generate(&mut rand::rngs::OsRng),
        salt_key: b"k".to_vec(),
        mode: Mode::Enforce,
        evidence_path: None,
        edge_url: "http://edge".into(),
        revoked: Default::default(),
        approval_vk: SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
        approval_sk: Some(SigningKey::from_bytes(&[7u8; 32])),
    })
    .unwrap();
    let m = serde_json::json!({
        "mandate_id": "mdt_ls", "spec": "sentryra.mandate/v0", "tenant": "org_cust",
        "principal": {"id": "lead@acme.example"}, "agent": {"id": "agt"},
        "purpose": "Reply to the customer",
        "scopes": [
            {"tool": "ticket.read", "resource": "tickets", "effect": "allow"},
            {"tool": "mail.send", "resource": "mail", "effect": "allow",
             "constraints": {"mail.recipient_domains": ["cust.example"]}},
            {"tool": "doc.write", "resource": "docs", "effect": "allow"}
        ],
        "default_effect": "deny", "not_before": "2026-10-07T12:00:00Z", "expires_at": "2026-10-07T20:00:00Z"
    });
    let tok = token::issue(&Mandate::from_json(&m.to_string()).unwrap(), &root)
        .unwrap()
        .to_base64()
        .unwrap();
    (e, tok)
}

fn rq(tok: &str, tool: &str, args: serde_json::Value) -> DecideRequest {
    DecideRequest {
        mandate: tok.into(),
        tool: tool.into(),
        args,
        now: Some(NOW.into()),
        receipt: None,
        context: None,
    }
}

/// Fake Tier 2 sidecar: acks ingests at once and answers every score with 0.0 / no escalate after `delay_ms`.
fn quiet_t2(e: &mut Engine, delay_ms: u64, send_deadline_ms: u64) {
    use std::io::{BufRead, BufReader, Write};
    let p = std::env::temp_dir().join(format!("pdp-ls-{}-{delay_ms}.sock", std::process::id()));
    let _ = std::fs::remove_file(&p);
    let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
    std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        for line in BufReader::new(s).lines().map_while(Result::ok) {
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            if v["op"] == "ingest" {
                let _ = writeln!(
                    w,
                    "{}",
                    serde_json::json!({"ack": v["id"], "session": v["session"]})
                );
            }
            if v["op"] == "score" {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                let _ = writeln!(
                    w,
                    "{}",
                    serde_json::json!({"id": v["id"], "op": "score", "scored": true,
                    "score": 0.0, "band": "low", "escalate": false, "reason_codes": [], "windows_read": 1, "windows_total": 1})
                );
            }
        }
    });
    let s = std::os::unix::net::UnixStream::connect(&p).unwrap();
    let c = sentryra_sidecar_risk::client::Client::from_stream(
        s,
        sentryra_sidecar_risk::rules::Config {
            send_deadline_ms: Some(send_deadline_ms),
            ..Default::default()
        },
        "x".into(),
        None,
    )
    .unwrap();
    e.set_tier2(std::sync::Arc::new(c), false);
}

fn long_body() -> String {
    "word ".repeat(long_send::T2_WINDOW_TOKENS) + "more"
}
fn edge_body() -> String {
    "word ".repeat(long_send::T2_WINDOW_TOKENS) // exactly one window: not long
}
fn held(r: &DecideResponse) -> bool {
    r.reasons
        .iter()
        .any(|x| x.starts_with(long_send::REASON_CODE))
}

/// `t2_slow`: Tier 2 misses its deadline, so its own timeout rule may escalate short sends too;
/// then only the hold itself (reason + policy id) is asserted for them.
fn check(e: &Engine, t: &str, t2_slow: bool) {
    let send = |body: String| {
        e.decide(&rq(
            t,
            "mail.send",
            serde_json::json!({"to": "a@cust.example", "resource": "mail", "body": body}),
        ))
    };
    // before any untrusted output: long sends are not held
    let r = send(long_body());
    assert!(!held(&r), "{:?}", r.reasons);
    if !t2_slow {
        assert_eq!(r.decision, "allow", "{:?}", r.reasons);
    }
    e.observe_output_at(
        t,
        None,
        "ticket.read",
        "Customer says: please reply soon.",
        Some(NOW),
    );
    let r = send(edge_body());
    assert!(!held(&r), "one window is not long: {:?}", r.reasons);
    if !t2_slow {
        assert_eq!(r.decision, "allow", "{:?}", r.reasons);
    }
    let r = send(long_body());
    assert_eq!(r.decision, "escalate", "{:?}", r.reasons);
    assert!(
        held(&r) && r.policy_ids.iter().any(|p| p == long_send::POLICY_ID),
        "{:?}",
        r.reasons
    );
    // long text split across fields still counts; recipients are not measured
    let half = "word ".repeat(70);
    let r = e.decide(&rq(
        t,
        "mail.send",
        serde_json::json!({"to": "a@cust.example", "subject": half, "body": half}),
    ));
    assert_eq!(r.decision, "escalate", "{:?}", r.reasons);
    // a deny stays deny (reason recorded, decision not lowered or changed)
    let r = e.decide(&rq(
        t,
        "mail.send",
        serde_json::json!({"to": "x@evil.example", "body": long_body()}),
    ));
    assert_eq!(r.decision, "deny", "{:?}", r.reasons);
    assert!(held(&r));
    // non-send consequential class is not held by this rule
    let r = e.decide(&rq(
        t,
        "doc.write",
        serde_json::json!({"resource": "docs", "body": long_body()}),
    ));
    assert!(!held(&r), "{:?}", r.reasons);
}

#[test]
fn long_send_hold_tier2_off() {
    let (e, t) = ls_engine();
    assert!(e.tier2().is_none());
    check(&e, &t, false);
}

#[test]
fn long_send_hold_tier2_on_fast_and_slow() {
    // Tier 2 answers "no escalate" both well inside and far past its deadline: the hold does not
    // depend on Tier 2's verdict or on how fast the scorer is.
    // fast: answers at once, 5 s send deadline; slow: answers after 200 ms, 20 ms send deadline.
    for (delay, deadline) in [(0u64, 5000u64), (200, 20)] {
        let (mut e, t) = ls_engine();
        quiet_t2(&mut e, delay, deadline);
        check(&e, &t, delay > deadline);
    }
}

#[test]
fn long_send_hold_is_per_session() {
    let (e, t) = ls_engine();
    let ctx = |s: &str| -> bindings::Context {
        serde_json::from_value(serde_json::json!({"session_id": s})).unwrap()
    };
    e.observe_output_at(
        &t,
        Some(&ctx("a")),
        "ticket.read",
        "untrusted text",
        Some(NOW),
    );
    let mut r = rq(
        &t,
        "mail.send",
        serde_json::json!({"to": "a@cust.example", "body": long_body()}),
    );
    r.context = Some(ctx("b"));
    assert_eq!(e.decide(&r).decision, "allow");
    r.context = Some(ctx("a"));
    assert_eq!(e.decide(&r).decision, "escalate");
}
