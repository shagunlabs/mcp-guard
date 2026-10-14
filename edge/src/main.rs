//! Sentryra Edge: decide API, stdio MCP proxy, key/mandate tooling, onboarding doctor, benchmark.
mod doctor;
mod mandate_new;
mod proxy;

use biscuit_auth::{Algorithm, KeyPair, PrivateKey};
use ed25519_dalek::{Signer, SigningKey};
use sentryra_mandate::{token, Mandate};
use sentryra_pdp::{Config, DecideRequest, Engine, Mode};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_POLICIES: &str = include_str!("../../policies/default.cedar");

const USAGE: &str = "usage: sentryra-edge <command>
  keygen <keydir>                               create local demo keys (root, catalogue, evidence, salt)
  sign-catalogue <keydir> <manifest.json>       write <manifest.json>.sig
  issue <keydir> <mandate.json>                 print a signed Biscuit mandate (base64)
  mandate new <keydir> <spec.json> [--catalogue m.json] [--json-out f]
                                                build + sign a mandate from a small JSON spec, print the token
                                                (external_send tools default to mail.recipients [$ticket.requester]
                                                when the spec has ticket.requester; context values are never printed)
  attenuate <keydir> <token> <tool> <resource> [expires_at]
  revocation-ids <keydir> <token>
  serve <keydir> [opts] [--addr 127.0.0.1:8787] HTTP: POST /v1/decide, GET /v1/approvals/<id>, GET /v1/evidence
  mcp-proxy <keydir> [opts] -- <server cmd...>  stdio MCP proxy (mandate from $SENTRYRA_MANDATE, trusted host context JSON from $SENTRYRA_CONTEXT)
  bench <keydir> [opts] [--n 20000]             in-process Tier 1 latency
  doctor [--no-network] [--home <dir>]          scan agent environment for standing credentials and egress
opts: --mode shadow|enforce (default enforce) --catalogue <manifest.json> (repeatable, needs .sig)
      --policies <file.cedar> (default: compiled-in) --evidence <file.jsonl> (default: <keydir>/evidence.jsonl; --no-evidence to disable) --revoked <id,...> --edge-url <url>
      --tier2-scorer <dir> [--tier2-deadline-ms 10] [--tier2-recheck-secs 60] [--tier2-diagnostic-no-probe (score-only diagnostics, never enforce)] [--tier2-dev-export (dev-export builds only; fixture mandates only)] [--tier2-config <scorer-config.json>] [--tier2-log <jsonl>]
      [--tier2-diag] [--tier2-allowlist <file>] [--tier2-python python3]   (mcp-proxy)
      [--tier2-noamx-shim <noamx.so> (default: deploy/noamx/noamx.so, sha256-pinned; preloaded into the scorer, which must prove AMX off or Tier 2 is refused)]
      [--tier2-diagnostic-allow-amx (dev-export builds only: no shim, accept XTILEDATA granted; AMX-on comparison, never enforce)]
      PROTOTYPE, off by default: [--tier2-window-filter (score only windows traceable to untrusted output; skipped windows = T2_PARTIAL_READ)] [--tier2-send-deadline-ms <ms> (external_send only; other classes keep --tier2-deadline-ms)]";

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2)
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p.as_ref())
        .unwrap_or_else(|e| die(format!("{}: {e}", p.as_ref().display())))
}

fn root_key(dir: &Path) -> KeyPair {
    let pk = PrivateKey::from_bytes_hex(read(dir.join("root.key")).trim(), Algorithm::Ed25519)
        .unwrap_or_else(|e| die(e));
    KeyPair::from(&pk)
}

fn ed_key(dir: &Path, name: &str) -> SigningKey {
    let b: [u8; 32] = hex::decode(read(dir.join(name)).trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die("bad key"));
    SigningKey::from_bytes(&b)
}

struct Opts {
    mode: Mode,
    catalogue: Vec<PathBuf>,
    policies: Option<PathBuf>,
    no_evidence: bool,
    evidence: Option<PathBuf>,
    revoked: Vec<String>,
    edge_url: String,
    addr: String,
    n: usize,
    rest: Vec<String>,
    flags: Vec<String>,
    t2_scorer: Option<PathBuf>,
    t2_python: String,
    t2_deadline_ms: u64,
    t2_window_filter: bool,
    t2_send_deadline_ms: Option<u64>,
    t2_recheck_secs: u64,
    t2_diag_noprobe: bool,
    t2_dev_export: bool,
    t2_log: Option<PathBuf>,
    t2_diag: bool,
    t2_allowlist: Option<PathBuf>,
    t2_config: Option<PathBuf>,
    t2_noamx_shim: Option<PathBuf>,
    t2_diag_allow_amx: bool,
}

fn opts(args: &[String]) -> Opts {
    let mut o = Opts {
        mode: Mode::Enforce,
        catalogue: vec![],
        policies: None,
        no_evidence: false,
        evidence: None,
        revoked: vec![],
        edge_url: "http://127.0.0.1:8787".into(),
        t2_scorer: None,
        t2_python: "python3".into(),
        t2_deadline_ms: 10,
        t2_window_filter: false,
        t2_send_deadline_ms: None,
        t2_recheck_secs: 60,
        t2_diag_noprobe: false,
        t2_dev_export: false,
        t2_log: None,
        t2_diag: false,
        t2_allowlist: None,
        t2_config: None,
        t2_noamx_shim: None,
        t2_diag_allow_amx: false,
        addr: "127.0.0.1:8787".into(),
        n: 20000,
        rest: vec![],
        flags: vec![],
    };
    let mut i = 0;
    while i < args.len() {
        let v = || {
            args.get(i + 1)
                .cloned()
                .unwrap_or_else(|| die(format!("{} needs a value", args[i])))
        };
        match args[i].as_str() {
            "--mode" => {
                o.mode = if v() == "shadow" {
                    Mode::Shadow
                } else {
                    Mode::Enforce
                }
            }
            "--catalogue" => o.catalogue.push(v().into()),
            "--policies" => o.policies = Some(v().into()),
            "--no-evidence" => {
                o.no_evidence = true;
                i += 1;
                continue;
            }
            "--evidence" => o.evidence = Some(v().into()),
            "--revoked" => o.revoked = v().split(',').map(String::from).collect(),
            "--edge-url" => o.edge_url = v(),
            "--tier2-scorer" => o.t2_scorer = Some(v().into()),
            "--tier2-python" => o.t2_python = v(),
            "--tier2-dev-export" => {
                if !sentryra_sidecar_risk::client::Client::dev_export_compiled() {
                    die("--tier2-dev-export: this build has no dev-export feature (release builds never do)");
                }
                o.t2_dev_export = true;
                i += 1;
                continue;
            }
            "--tier2-diagnostic-no-probe" => {
                o.t2_diag_noprobe = true;
                i += 1;
                continue;
            }
            "--tier2-recheck-secs" => {
                o.t2_recheck_secs = v().parse().unwrap_or_else(|_| die("--tier2-recheck-secs"))
            }
            "--tier2-deadline-ms" => {
                o.t2_deadline_ms = v().parse().unwrap_or_else(|_| die("--tier2-deadline-ms"))
            }
            "--tier2-window-filter" => {
                o.t2_window_filter = true;
                i += 1;
                continue;
            }
            "--tier2-send-deadline-ms" => {
                o.t2_send_deadline_ms = Some(
                    v().parse()
                        .unwrap_or_else(|_| die("--tier2-send-deadline-ms")),
                )
            }
            "--tier2-config" => o.t2_config = Some(v().into()),
            "--tier2-noamx-shim" => o.t2_noamx_shim = Some(v().into()),
            "--tier2-diagnostic-allow-amx" => {
                if !sentryra_sidecar_risk::client::Client::dev_export_compiled() {
                    die("--tier2-diagnostic-allow-amx: dev-export builds only (release builds always require AMX off)");
                }
                o.t2_diag_allow_amx = true;
                i += 1;
                continue;
            }
            "--tier2-log" => o.t2_log = Some(v().into()),
            "--tier2-allowlist" => o.t2_allowlist = Some(v().into()),
            "--tier2-diag" => {
                o.t2_diag = true;
                i += 1;
                continue;
            }
            "--addr" => o.addr = v(),
            "--n" => o.n = v().parse().unwrap_or_else(|_| die("--n")),
            "--home" => {
                o.flags.push(format!("home={}", v()));
            }
            "--" => {
                o.rest = args[i + 1..].to_vec();
                break;
            }
            f if f.starts_with("--") => {
                o.flags.push(f.to_string());
                i += 1;
                continue;
            }
            x => o.rest.push(x.to_string()),
        }
        i += 2;
    }
    o
}

fn engine(dir: &Path, o: &Opts) -> Engine {
    let manifests = o
        .catalogue
        .iter()
        .map(|p| {
            (
                std::fs::read(p).unwrap_or_else(|e| die(e)),
                read(format!("{}.sig", p.display())).trim().to_string(),
            )
        })
        .collect();
    Engine::new(Config {
        root: root_key(dir).public(),
        catalogue_key: ed_key(dir, "catalogue.key").verifying_key(),
        manifests,
        policies: match &o.policies {
            Some(p) => read(p),
            None => DEFAULT_POLICIES.to_string(), // compiled-in default; override with --policies
        },
        evidence_key: ed_key(dir, "evidence.key"),
        salt_key: hex::decode(read(dir.join("salt.key")).trim()).unwrap_or_else(|e| die(e)),
        mode: o.mode,
        // Evidence log is ON by default: <keydir>/evidence.jsonl, or $SENTRYRA_EVIDENCE, or --evidence.
        evidence_path: if o.no_evidence {
            None
        } else {
            Some(o.evidence.clone().unwrap_or_else(|| {
                std::env::var_os("SENTRYRA_EVIDENCE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| dir.join("evidence.jsonl"))
            }))
        },
        edge_url: o.edge_url.clone(),
        revoked: o.revoked.iter().cloned().collect(),
        approval_vk: ed_key(dir, "approval.key").verifying_key(),
        approval_sk: Some(ed_key(dir, "approval.key")),
    })
    .unwrap_or_else(|e| die(e))
}

/// Start the Tier 2 sidecar (one process = one scoring session) if `--tier2-scorer` is set.
/// The model digest must be on the allowlist (pinned copy by default) or the Edge refuses to start.
fn attach_tier2(e: &mut Engine, o: &Opts) {
    use sentryra_sidecar_risk::{allowlist, client, config, rules};
    let Some(dir) = &o.t2_scorer else { return };
    let allow = match &o.t2_allowlist {
        Some(p) => allowlist::parse(&read(p)),
        None => allowlist::parse(allowlist::PINNED),
    }
    .unwrap_or_else(|e| die(format!("tier2 allowlist: {e:?}")));
    // Versioned scorer config: pinned v0 by default, or a file (e.g. a later V1) — no code change.
    let (cfg_text, cfg_path) = match &o.t2_config {
        Some(p) => (read(p), p.clone()),
        None => {
            let p = std::env::temp_dir()
                .join(format!("sentryra-t2-config-{}.json", std::process::id()));
            std::fs::write(&p, config::PINNED_V0).unwrap_or_else(|e| die(e));
            (config::PINNED_V0.to_string(), p)
        }
    };
    let sc = config::ScorerConfig::parse(&cfg_text)
        .unwrap_or_else(|e| die(format!("tier2 config: {e}")));
    let rcfg = rules::Config {
        threshold: sc.threshold,
        near_margin: sc.near_margin,
        deadline_ms: o.t2_deadline_ms,
        recheck_secs: o.t2_recheck_secs,
        window_filter: o.t2_window_filter,
        send_deadline_ms: o.t2_send_deadline_ms,
    };
    let sock = std::env::temp_dir().join(format!("sentryra-t2-{}.sock", std::process::id()));
    let c = match client::Client::spawn(client::SpawnOpts {
        python: o.t2_python.clone(),
        server: client::default_server(),
        scorer_dir: dir.clone(),
        socket: sock,
        allowlist: allow,
        log: o.t2_log.clone(),
        cfg: rcfg,
        scorer_config: sc.clone(),
        scorer_config_path: cfg_path,
        diagnostic_no_probe: o.t2_diag_noprobe,
        feature_export: o.t2_dev_export,
        noamx_shim: Some(
            o.t2_noamx_shim
                .clone()
                .unwrap_or_else(client::default_noamx_shim),
        ),
        diagnostic_allow_amx: o.t2_diag_allow_amx,
    }) {
        Ok(c) => {
            eprintln!(
                "[sentryra] tier2 scorer up: config {} model sha256:{} deadline {} ms (external_send {} ms) threshold {} window_filter {}",
                sc.config_version, c.model_digest, o.t2_deadline_ms, rcfg.deadline_for(sentryra_sidecar_risk::types::SideEffect::ExternalSend), sc.threshold, o.t2_window_filter
            );
            c
        }
        Err(e) => {
            // Refused to start (digest / config / determinism): fail closed, never die silently.
            eprintln!("[sentryra] tier2 UNAVAILABLE (fail closed: external_send/destructive/privilege escalate): {}", e.0);
            client::Client::dead(rcfg, sc.config_version.clone(), e.0)
        }
    };
    let c = Arc::new(c);
    c.start_recheck(); // periodic probe re-check through the same FIFO queue
    e.set_tier2(c, o.t2_diag);
    e.set_tier2_dev_export(o.t2_dev_export);
}

fn mandate_cmd(a: &[String]) {
    const U: &str = "usage: sentryra-edge mandate new <keydir> <spec.json> [--catalogue <manifest.json>] [--json-out <file>]";
    let (Some(sub), Some(d), Some(spec_p)) = (a.first(), a.get(1), a.get(2)) else {
        die(U)
    };
    if sub != "new" {
        die(U);
    }
    let d = PathBuf::from(d);
    let (mut cat, mut json_out) = (None, None);
    let mut i = 3;
    while i < a.len() {
        let v = a.get(i + 1).cloned().unwrap_or_else(|| die(U));
        match a[i].as_str() {
            "--catalogue" => cat = Some(v),
            "--json-out" => json_out = Some(v),
            x => die(format!("mandate new: unknown argument {x}\n{U}")),
        }
        i += 2;
    }
    let mut classes = std::collections::BTreeMap::new();
    if let Some(c) = cat {
        // Only a catalogue signed with this keydir's catalogue key is trusted for side-effect classes.
        let bytes = std::fs::read(&c).unwrap_or_else(|e| die(format!("{c}: {e}")));
        let sig: [u8; 64] = hex::decode(read(format!("{c}.sig")).trim())
            .ok()
            .and_then(|v| v.try_into().ok())
            .unwrap_or_else(|| die(format!("{c}.sig: bad signature file")));
        ed25519_dalek::Verifier::verify(
            &ed_key(&d, "catalogue.key").verifying_key(),
            &bytes,
            &ed25519_dalek::Signature::from_bytes(&sig),
        )
        .unwrap_or_else(|_| die(format!("{c}: catalogue signature does not verify")));
        let m: sentryra_connector_manifest::Manifest =
            serde_json::from_slice(&bytes).unwrap_or_else(|e| die(format!("manifest: {e}")));
        for t in m.tools {
            if let Some(k) = t.side_effect_class {
                classes.insert(t.name, k);
            }
        }
    }
    if !(spec_p.ends_with(".json")) {
        die(format!(
            "mandate new: spec must be JSON (.json), got {spec_p}"
        ));
    }
    let spec = mandate_new::parse_spec(&read(spec_p)).unwrap_or_else(|e| die(e));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (m, rules) = mandate_new::build(spec, &classes, now).unwrap_or_else(|e| die(e));
    let t = token::issue(&m, &root_key(&d)).unwrap_or_else(|e| die(e));
    if let Some(p) = json_out {
        // Holds the signed context values: written owner-only, never echoed.
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&p)
            .unwrap_or_else(|e| die(format!("{p}: {e}")));
        f.write_all(serde_json::to_string_pretty(&m).unwrap().as_bytes())
            .unwrap_or_else(|e| die(format!("{p}: {e}")));
    }
    eprint!("{}", mandate_new::summary(&m, &rules));
    println!("{}", t.to_base64().unwrap());
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = a.first() else { die(USAGE) };
    let dir = a.get(1).map(PathBuf::from);
    let need_dir = || dir.clone().unwrap_or_else(|| die(USAGE));
    match cmd.as_str() {
        "keygen" => {
            let d = need_dir();
            std::fs::create_dir_all(&d).unwrap_or_else(|e| die(e));
            let mut rng = rand::rngs::OsRng;
            let w = |n: &str, s: String| std::fs::write(d.join(n), s).unwrap_or_else(|e| die(e));
            w("root.key", KeyPair::new().private().to_bytes_hex());
            w(
                "catalogue.key",
                hex::encode(SigningKey::generate(&mut rng).to_bytes()),
            );
            w(
                "evidence.key",
                hex::encode(SigningKey::generate(&mut rng).to_bytes()),
            );
            let mut salt = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut salt);
            w("salt.key", hex::encode(salt));
            w(
                "approval.key",
                hex::encode(SigningKey::generate(&mut rng).to_bytes()),
            );
            let mut tok = [0u8; 24];
            rand::RngCore::fill_bytes(&mut rng, &mut tok);
            w("approver.token", hex::encode(tok));
            rand::RngCore::fill_bytes(&mut rng, &mut tok);
            w("ingest.token", hex::encode(tok)); // bearer for POST /v1/outputs (tool-host side)
            w("root.pub", root_key(&d).public().to_bytes_hex());
            w(
                "evidence.pub",
                hex::encode(ed_key(&d, "evidence.key").verifying_key().to_bytes()),
            );
            println!(
                "keys written to {} (local demo keys; production keys live in the customer's KMS)",
                d.display()
            );
        }
        "sign-catalogue" => {
            let d = need_dir();
            let m = a.get(2).unwrap_or_else(|| die(USAGE));
            let bytes = std::fs::read(m).unwrap_or_else(|e| die(e));
            serde_json::from_slice::<sentryra_connector_manifest::Manifest>(&bytes)
                .unwrap_or_else(|e| die(format!("manifest: {e}")));
            std::fs::write(
                format!("{m}.sig"),
                hex::encode(ed_key(&d, "catalogue.key").sign(&bytes).to_bytes()),
            )
            .unwrap();
            println!("signed {m}");
        }
        "issue" => {
            let d = need_dir();
            let m = Mandate::from_json(&read(a.get(2).unwrap_or_else(|| die(USAGE))))
                .unwrap_or_else(|e| die(format!("{e:?}")));
            let t = token::issue(&m, &root_key(&d)).unwrap_or_else(|e| die(e));
            println!("{}", t.to_base64().unwrap());
        }
        "attenuate" => {
            let d = need_dir();
            let (Some(t), Some(tool), Some(res)) = (a.get(2), a.get(3), a.get(4)) else {
                die(USAGE)
            };
            let b = biscuit_auth::Biscuit::from_base64(t.trim(), root_key(&d).public())
                .unwrap_or_else(|e| die(e));
            let n = token::attenuate(&b, &[(tool, res)], a.get(5).map(|s| s.as_str()))
                .unwrap_or_else(|e| die(e));
            println!("{}", n.to_base64().unwrap());
        }
        "revocation-ids" => {
            let d = need_dir();
            let b = biscuit_auth::Biscuit::from_base64(
                a.get(2).unwrap_or_else(|| die(USAGE)).trim(),
                root_key(&d).public(),
            )
            .unwrap_or_else(|e| die(e));
            for id in token::revocation_ids(&b) {
                println!("{id}");
            }
        }
        "mandate" => mandate_cmd(&a[1..]),
        "serve" => {
            let d = need_dir();
            let o = opts(&a[2..]);
            let e = Arc::new(engine(&d, &o));
            let tok = read(d.join("approver.token")).trim().to_string();
            // Output ingest is disabled unless an ingest token exists (keygen writes one).
            let ing = std::fs::read_to_string(d.join("ingest.token"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| s.len() >= 32);
            if ing.is_none() {
                eprintln!("[sentryra] no ingest.token: POST /v1/outputs disabled (taint/Tier 2 see no outputs in serve mode)");
            }
            serve(e, o.addr, tok, ing);
        }
        "mcp-proxy" => {
            let d = need_dir();
            let o = opts(&a[2..]);
            if o.rest.is_empty() {
                die("mcp-proxy needs -- <server command>");
            }
            let mandate =
                std::env::var("SENTRYRA_MANDATE").unwrap_or_else(|_| die("set SENTRYRA_MANDATE"));
            let mut e = engine(&d, &o);
            attach_tier2(&mut e, &o);
            let e = Arc::new(e);
            // Trusted host context for `$` bindings: from the host's environment, never from the agent.
            let context = std::env::var("SENTRYRA_CONTEXT").ok().map(|c| {
                serde_json::from_str(&c).unwrap_or_else(|x| die(format!("SENTRYRA_CONTEXT: {x}")))
            });
            let code = proxy::run(e.clone(), mandate, context, &o.rest);
            if let Some(c) = e.tier2() {
                c.flush(std::time::Duration::from_secs(120)); // per-window diagnostics, after the run
                c.shutdown();
            }
            drop(e);
            std::process::exit(code);
        }
        "bench" => {
            let d = need_dir();
            let mut o = opts(&a[2..]);
            o.no_evidence |= o.evidence.is_none(); // in-memory chain only, unless --evidence given
            bench(&d, &o);
        }
        "doctor" => {
            let o = opts(&a[1..]);
            let home = o
                .flags
                .iter()
                .find_map(|f| f.strip_prefix("home=").map(PathBuf::from));
            let net = !o.flags.iter().any(|f| f == "--no-network");
            std::process::exit(doctor::run(home, net));
        }
        _ => die(USAGE),
    }
}

fn bench(dir: &Path, o: &Opts) {
    let e = engine(dir, o);
    let m = serde_json::json!({
        "mandate_id": "mdt_bench", "spec": "sentryra.mandate/v0", "tenant": "org_bench",
        "principal": {"id": "bench@local"}, "agent": {"id": "agt_bench"}, "purpose": "benchmark",
        "scopes": [{"tool": "db.query", "resource": "db:demo", "effect": "allow"}],
        "default_effect": "deny", "not_before": "2020-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"
    });
    let tok = token::issue(&Mandate::from_json(&m.to_string()).unwrap(), &root_key(dir))
        .unwrap()
        .to_base64()
        .unwrap();
    e.observe_output_in(
        &tok,
        None,
        "db.query",
        "ticket 7: customer asks for a refund on order 1234 please",
    );
    let cases = [
        serde_json::json!({"db": "demo", "sql": "SELECT id, name FROM users WHERE id = 7"}),
        serde_json::json!({"db": "demo", "sql": "DROP TABLE users"}),
        serde_json::json!({"db": "demo", "sql": "UPDATE users SET name = 'x' WHERE id = 1"}),
    ];
    for c in &cases {
        e.decide(&DecideRequest {
            mandate: tok.clone(),
            tool: "db.query".into(),
            args: c.clone(),
            now: None,
            receipt: None,
            context: None,
        });
    }
    let mut lat = Vec::with_capacity(o.n);
    for i in 0..o.n {
        let r = DecideRequest {
            mandate: tok.clone(),
            tool: "db.query".into(),
            args: cases[i % cases.len()].clone(),
            now: None,
            receipt: None,
            context: None,
        };
        let t = std::time::Instant::now();
        std::hint::black_box(e.decide(&r));
        lat.push(t.elapsed().as_secs_f64() * 1e6);
    }
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| lat[((lat.len() as f64 * q) as usize).min(lat.len() - 1)];
    println!(
        "Tier 1 decide() in-process, {} decisions (allow/deny/escalate mix), incl. Biscuit verify + SQL parse + taint + Cedar + signed evidence append (no fsync):",
        o.n
    );
    println!(
        "  p50 {:.0} us   p90 {:.0} us   p99 {:.0} us   max {:.0} us",
        p(0.5),
        p(0.9),
        p(0.99),
        lat[lat.len() - 1]
    );
    println!(
        "  box-local benchmark: {} CPUs, release={}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        !cfg!(debug_assertions)
    );
}

#[derive(serde::Deserialize)]
struct OutputIngest {
    mandate: String,
    decision_id: String,
    tool: String,
    output: String,
    #[serde(default)]
    context: Option<sentryra_pdp::bindings::Context>,
}

fn router(e: Arc<Engine>, approver_token: String, ingest_token: Option<String>) -> axum::Router {
    use axum::{
        extract::{Path as P, State},
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    #[derive(Clone)]
    struct S {
        e: Arc<Engine>,
        token: Arc<String>,
        ingest: Arc<Option<String>>,
    }
    // Basic bearer-token auth for the approval view (MVP; production: approver SSO + WebAuthn).
    fn authed(h: &HeaderMap, token: &str) -> bool {
        let got = h
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        got.len() == token.len()
            && got
                .bytes()
                .zip(token.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }
    #[derive(serde::Deserialize)]
    struct Approve {
        approver: String,
    }
    let st = S {
        e: e.clone(),
        token: Arc::new(approver_token),
        ingest: Arc::new(ingest_token),
    };
    Router::new()
                .route(
                    "/v1/decide",
                    post(
                        |State(s): State<S>, Json(r): Json<DecideRequest>| async move {
                            Json(s.e.decide(&r))
                        },
                    ),
                )
                // Approval view: served by the customer-side Edge, so raw args never transit the control plane.
                .route(
                    "/v1/approvals/{id}",
                    get(
                        |State(s): State<S>, h: HeaderMap, P(id): P<String>| async move {
                            if !authed(&h, &s.token) {
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                            s.e.pending(&id).map(Json).ok_or(StatusCode::NOT_FOUND)
                        },
                    ),
                )
                .route(
                    "/v1/approvals/{id}/approve",
                    post(
                        |State(s): State<S>,
                         h: HeaderMap,
                         P(id): P<String>,
                         Json(a): Json<Approve>| async move {
                            if !authed(&h, &s.token) {
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                            s.e.approve(&id, &a.approver)
                                .map(Json)
                                .map_err(|_| StatusCode::NOT_FOUND)
                        },
                    ),
                )
                // Tool host reports a tool's output so Tier 1 taint and Tier 2 see it. Auth: ingest
                // bearer token + verified mandate + a prior allow/shadow decision for the same
                // mandate/session and tool (single use). Keyed by verified mandate id + session_id.
                .route(
                    "/v1/outputs",
                    post(
                        |State(s): State<S>, h: HeaderMap, Json(o): Json<OutputIngest>| async move {
                            let Some(t) = s.ingest.as_ref() else {
                                return Err(StatusCode::NOT_FOUND);
                            };
                            if !authed(&h, t) {
                                return Err(StatusCode::UNAUTHORIZED);
                            }
                            match s.e.ingest_output(&o.mandate, o.context.as_ref(), &o.decision_id, &o.tool, &o.output) {
                                Ok(()) => Ok(StatusCode::NO_CONTENT),
                                Err(sentryra_pdp::IngestError::Mandate) => Err(StatusCode::FORBIDDEN),
                                Err(sentryra_pdp::IngestError::UnknownDecision) => Err(StatusCode::CONFLICT),
                            }
                        },
                    ),
                )
                .route("/healthz", get(|| async { "ok" }))
                // Evidence export: approver bearer token (entries carry salted arg digests, decisions, reasons).
                .route(
                    "/v1/evidence",
                    get(|State(s): State<S>, h: HeaderMap| async move {
                        if !authed(&h, &s.token) {
                            return Err(StatusCode::UNAUTHORIZED);
                        }
                        Ok(Json(s.e.entries()))
                    }),
                )
                .with_state(st)
}

fn serve(e: Arc<Engine>, addr: String, approver_token: String, ingest_token: Option<String>) {
    let app = router(e.clone(), approver_token, ingest_token);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let l = tokio::net::TcpListener::bind(&addr)
            .await
            .unwrap_or_else(|x| die(x));
        eprintln!(
            "sentryra-edge listening on http://{addr} mode={:?} evidence-key={}",
            e.mode,
            e.evidence_public_key_hex()
        );
        axum::serve(l, app).await.unwrap();
    });
}
