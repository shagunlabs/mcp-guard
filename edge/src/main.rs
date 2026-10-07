//! Sentryra Edge: decide API, stdio MCP proxy, key/mandate tooling, onboarding doctor, benchmark.
mod doctor;
mod proxy;

use biscuit_auth::{Algorithm, KeyPair, PrivateKey};
use ed25519_dalek::{Signer, SigningKey};
use sentryra_mandate::{token, Mandate};
use sentryra_pdp::{Config, DecideRequest, Engine, Mode};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const USAGE: &str = "usage: sentryra-edge <command>
  keygen <keydir>                               create local demo keys (root, catalogue, evidence, salt)
  sign-catalogue <keydir> <manifest.json>       write <manifest.json>.sig
  issue <keydir> <mandate.json>                 print a signed Biscuit mandate (base64)
  attenuate <keydir> <token> <tool> <resource> [expires_at]
  revocation-ids <keydir> <token>
  serve <keydir> [opts] [--addr 127.0.0.1:8787] HTTP: POST /v1/decide, GET /v1/approvals/<id>, GET /v1/evidence
  mcp-proxy <keydir> [opts] -- <server cmd...>  stdio MCP proxy (mandate from $SENTRYRA_MANDATE)
  bench <keydir> [opts] [--n 20000]             in-process Tier 1 latency
  doctor [--no-network] [--home <dir>]          scan agent environment for standing credentials and egress
opts: --mode shadow|enforce (default enforce) --catalogue <manifest.json> (repeatable, needs .sig)
      --policies <file.cedar> --evidence <file.jsonl> --revoked <id,...> --edge-url <url>";

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
    policies: PathBuf,
    evidence: Option<PathBuf>,
    revoked: Vec<String>,
    edge_url: String,
    addr: String,
    n: usize,
    rest: Vec<String>,
    flags: Vec<String>,
}

fn opts(args: &[String]) -> Opts {
    let mut o = Opts {
        mode: Mode::Enforce,
        catalogue: vec![],
        policies: "policies/default.cedar".into(),
        evidence: None,
        revoked: vec![],
        edge_url: "http://127.0.0.1:8787".into(),
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
            "--policies" => o.policies = v().into(),
            "--evidence" => o.evidence = Some(v().into()),
            "--revoked" => o.revoked = v().split(',').map(String::from).collect(),
            "--edge-url" => o.edge_url = v(),
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
        policies: read(&o.policies),
        evidence_key: ed_key(dir, "evidence.key"),
        salt_key: hex::decode(read(dir.join("salt.key")).trim()).unwrap_or_else(|e| die(e)),
        mode: o.mode,
        evidence_path: o.evidence.clone(),
        edge_url: o.edge_url.clone(),
        revoked: o.revoked.iter().cloned().collect(),
        approval_vk: ed_key(dir, "approval.key").verifying_key(),
        approval_sk: Some(ed_key(dir, "approval.key")),
    })
    .unwrap_or_else(|e| die(e))
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
        "serve" => {
            let d = need_dir();
            let o = opts(&a[2..]);
            let e = Arc::new(engine(&d, &o));
            let tok = read(d.join("approver.token")).trim().to_string();
            serve(e, o.addr, tok);
        }
        "mcp-proxy" => {
            let d = need_dir();
            let o = opts(&a[2..]);
            if o.rest.is_empty() {
                die("mcp-proxy needs -- <server command>");
            }
            let mandate =
                std::env::var("SENTRYRA_MANDATE").unwrap_or_else(|_| die("set SENTRYRA_MANDATE"));
            let e = Arc::new(engine(&d, &o));
            std::process::exit(proxy::run(e, mandate, &o.rest));
        }
        "bench" => {
            let d = need_dir();
            let o = opts(&a[2..]);
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
    e.observe_output(
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

fn serve(e: Arc<Engine>, addr: String, approver_token: String) {
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
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let app =
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
                .route(
                    "/v1/evidence",
                    get(|State(s): State<S>| async move { Json(s.e.entries()) }),
                )
                .with_state(st);
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
