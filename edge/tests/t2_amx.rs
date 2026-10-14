//! Tier 2 AMX gate, end to end with the real scorer sidecar (skipped when the scorer dir / onnxruntime /
//! built shim are absent). The Edge preloads the sha256-pinned noamx shim, and the scorer must PROVE AMX is
//! off (raw arch_prctl(ARCH_GET_XCOMP_PERM), XTILEDATA bit 18 clear after model load); otherwise Tier 2 is
//! refused (fail closed). "Shim loaded" is never taken as proof.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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

fn scorer_dir() -> Option<PathBuf> {
    let d = std::env::var_os("SENTRYRA_T2_SCORER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tier2-prototype")
        });
    let shim = Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/noamx/noamx.so");
    let ort = Command::new("python3")
        .args(["-c", "import onnxruntime, tokenizers"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if d.join("scorer.py").exists() && shim.exists() && ort {
        Some(d)
    } else {
        eprintln!(
            "skip: needs {} + built shim (make noamx) + python3 onnxruntime",
            d.display()
        );
        None
    }
}

fn cpu_has_amx() -> bool {
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.split_whitespace().any(|w| w == "amx_tile"))
        .unwrap_or(false)
}

struct Env {
    d: PathBuf,
    tok: String,
}

fn setup(tag: &str) -> Env {
    let d = std::env::temp_dir().join(format!("edge-amx-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let keys = d.join("keys");
    run(&["keygen", keys.to_str().unwrap()]);
    let cat = d.join("catalogue.json");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../spec/examples/connector-demo-db.json"),
        &cat,
    )
    .unwrap();
    run(&[
        "sign-catalogue",
        keys.to_str().unwrap(),
        cat.to_str().unwrap(),
    ]);
    let m = serde_json::json!({
        "mandate_id": "mdt_amx", "spec": "sentryra.mandate/v0", "tenant": "t", "principal": {"id": "p@x"}, "agent": {"id": "a"},
        "purpose": "Answer support questions from the demo DB",
        "scopes": [{"tool": "db.query", "resource": "db:demo", "effect": "allow"}],
        "default_effect": "deny", "not_before": "2020-01-01T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z"});
    let f = d.join("m.json");
    std::fs::write(&f, m.to_string()).unwrap();
    let tok = run(&["issue", keys.to_str().unwrap(), f.to_str().unwrap()])
        .trim()
        .to_string();
    Env { d, tok }
}

/// Start the proxy with Tier 2 and return its stderr once Tier 2 attached (stdin is closed at once).
fn edge_stderr(e: &Env, scorer: &Path, python: &str, extra: &[&str]) -> String {
    let d = &e.d;
    let o = Command::new(BIN)
        .args([
            "mcp-proxy",
            d.join("keys").to_str().unwrap(),
            "--catalogue",
            d.join("catalogue.json").to_str().unwrap(),
            "--no-evidence",
            "--tier2-scorer",
            scorer.to_str().unwrap(),
            "--tier2-python",
            python,
            "--tier2-recheck-secs",
            "0",
        ])
        .args(extra)
        .args([
            "--",
            "python3",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../demo/sample_mcp_server.py"),
        ])
        .env("SENTRYRA_MANDATE", &e.tok)
        .env_remove("LD_PRELOAD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A `python` that silently drops the preload (the shim "configured" but not in effect), optionally
/// also telling the scorer to keep running with AMX (so only the Edge's own check stands in the way).
fn wrapper(e: &Env, name: &str, extra_arg: &str) -> String {
    let p = e.d.join(name);
    std::fs::write(
        &p,
        format!("#!/bin/sh\nunset LD_PRELOAD\nexec python3 \"$@\" {extra_arg}\n"),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p.to_str().unwrap().to_string()
}

#[test]
fn tier2_requires_proven_amx_off() {
    let Some(sc) = scorer_dir() else { return };
    let e = setup("gate");

    // 1. Pinned shim preloaded by the Edge: scorer reports XTILEDATA not granted, Tier 2 comes up.
    let s = edge_stderr(&e, &sc, "python3", &[]);
    assert!(s.contains("tier2 AMX check passed"), "{s}");
    assert!(s.contains("\"xtiledata_granted\": false"), "{s}");
    assert!(s.contains("tier2 scorer up"), "{s}");
    assert!(!s.contains("tier2 UNAVAILABLE"), "{s}");

    // 2. Shim not in effect (preload dropped): on an AMX CPU ONNX Runtime gets XTILEDATA, the scorer's
    //    raw ARCH_GET_XCOMP_PERM sees bit 18 and it refuses to start; the Edge fails closed.
    let s = edge_stderr(&e, &sc, &wrapper(&e, "py-noshim", ""), &[]);
    if cpu_has_amx() {
        assert!(s.contains("\"xtiledata_granted\": true"), "{s}");
        assert!(s.contains("XTILEDATA (AMX) permission granted=True"), "{s}");
        assert!(s.contains("tier2 UNAVAILABLE"), "{s}");
        assert!(!s.contains("tier2 scorer up"), "{s}");
    } else {
        eprintln!("note: CPU has no AMX; shim-off reports granted=false and Tier 2 comes up");
        assert!(s.contains("\"xtiledata_granted\": false"), "{s}");
    }

    // 3. Same, but the scorer is told not to refuse: the Edge's own hello check refuses Tier 2.
    let s = edge_stderr(
        &e,
        &sc,
        &wrapper(&e, "py-noshim-allow", "--diagnostic-allow-amx"),
        &[],
    );
    if cpu_has_amx() {
        assert!(
            s.contains("scorer AMX check: xtiledata_granted=true"),
            "{s}"
        );
        assert!(s.contains("tier2 UNAVAILABLE"), "{s}");
        assert!(!s.contains("tier2 scorer up"), "{s}");
    }

    // 4. Unpinned shim file: refused before the scorer is launched.
    let fake = e.d.join("noamx.so");
    std::fs::write(&fake, b"not the pinned shim").unwrap();
    let s = edge_stderr(
        &e,
        &sc,
        "python3",
        &["--tier2-noamx-shim", fake.to_str().unwrap()],
    );
    assert!(s.contains("!= pinned"), "{s}");
    assert!(s.contains("tier2 UNAVAILABLE"), "{s}");
    let s = edge_stderr(
        &e,
        &sc,
        "python3",
        &["--tier2-noamx-shim", "/nonexistent/noamx.so"],
    );
    assert!(s.contains("tier2 UNAVAILABLE"), "{s}");
    let _ = std::fs::remove_dir_all(&e.d);
}

#[test]
fn amx_diagnostic_is_dev_export_only() {
    let o = Command::new(BIN)
        .args([
            "mcp-proxy",
            "/nonexistent",
            "--tier2-diagnostic-allow-amx",
            "--",
            "true",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    if sentryra_sidecar_risk::client::Client::dev_export_compiled() {
        assert!(!err.contains("dev-export builds only"), "{err}");
    } else {
        assert!(!o.status.success());
        assert!(err.contains("dev-export builds only"), "{err}");
    }
}
