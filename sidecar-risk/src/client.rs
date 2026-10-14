//! Local-only transport to the Python scorer process: newline-delimited JSON over a unix socket
//! (no TCP, nothing off-box). One sidecar process = one scoring session (single-threaded server,
//! one ONNX session). The Edge enforces the per-call deadline; late replies are only logged.
use crate::allowlist;
use crate::rules::{Config, T2Result};
use crate::types::{ScoreRequest, ScoreResponse, SideEffect};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Waiters = Arc<Mutex<HashMap<u64, Sender<Value>>>>;

pub struct Client {
    w: Mutex<Option<UnixStream>>,
    waiters: Waiters,
    pending_ingest: Arc<Mutex<HashMap<String, HashSet<u64>>>>,
    /// (mandate, session) keys that have seen untrusted output. State is per key; the scorer
    /// keeps one shared INT8 inference session and serves all keys through one FIFO queue.
    untrusted: Mutex<HashSet<String>>,
    /// Set when a periodic probe re-check fails: Tier 2 is then unavailable (fail closed).
    pub health: Arc<Mutex<Option<String>>>,
    /// DIAGNOSTIC ONLY (dev-export builds): the scorer may report XTILEDATA granted (AMX-on comparison).
    allow_amx_diag: bool,
    /// The scorer's startup AMX report (`hello.amx`), for logs and bench records.
    pub amx: Option<Value>,
    next: AtomicU64,
    pub cfg: Config,
    pub model_digest: String,
    /// Versioned scorer config in force (recorded in every decision).
    pub config_version: String,
    /// Why the sidecar is unavailable (refused to start); every call then returns Unavailable.
    pub dead: Option<String>,
    child: Mutex<Option<Child>>,
}

#[derive(Debug)]
pub struct ClientError(pub String);

pub struct SpawnOpts {
    pub python: String,
    pub server: PathBuf,
    pub scorer_dir: PathBuf,
    pub socket: PathBuf,
    pub allowlist: Vec<String>,
    /// Data-plane log of every scorer reply incl. late ones and per-window diagnostics.
    pub log: Option<PathBuf>,
    pub cfg: Config,
    pub scorer_config: crate::config::ScorerConfig,
    /// Path of the config file passed to the scorer process (it re-verifies weights + threshold).
    pub scorer_config_path: PathBuf,
    /// DIAGNOSTIC ONLY (score-only pass for a config without probe refs): skip the probe check.
    /// The config version is then recorded as `<id>+diag-noprobe`; never for enforcement.
    pub diagnostic_no_probe: bool,
    /// DEV ONLY: allow per-call feature export (ignored unless built with `dev-export`).
    pub feature_export: bool,
    /// AMX-off shim preloaded into the scorer (`LD_PRELOAD`); must match `NOAMX_SHA256`.
    /// `None` is accepted only together with `diagnostic_allow_amx` in a dev-export build.
    pub noamx_shim: Option<PathBuf>,
    /// DIAGNOSTIC ONLY, dev-export builds only: run the scorer WITHOUT the shim and accept a report of
    /// XTILEDATA granted (AMX-on load comparison). Config id gets `+diag-amx`; never enforcement.
    pub diagnostic_allow_amx: bool,
}

/// Pinned sha256 of the AMX-off shim built by `deploy/noamx/build.sh` (reproducible; equals the research
/// `tier2-prototype/concurrency/noamx.so`, built from the vendored `deploy/noamx/noamx.c`).
pub const NOAMX_PIN_FILE: &str = include_str!("../../deploy/noamx/noamx.so.sha256");

pub fn noamx_sha256() -> &'static str {
    NOAMX_PIN_FILE.split_whitespace().next().unwrap_or("")
}

/// Default shim location (built in place by `make noamx`).
pub fn default_noamx_shim() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/noamx/noamx.so")
}

/// Check the shim file against its pin and return its absolute path (for `LD_PRELOAD`).
pub fn verify_noamx_shim(p: &Path, pin: &str) -> Result<PathBuf, ClientError> {
    let got = allowlist::sha256_file(p).map_err(|e| {
        ClientError(format!(
            "noamx shim {}: {e:?} (build it: make noamx)",
            p.display()
        ))
    })?;
    if got != pin {
        return Err(ClientError(format!(
            "noamx shim {} sha256 {got} != pinned {pin}; refusing Tier 2",
            p.display()
        )));
    }
    std::fs::canonicalize(p).map_err(|e| ClientError(format!("noamx shim: {e}")))
}

/// The scorer must prove AMX is off: its `amx.xtiledata_granted` (raw ARCH_GET_XCOMP_PERM bit 18,
/// read after model load) must be exactly `false`. Missing / null / true => refuse Tier 2, except
/// `true` under the dev-only AMX diagnostic. "Shim loaded" alone is never accepted as proof.
pub fn check_amx(reply: &Value, allow_amx_diag: bool) -> Result<(), ClientError> {
    match reply
        .get("amx")
        .and_then(|a| a.get("xtiledata_granted"))
        .and_then(|v| v.as_bool())
    {
        Some(false) => Ok(()),
        Some(true) if allow_amx_diag => Ok(()),
        g => Err(ClientError(format!(
            "scorer AMX check: xtiledata_granted={} (must be false; AMX INT8 is not deterministic under load): {}",
            g.map(|b| b.to_string()).unwrap_or_else(|| "unknown".into()),
            reply.get("amx").cloned().unwrap_or_default()
        ))),
    }
}

impl Client {
    /// Verify the model digest against the allowlist BEFORE launching anything, start the
    /// single scorer process, connect over the unix socket, and check the scorer's own digest.
    pub fn spawn(o: SpawnOpts) -> Result<Client, ClientError> {
        let model = o.scorer_dir.join("onnx/model_int8.onnx");
        let digest = allowlist::verify(&model, &o.allowlist)
            .map_err(|e| ClientError(format!("refusing to load Tier 2 model: {e:?}")))?;
        if digest != o.scorer_config.model_sha256 {
            return Err(ClientError(format!(
                "config {} pins model {} but file is {digest}",
                o.scorer_config.config_version, o.scorer_config.model_sha256
            )));
        }
        if let (Some(f), Some(pin)) = (
            &o.scorer_config.weights_file,
            &o.scorer_config.weights_sha256,
        ) {
            let w = allowlist::sha256_file(&o.scorer_dir.join(f))
                .map_err(|e| ClientError(format!("weights: {e:?}")))?;
            if &w != pin {
                return Err(ClientError(format!(
                    "weights sha256 {w} != config {} pin",
                    o.scorer_config.config_version
                )));
            }
        }
        let diag_amx = o.diagnostic_allow_amx && Self::dev_export_compiled();
        if o.diagnostic_allow_amx && !diag_amx {
            return Err(ClientError(
                "diagnostic_allow_amx needs a dev-export build".into(),
            ));
        }
        let shim = match (&o.noamx_shim, diag_amx) {
            (_, true) => None, // AMX-on diagnostic: no shim at all
            (Some(p), false) => Some(verify_noamx_shim(p, noamx_sha256())?),
            (None, false) => {
                return Err(ClientError(
                    "Tier 2 needs the noamx shim (AMX off); none configured".into(),
                ))
            }
        };
        let _ = std::fs::remove_file(&o.socket);
        let mut cmd = Command::new(&o.python);
        match &shim {
            Some(p) => cmd.env("LD_PRELOAD", p), // exactly the pinned shim; nothing inherited
            None => cmd.env_remove("LD_PRELOAD"),
        };
        let mut child = cmd
            .arg(&o.server)
            .arg("--scorer-dir")
            .arg(&o.scorer_dir)
            .arg("--socket")
            .arg(&o.socket)
            .arg("--expect-sha256")
            .arg(&digest)
            .arg("--config")
            .arg(&o.scorer_config_path)
            .args(if o.diagnostic_no_probe {
                vec!["--diagnostic-no-probe"]
            } else {
                vec![]
            })
            .args(if o.cfg.window_filter {
                vec!["--window-filter"]
            } else {
                vec![]
            })
            .args(if o.feature_export && Self::dev_export_compiled() {
                vec!["--feature-export"]
            } else {
                vec![]
            })
            .args(if diag_amx {
                vec!["--diagnostic-allow-amx"]
            } else {
                vec![]
            })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| ClientError(format!("start scorer: {e}")))?;
        let t0 = Instant::now();
        let s = loop {
            match UnixStream::connect(&o.socket) {
                Ok(s) => break s,
                Err(_) if t0.elapsed() < Duration::from_secs(60) => {
                    if let Ok(Some(st)) = child.try_wait() {
                        return Err(ClientError(format!(
                            "scorer refused to start ({st}); see its stderr"
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => {
                    let _ = child.kill();
                    return Err(ClientError(format!("connect {}: {e}", o.socket.display())));
                }
            }
        };
        let mut c = Self::from_stream(s, o.cfg, digest.clone(), o.log)?;
        c.config_version = o.scorer_config.config_version.clone();
        if o.diagnostic_no_probe {
            c.config_version.push_str("+diag-noprobe");
        }
        if diag_amx {
            c.config_version.push_str("+diag-amx");
        }
        c.allow_amx_diag = diag_amx;
        *c.child.lock().unwrap() = Some(child);
        let hello = c
            .call(json!({"op": "hello"}), Duration::from_secs(60))
            .ok_or_else(|| ClientError("no hello".into()))?;
        let got = hello
            .get("model_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if got != format!("sha256:{digest}") {
            return Err(ClientError(format!(
                "scorer digest {got} != allowlisted {digest}"
            )));
        }
        // AMX proof before anything else is trusted (the scorer also refuses on its own).
        check_amx(&hello, diag_amx)?;
        c.amx = hello.get("amx").cloned();
        eprintln!(
            "[sentryra] tier2 AMX check passed: {}",
            hello.get("amx").cloned().unwrap_or_default()
        );
        if hello.get("config_version").and_then(|v| v.as_str()) != Some(c.config_version.as_str()) {
            return Err(ClientError(format!(
                "scorer config {:?} != {}",
                hello.get("config_version"),
                c.config_version
            )));
        }
        // The scorer must run in the same window-filter mode as the Edge (else skips go unreported).
        if hello
            .get("window_filter")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            != o.cfg.window_filter
        {
            return Err(ClientError(format!(
                "scorer window_filter {:?} != Edge {}",
                hello.get("window_filter"),
                o.cfg.window_filter
            )));
        }
        if hello.get("determinism_ok") != Some(&json!(true)) {
            return Err(ClientError(format!(
                "scorer probe self-check failed: {}",
                hello.get("determinism").cloned().unwrap_or_default()
            )));
        }
        eprintln!(
            "[sentryra] tier2 probe self-check passed: {}",
            hello.get("determinism").cloned().unwrap_or_default()
        );
        Ok(c)
    }

    pub fn from_stream(
        s: UnixStream,
        cfg: Config,
        model_digest: String,
        log: Option<PathBuf>,
    ) -> Result<Client, ClientError> {
        let r = s.try_clone().map_err(|e| ClientError(e.to_string()))?;
        let waiters: Waiters = Arc::default();
        let pending: Arc<Mutex<HashMap<String, HashSet<u64>>>> = Arc::default();
        let (w2, p2) = (waiters.clone(), pending.clone());
        let mut logf = log.and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .ok()
        });
        std::thread::spawn(move || {
            for line in BufReader::new(r).lines().map_while(Result::ok) {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if let Some(a) = v.get("ack").and_then(|x| x.as_u64()) {
                    let sess = v
                        .get("session")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    if let Some(s) = p2.lock().unwrap().get_mut(&sess) {
                        s.remove(&a);
                    }
                    continue;
                }
                let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
                let waiter = w2.lock().unwrap().remove(&id);
                let on_time = match waiter {
                    Some(tx) => tx.send(v.clone()).is_ok(),
                    None => false,
                };
                if v.get("op").and_then(|x| x.as_str()) == Some("score") || v.get("diag").is_some()
                {
                    if let Some(f) = logf.as_mut() {
                        let mut e = v.clone();
                        e["delivered_in_deadline"] = json!(on_time);
                        let _ = writeln!(f, "{e}").and_then(|_| f.flush());
                    }
                }
            }
        });
        Ok(Client {
            w: Mutex::new(Some(s)),
            waiters,
            pending_ingest: pending,
            untrusted: Mutex::default(),
            health: Arc::default(),
            allow_amx_diag: false,
            amx: None,
            next: AtomicU64::new(1),
            cfg,
            model_digest,
            config_version: String::new(),
            dead: None,
            child: Mutex::new(None),
        })
    }

    /// A sidecar that refused to start (digest, config or probe self-check failure). Fail closed:
    /// every call is `Unavailable`, which escalates destructive / privilege / external_send.
    pub fn dead(cfg: Config, config_version: String, reason: String) -> Client {
        Client {
            w: Mutex::new(None),
            waiters: Arc::default(),
            pending_ingest: Arc::default(),
            untrusted: Mutex::default(),
            health: Arc::default(),
            allow_amx_diag: false,
            amx: None,
            next: AtomicU64::new(1),
            cfg,
            model_digest: String::new(),
            config_version,
            dead: Some(reason),
            child: Mutex::new(None),
        }
    }

    fn send(&self, v: &Value) -> bool {
        let mut g = self.w.lock().unwrap();
        let Some(w) = g.as_mut() else { return false };
        writeln!(w, "{v}").and_then(|_| w.flush()).is_ok()
    }

    fn call(&self, mut v: Value, timeout: Duration) -> Option<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        v["id"] = json!(id);
        let (tx, rx) = channel();
        self.waiters.lock().unwrap().insert(id, tx);
        if !self.send(&v) {
            self.waiters.lock().unwrap().remove(&id);
            return None;
        }
        let r = rx.recv_timeout(timeout).ok();
        if r.is_none() {
            self.waiters.lock().unwrap().remove(&id); // a late reply is logged, never applied
        }
        r
    }

    /// Cache untrusted output as it arrives. Fire-and-forget: embedding happens in the scorer,
    /// off the agent's response path; the ack clears the session's pending set.
    pub fn ingest(&self, session: &str, text: &str) {
        self.untrusted.lock().unwrap().insert(session.to_string());
        if self.dead.is_some() {
            return;
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.pending_ingest
            .lock()
            .unwrap()
            .entry(session.to_string())
            .or_default()
            .insert(id);
        if !self.send(&json!({"op": "ingest", "id": id, "session": session, "text": text})) {
            self.pending_ingest
                .lock()
                .unwrap()
                .get_mut(session)
                .map(|s| s.remove(&id));
        }
    }

    pub fn has_untrusted(&self, session: &str) -> bool {
        self.untrusted.lock().unwrap().contains(session)
    }

    /// Why Tier 2 is unavailable right now (refused to start, or a failed periodic re-check).
    pub fn unavailable(&self) -> Option<String> {
        self.dead
            .clone()
            .or_else(|| self.health.lock().unwrap().clone())
    }

    /// One probe re-check through the same FIFO queue as scoring (one shared INT8 session).
    /// On failure or no answer, Tier 2 is marked unavailable for good (fail closed).
    pub fn recheck(&self, timeout: Duration) -> bool {
        if self.dead.is_some() {
            return false;
        }
        let r = self.call(json!({"op": "probe"}), timeout);
        let amx = r.as_ref().map(|v| check_amx(v, self.allow_amx_diag));
        let ok = r
            .as_ref()
            .and_then(|v| v.get("determinism_ok"))
            .and_then(|v| v.as_bool())
            == Some(true)
            && matches!(amx, Some(Ok(())));
        if !ok {
            let why = match amx {
                Some(Err(e)) => format!("periodic re-check: {}", e.0),
                _ => format!(
                    "periodic probe re-check failed: {}",
                    r.and_then(|v| v.get("determinism").cloned())
                        .unwrap_or(json!("no reply"))
                ),
            };
            eprintln!("[sentryra] tier2 UNAVAILABLE (fail closed): {why}");
            *self.health.lock().unwrap() = Some(why);
        } else {
            eprintln!("[sentryra] tier2 periodic probe re-check passed");
        }
        ok
    }

    /// Run `recheck` every `cfg.recheck_secs` (0 = off) until the client is dropped.
    pub fn start_recheck(self: &Arc<Self>) {
        let secs = self.cfg.recheck_secs;
        if secs == 0 || self.dead.is_some() {
            return;
        }
        let w = Arc::downgrade(self);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(secs));
            let Some(c) = w.upgrade() else { return };
            if !c.recheck(Duration::from_secs(30)) {
                return;
            }
        });
    }

    pub fn cache_ready(&self, session: &str) -> bool {
        self.pending_ingest
            .lock()
            .unwrap()
            .get(session)
            .is_none_or(|s| s.is_empty())
    }

    /// Score one call within the deadline. Returns the request id (for the data-plane log) too.
    /// True only in builds with the `dev-export` cargo feature (never release artifacts).
    pub const fn dev_export_compiled() -> bool {
        cfg!(feature = "dev-export")
    }

    /// As `score`, optionally asking for the DEV feature export of this call. The request is
    /// dropped unless the build has `dev-export`; the caller must also have checked the fixture marker.
    #[allow(clippy::too_many_arguments)]
    pub fn score_ex(
        &self,
        session: &str,
        purpose: &str,
        tool: &str,
        class: SideEffect,
        resource: &str,
        args: &Value,
        diag: bool,
        export: bool,
    ) -> (u64, T2Result) {
        self.score_inner(
            session,
            purpose,
            tool,
            class,
            resource,
            args,
            diag,
            export && Self::dev_export_compiled(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn score(
        &self,
        session: &str,
        purpose: &str,
        tool: &str,
        class: SideEffect,
        resource: &str,
        args: &Value,
        diag: bool,
    ) -> (u64, T2Result) {
        self.score_inner(session, purpose, tool, class, resource, args, diag, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn score_inner(
        &self,
        session: &str,
        purpose: &str,
        tool: &str,
        class: SideEffect,
        resource: &str,
        args: &Value,
        diag: bool,
        export: bool,
    ) -> (u64, T2Result) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let req = ScoreRequest {
            op: "score",
            id,
            session: session.into(),
            purpose: purpose.into(),
            tool: tool.into(),
            side_effect: class.wire(),
            resource: resource.into(),
            args: args.clone(),
        };
        let mut v = serde_json::to_value(&req).unwrap();
        if diag {
            v["diag"] = json!(true);
        }
        if export {
            v["diag"] = json!(true);
            v["export"] = json!(true);
        }
        if self.unavailable().is_some() {
            return (id, T2Result::Unavailable);
        }
        if !self.cache_ready(session) {
            // Cache not ready => treated as a timeout. Still sent so the raw score is logged.
            let _ = self.send(&v);
            return (
                id,
                T2Result::Timeout {
                    cache_not_ready: true,
                },
            );
        }
        let (tx, rx) = channel();
        self.waiters.lock().unwrap().insert(id, tx);
        if !self.send(&v) {
            self.waiters.lock().unwrap().remove(&id);
            return (id, T2Result::Unavailable);
        }
        match rx.recv_timeout(Duration::from_millis(self.cfg.deadline_for(class))) {
            Ok(r) => match serde_json::from_value::<ScoreResponse>(r) {
                Ok(s) => (id, T2Result::Scored(Box::new(s))),
                Err(_) => (id, T2Result::Unavailable),
            },
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                self.waiters.lock().unwrap().remove(&id);
                (
                    id,
                    T2Result::Timeout {
                        cache_not_ready: false,
                    },
                )
            }
            Err(_) => (id, T2Result::Unavailable),
        }
    }

    /// Ask the scorer to finish per-window diagnostics and wait for it (bench/shutdown only).
    pub fn flush(&self, timeout: Duration) {
        let _ = self.call(json!({"op": "flush"}), timeout);
    }
}

impl Client {
    /// Stop the scorer process.
    pub fn shutdown(&self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.lock().unwrap().take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub fn default_server() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("python/t2_server.py")
}

#[cfg(test)]
mod t {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Fake scorer on a unix socket: replies after `delay_ms`, acks ingests after `ingest_ms`.
    fn fake(delay_ms: u64, ingest_ms: u64, reply: Value) -> Client {
        fake_probe(delay_ms, ingest_ms, reply, true)
    }
    /// Single-threaded like the real server: one FIFO queue in front of one inference session.
    fn fake_probe(delay_ms: u64, ingest_ms: u64, reply: Value, probe_ok: bool) -> Client {
        fake_cfg(delay_ms, ingest_ms, reply, probe_ok, Config::default())
    }
    fn fake_cfg(
        delay_ms: u64,
        ingest_ms: u64,
        reply: Value,
        probe_ok: bool,
        cfg: Config,
    ) -> Client {
        let p =
            std::env::temp_dir().join(format!("t2fake{}-{}.sock", std::process::id(), rand_id()));
        let _ = std::fs::remove_file(&p);
        let l = UnixListener::bind(&p).unwrap();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut w = s.try_clone().unwrap();
            for line in BufReader::new(s).lines().map_while(Result::ok) {
                let v: Value = serde_json::from_str(&line).unwrap();
                match v["op"].as_str() {
                    Some("ingest") => {
                        std::thread::sleep(Duration::from_millis(ingest_ms));
                        let _ = writeln!(w, "{}", json!({"ack": v["id"], "session": v["session"]}));
                    }
                    Some("score") => {
                        std::thread::sleep(Duration::from_millis(delay_ms));
                        let mut r = reply.clone();
                        r["id"] = v["id"].clone();
                        r["op"] = json!("score");
                        let _ = writeln!(w, "{r}");
                    }
                    Some("probe") => {
                        let _ = writeln!(
                            w,
                            "{}",
                            json!({"id": v["id"], "op": "probe", "determinism_ok": probe_ok, "determinism": "fake", "amx": {"xtiledata_granted": false}})
                        );
                    }
                    _ => {}
                }
            }
        });
        let s = UnixStream::connect(&p).unwrap();
        Client::from_stream(s, cfg, "x".into(), None).unwrap()
    }
    fn rand_id() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64
    }
    fn ok_reply() -> Value {
        json!({"scored": true, "score": 0.8, "band": "high", "escalate": true, "reason_codes": ["T2_UNTRUSTED_CONTENT_CARRIED"], "windows_read": 1, "windows_total": 1})
    }

    #[test]
    fn deadline_enforced_by_edge() {
        let c = fake(40, 0, ok_reply());
        let t = Instant::now();
        let (_, r) = c.score(
            "s",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        assert!(
            matches!(
                r,
                T2Result::Timeout {
                    cache_not_ready: false
                }
            ),
            "{r:?}"
        );
        assert!(t.elapsed() < Duration::from_millis(35), "{:?}", t.elapsed());
    }
    #[test]
    fn send_deadline_applies_to_external_send_only() {
        let cfg = Config {
            send_deadline_ms: Some(400),
            ..Config::default()
        };
        let c = fake_cfg(40, 0, ok_reply(), true, cfg);
        let (_, r) = c.score(
            "s",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        assert!(matches!(r, T2Result::Scored(_)), "{r:?}");
        // every other class keeps the 10 ms deadline
        let (_, r) = c.score(
            "s",
            "p",
            "db.write",
            SideEffect::Write,
            "r",
            &json!({}),
            false,
        );
        assert!(
            matches!(
                r,
                T2Result::Timeout {
                    cache_not_ready: false
                }
            ),
            "{r:?}"
        );
    }
    #[test]
    fn scored_within_deadline() {
        let c = fake(0, 0, ok_reply());
        let (_, r) = c.score(
            "s",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        match r {
            T2Result::Scored(s) => assert_eq!(s.score, Some(0.8)),
            x => panic!("{x:?}"),
        }
    }
    #[test]
    fn cache_not_ready_is_timeout() {
        let c = fake(0, 200, ok_reply());
        c.ingest("s", "untrusted text");
        let (_, r) = c.score(
            "s",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        assert!(
            matches!(
                r,
                T2Result::Timeout {
                    cache_not_ready: true
                }
            ),
            "{r:?}"
        );
        // other sessions are unaffected
        assert!(c.cache_ready("other"));
    }
    #[test]
    fn per_mandate_session_state_isolated() {
        let c = fake(0, 0, ok_reply());
        c.ingest("m:A/s1", "untrusted for A");
        assert!(c.has_untrusted("m:A/s1"));
        assert!(!c.has_untrusted("m:B/s1"));
        assert!(!c.has_untrusted("m:A/s2"));
    }
    #[test]
    fn queue_wait_counts_toward_deadline() {
        // one shared session, serialized: the 2nd call waits behind the 1st (8 ms each, 10 ms deadline)
        let c = Arc::new(fake(8, 0, ok_reply()));
        let c2 = c.clone();
        let h = std::thread::spawn(move || {
            c2.score(
                "a",
                "p",
                "mail.send",
                SideEffect::ExternalSend,
                "r",
                &json!({}),
                false,
            )
            .1
        });
        std::thread::sleep(Duration::from_millis(1));
        let (_, r2) = c.score(
            "b",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        let r1 = h.join().unwrap();
        assert!(matches!(r1, T2Result::Scored(_)), "{r1:?}");
        assert!(
            matches!(
                r2,
                T2Result::Timeout {
                    cache_not_ready: false
                }
            ),
            "{r2:?}"
        );
    }
    #[test]
    fn periodic_recheck_failure_fails_closed() {
        let c = fake_probe(0, 0, ok_reply(), false);
        assert!(!c.recheck(Duration::from_secs(2)));
        assert!(c.unavailable().is_some());
        let (_, r) = c.score(
            "s",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        assert!(matches!(r, T2Result::Unavailable));
        let ok = fake_probe(0, 0, ok_reply(), true);
        assert!(ok.recheck(Duration::from_secs(2)));
        assert!(ok.unavailable().is_none());
        assert_eq!(Config::default().recheck_secs, 60);
    }
}

#[cfg(test)]
mod dead_t {
    use super::*;
    use crate::rules::apply;
    use crate::Outcome;
    #[test]
    fn refused_sidecar_fails_closed() {
        let c = Client::dead(Config::default(), "t2cfg-v0".into(), "determinism".into());
        let (_, r) = c.score(
            "s",
            "p",
            "mail.send",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
        );
        assert!(matches!(r, T2Result::Unavailable));
        assert_eq!(
            apply(
                Outcome::Allow,
                SideEffect::ExternalSend,
                &r,
                &c.cfg,
                crate::rules::Ctx {
                    untrusted_in_session: true
                }
            )
            .outcome,
            Outcome::Escalate
        );
        assert_eq!(
            apply(
                Outcome::Allow,
                SideEffect::Read,
                &r,
                &c.cfg,
                crate::rules::Ctx {
                    untrusted_in_session: true
                }
            )
            .outcome,
            Outcome::Allow
        );
    }
}

#[cfg(test)]
mod export_t {
    use super::*;
    use std::os::unix::net::UnixListener;
    #[test]
    fn export_request_only_in_dev_export_builds() {
        let p = std::env::temp_dir().join(format!("t2exp{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let l = UnixListener::bind(&p).unwrap();
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let s2 = seen.clone();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut w = s.try_clone().unwrap();
            for line in BufReader::new(s).lines().map_while(Result::ok) {
                let v: Value = serde_json::from_str(&line).unwrap();
                s2.lock().unwrap().push(v.clone());
                let _ = writeln!(
                    w,
                    "{}",
                    json!({"id": v["id"], "op": "score", "scored": false})
                );
            }
        });
        let c = Client::from_stream(
            UnixStream::connect(&p).unwrap(),
            Config::default(),
            "x".into(),
            None,
        )
        .unwrap();
        c.score_ex(
            "s",
            "p",
            "t",
            SideEffect::ExternalSend,
            "r",
            &json!({}),
            false,
            true,
        );
        let got = seen.lock().unwrap()[0].get("export").cloned();
        if Client::dev_export_compiled() {
            assert_eq!(got, Some(json!(true)));
        } else {
            assert_eq!(got, None, "release/default builds never request an export");
        }
    }
}

#[cfg(test)]
mod amx_t {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn amx_must_be_proven_off() {
        let r = |a: Value| json!({ "amx": a });
        assert!(check_amx(&r(json!({"xtiledata_granted": false})), false).is_ok());
        for bad in [
            json!({"xtiledata_granted": true}),
            json!({"xtiledata_granted": null}),
            json!({"xtiledata_granted": "false"}),
            json!({"shim_mapped": true}), // "shim loaded" is not proof
            json!(null),
        ] {
            assert!(check_amx(&r(bad.clone()), false).is_err(), "{bad}");
        }
        assert!(check_amx(&json!({}), false).is_err(), "no amx report");
        // dev-only AMX-on diagnostic accepts `true`, still never unknown
        assert!(check_amx(&r(json!({"xtiledata_granted": true})), true).is_ok());
        assert!(check_amx(&r(json!({"xtiledata_granted": null})), true).is_err());
    }

    #[test]
    fn shim_pinned_by_sha256() {
        assert_eq!(
            noamx_sha256(),
            "2634166910b2503f7d3e6fd354fcf9607a3b4ddfde119d8840a40c8b4d97d205"
        );
        let d = std::env::temp_dir().join(format!("noamx-t-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("noamx.so");
        std::fs::write(&f, b"not the shim").unwrap();
        let sha = allowlist::sha256_file(&f).unwrap();
        assert!(verify_noamx_shim(&f, noamx_sha256()).is_err(), "unpinned file refused");
        let ok = verify_noamx_shim(&f, &sha).unwrap();
        assert!(ok.is_absolute());
        assert!(verify_noamx_shim(&d.join("missing.so"), &sha).is_err());
        let _ = std::fs::remove_dir_all(&d);
        // The in-tree build (make noamx) must match the pin when present.
        let real = default_noamx_shim();
        if real.exists() {
            verify_noamx_shim(&real, noamx_sha256()).unwrap();
        } else {
            eprintln!("note: {} not built (make noamx); pin check of the real shim skipped", real.display());
        }
    }

    fn fake_amx(probe_amx: Value) -> Client {
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "t2amx{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        let l = UnixListener::bind(&p).unwrap();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut w = s.try_clone().unwrap();
            for line in BufReader::new(s).lines().map_while(Result::ok) {
                let v: Value = serde_json::from_str(&line).unwrap();
                let _ = writeln!(
                    w,
                    "{}",
                    json!({"id": v["id"], "op": "probe", "determinism_ok": true, "determinism": "fake", "amx": probe_amx})
                );
            }
        });
        Client::from_stream(
            UnixStream::connect(&p).unwrap(),
            Config::default(),
            "x".into(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn periodic_recheck_fails_closed_if_amx_appears() {
        let c = fake_amx(json!({"xtiledata_granted": true}));
        assert!(!c.recheck(Duration::from_secs(2)), "probes pass but AMX granted");
        assert!(c.unavailable().unwrap().contains("xtiledata_granted=true"));
        let c = fake_amx(json!({"shim_mapped": true}));
        assert!(!c.recheck(Duration::from_secs(2)), "no proof");
        let c = fake_amx(json!({"xtiledata_granted": false}));
        assert!(c.recheck(Duration::from_secs(2)));
        assert!(c.unavailable().is_none());
    }
}
