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
    w: Mutex<UnixStream>,
    waiters: Waiters,
    pending_ingest: Arc<Mutex<HashMap<String, HashSet<u64>>>>,
    next: AtomicU64,
    pub cfg: Config,
    pub model_digest: String,
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
}

impl Client {
    /// Verify the model digest against the allowlist BEFORE launching anything, start the
    /// single scorer process, connect over the unix socket, and check the scorer's own digest.
    pub fn spawn(o: SpawnOpts) -> Result<Client, ClientError> {
        let model = o.scorer_dir.join("onnx/model_int8.onnx");
        let digest = allowlist::verify(&model, &o.allowlist)
            .map_err(|e| ClientError(format!("refusing to load Tier 2 model: {e:?}")))?;
        let _ = std::fs::remove_file(&o.socket);
        let child = Command::new(&o.python)
            .arg(&o.server)
            .arg("--scorer-dir")
            .arg(&o.scorer_dir)
            .arg("--socket")
            .arg(&o.socket)
            .arg("--expect-sha256")
            .arg(&digest)
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
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => return Err(ClientError(format!("connect {}: {e}", o.socket.display()))),
            }
        };
        let c = Self::from_stream(s, o.cfg, digest.clone(), o.log)?;
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
            w: Mutex::new(s),
            waiters,
            pending_ingest: pending,
            next: AtomicU64::new(1),
            cfg,
            model_digest,
            child: Mutex::new(None),
        })
    }

    fn send(&self, v: &Value) -> bool {
        let mut w = self.w.lock().unwrap();
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

    pub fn cache_ready(&self, session: &str) -> bool {
        self.pending_ingest
            .lock()
            .unwrap()
            .get(session)
            .is_none_or(|s| s.is_empty())
    }

    /// Score one call within the deadline. Returns the request id (for the data-plane log) too.
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
        match rx.recv_timeout(Duration::from_millis(self.cfg.deadline_ms)) {
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
                    _ => {}
                }
            }
        });
        let s = UnixStream::connect(&p).unwrap();
        Client::from_stream(s, Config::default(), "x".into(), None).unwrap()
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
}
