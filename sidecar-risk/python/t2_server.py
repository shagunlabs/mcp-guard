#!/usr/bin/env python3
"""Sentryra Tier 2 sidecar server: wraps the research scorer (tier2-prototype/scorer.py, read-only) behind a
local unix socket speaking newline-delimited JSON. Runs in the customer's data plane next to the Edge.

- ONE process, ONE thread, ONE ONNX session (HANDOFF §6: no parallel INT8 sessions). Requests are
  served strictly in order; the Edge enforces the deadline (Python cannot preempt a call).
- Model digest is checked by the Edge against its allowlist before launch, and again here
  (`--expect-sha256`) before the session is created; mismatch -> exit (contract §6: refuse to start).
- Ops: hello | ingest{session,text} -> ack | score{session,purpose,tool,side_effect,resource,args[,diag]}
  | flush (computes per-window diagnostic scores for diag requests, off the decision path).
"""
import argparse, hashlib, json, os, socket, sys

ap = argparse.ArgumentParser()
ap.add_argument("--scorer-dir", required=True)
ap.add_argument("--socket", required=True)
ap.add_argument("--expect-sha256", required=True)
ap.add_argument("--config", required=True, help="versioned scorer config (scorer version + weights ref + threshold)")
a = ap.parse_args()
sys.path.insert(0, a.scorer_dir)
import scorer  # noqa: E402  (the research single entrypoint)

model = os.path.join(a.scorer_dir, "onnx", "model_int8.onnx")
if a.expect_sha256 != scorer.EXPECTED_MODEL_SHA256:
    sys.exit(f"t2_server: Edge allowlist digest {a.expect_sha256} != scorer pin {scorer.EXPECTED_MODEL_SHA256}; refusing")
scorer.verify_model(model, a.expect_sha256)          # raises ModelDigestMismatch before loading
CFG = json.load(open(a.config))
if CFG["model_sha256"] != a.expect_sha256 or CFG["scorer_version"] != scorer.MODEL_VERSION:
    sys.exit(f"t2_server: config {CFG['config_version']} does not match model/scorer version; refusing")
wpath = os.path.join(a.scorer_dir, CFG["weights_file"])
if hashlib.sha256(open(wpath, "rb").read()).hexdigest() != CFG["weights_sha256"]:
    sys.exit(f"t2_server: weights sha256 != config {CFG['config_version']}; refusing")
W = json.load(open(wpath))
ENC = scorer.Encoder(model)                          # the one and only INT8 session
for _ in range(5):                                   # warm-up before accepting (stateless: no session data)
    ENC.one("warm-up text for the tier two scorer session " * 8)

# Startup self-check against PINNED reference scores (the research probe file, incl. a long probe).
# Each probe is scored in a fresh session on the one INT8 session; |score - reference| must be
# <= probe_tolerance. Missing file, bad pin, or any probe out of tolerance => refuse to start.
# File format: {"reference_version": str, "probes": [{"id", "purpose", "untrusted": [str],
#   "tool", "side_effect", "resource", "args": {...}, "score": float}]}


def self_check():
    rp = os.path.join(a.scorer_dir, CFG["probe_reference_file"])
    if not os.path.exists(rp):
        return False, {"error": f"probe reference file missing: {CFG['probe_reference_file']}"}
    raw = open(rp, "rb").read()
    pin = CFG.get("probe_reference_sha256")
    if pin and hashlib.sha256(raw).hexdigest() != pin:
        return False, {"error": "probe reference sha256 != config pin"}
    ref = json.loads(raw)
    tol, out, ok = float(CFG["probe_tolerance"]), [], bool(ref.get("probes"))
    for pr in ref.get("probes", []):
        sc = scorer.Tier2Scorer(W=W, encoder=ENC)
        for u in pr.get("untrusted", []):
            sc.ingest(u)
        r = sc.score_call(pr["purpose"], pr.get("tool", "mail.send"), pr.get("side_effect", "external_send"), pr.get("resource"), pr["args"])
        got = None if r is None else r["score"]
        good = got is not None and abs(got - float(pr["score"])) <= tol
        ok &= good
        out.append({"id": pr.get("id"), "ref": pr["score"], "got": got, "ok": good,
                    "windows": None if r is None else f"{r['windows_read']}/{r['windows_total']}"})
    return ok, {"reference_version": ref.get("reference_version"), "pinned": bool(pin), "tolerance": tol, "probes": out}


DET_OK, DET = self_check()
print(f"t2_server: probe self-check {'PASS' if DET_OK else 'FAIL'} {json.dumps(DET)}", file=sys.stderr, flush=True)
if not DET_OK:
    sys.exit("t2_server: probe self-check failed; refusing to start (Edge fails closed)")
SESS = {}
DIAG = []                                            # (score_id, session, purpose, text, untrusted snapshot, resp)


def session(k):
    if k not in SESS:
        SESS[k] = scorer.Tier2Scorer(W=W, encoder=ENC)
    return SESS[k]


def window_scores(sc, purpose, text, untrusted, resp):
    """Raw score of each window the scorer read (same selector), for evidence/bench only."""
    if resp is None:
        return None
    if set(resp["reason_codes"]) & {scorer.RC_FRAG, scorer.RC_PLACEHOLDER}:
        return [resp["score"]]
    ws, _ = scorer.windows(ENC, text)
    idx = scorer.select(ws, untrusted, purpose)
    tmp = scorer.Tier2Scorer.__new__(scorer.Tier2Scorer)
    tmp.W, tmp.enc, tmp.chunk, tmp.pemb, tmp.untrusted, tmp.sink_hist = sc.W, ENC, sc.chunk, sc.pemb, list(untrusted), {}
    out = []
    for i in idx:
        f, _, _ = tmp._features(purpose, ws[i])
        out.append({"window": i, "score": round(scorer.score_from_features(f, sc.W), 4)})
    return out


def handle(m):
    op = m.get("op")
    if op == "hello":
        return {"id": m["id"], "op": "hello", "model_digest": scorer.MODEL_DIGEST, "model_version": scorer.MODEL_VERSION, "model_id": scorer.MODEL_ID,
                "config_version": CFG["config_version"], "determinism_ok": DET_OK, "determinism": DET}
    if op == "ingest":
        session(m["session"]).ingest(m["text"])
        return {"ack": m["id"], "session": m["session"]}
    if op == "score":
        sc = session(m["session"])
        args = m.get("args") or {}
        r = sc.score_call(m["purpose"], m["tool"], m["side_effect"], m.get("resource"), args)
        if m.get("diag"):
            text = " ".join(v for k, v in args.items() if k in scorer.TEXT_FIELDS and isinstance(v, str)) or None
            DIAG.append((m["id"], m["session"], m["purpose"], text, list(sc.untrusted), r, m["tool"]))
        out = {"id": m["id"], "op": "score", "session": m["session"], "tool": m["tool"], "scored": r is not None}
        out.update(r or {})
        return out
    if op == "flush":
        outs = []
        for sid, sk, purpose, text, unt, r, tool in DIAG:
            outs.append({"diag": sid, "session": sk, "tool": tool, "score": None if r is None else r["score"],
                         "window_scores": window_scores(SESS[sk], purpose, text, unt, r)})
        DIAG.clear()
        return outs + [{"id": m["id"], "op": "flush"}]
    return {"id": m.get("id"), "op": "error", "error": "unknown op"}


try:
    os.unlink(a.socket)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(a.socket); os.chmod(a.socket, 0o600); srv.listen(1)
while True:
    conn, _ = srv.accept()
    f = conn.makefile("rwb", buffering=0)
    for line in f:
        try:
            res = handle(json.loads(line))
        except Exception as e:  # malformed request: answer, never crash the session
            res = {"id": None, "op": "error", "error": type(e).__name__}
        for r in (res if isinstance(res, list) else [res]):
            f.write((json.dumps(r) + "\n").encode())
    conn.close()
    if os.environ.get("T2_SERVER_ONE_SHOT", "1") == "1":
        break
