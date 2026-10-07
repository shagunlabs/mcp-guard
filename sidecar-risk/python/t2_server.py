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
ap.add_argument("--feature-export", action="store_true", help="DEV/HELDOUT: include full feature export in diag flush")
ap.add_argument("--window-filter", action="store_true", help="PROTOTYPE: score only windows traceable to untrusted output; skipped windows are reported (windows_skipped) and count as unread")
ap.add_argument("--diagnostic-no-probe", action="store_true", help="DIAGNOSTIC ONLY: skip the probe check (score-only pass)")
a = ap.parse_args()
sys.path.insert(0, a.scorer_dir)
import scorer  # noqa: E402  (the research single entrypoint)

model = os.path.join(a.scorer_dir, "onnx", "model_int8.onnx")
if a.expect_sha256 != scorer.EXPECTED_MODEL_SHA256:
    sys.exit(f"t2_server: Edge allowlist digest {a.expect_sha256} != scorer pin {scorer.EXPECTED_MODEL_SHA256}; refusing")
scorer.verify_model(model, a.expect_sha256)          # raises ModelDigestMismatch before loading
CFG = json.load(open(a.config))
KEY = CFG["scorer_config"]
if KEY not in scorer.CONFIGS or scorer.CONFIGS[KEY]["config_version"] != CFG["config_version"]:
    sys.exit(f"t2_server: config {CFG['config_version']} is not scorer config {KEY!r}; refusing")
if abs(float(scorer.CONFIGS[KEY]["threshold"]) - float(CFG["threshold"])) > 1e-12:
    sys.exit(f"t2_server: config threshold {CFG['threshold']} != scorer {KEY} threshold; refusing")
if CFG["model_sha256"] != a.expect_sha256 or CFG["scorer_version"] != scorer.MODEL_VERSION:
    sys.exit(f"t2_server: config {CFG['config_version']} does not match model/scorer version; refusing")
W = None                                             # V1: weights pinned in scorer.CONFIGS
if CFG.get("weights_file"):
    wpath = os.path.join(a.scorer_dir, CFG["weights_file"])
    if hashlib.sha256(open(wpath, "rb").read()).hexdigest() != CFG["weights_sha256"]:
        sys.exit(f"t2_server: weights sha256 != config {CFG['config_version']}; refusing")
    W = json.load(open(wpath))
THR = float(CFG["threshold"])
EXPORT = a.feature_export   # only passed by an Edge built with the dev-export feature
CFG_ID = CFG["config_version"] + ("+diag-noprobe" if a.diagnostic_no_probe else "")


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t2_window_filter as WF  # noqa: E402
SCORER_CLS = WF.filtered(scorer, scorer.Tier2Scorer) if a.window_filter else scorer.Tier2Scorer


def new_scorer(cls=None):
    return (cls or SCORER_CLS)(W=W, encoder=ENC, threshold=THR, config=KEY)


def selected(ws, untrusted, purpose):
    """Windows the active scorer reads (budget selector, or the window filter)."""
    return WF.traceable(scorer, ws, untrusted, purpose) if a.window_filter else scorer.select(ws, untrusted, purpose)


ENC = scorer.Encoder(model)                          # the one and only INT8 session
for _ in range(5):                                   # warm-up before accepting (stateless: no session data)
    ENC.one("warm-up text for the tier two scorer session " * 8)

# Startup self-check against PINNED reference scores (the research probe file, incl. a long probe).
# Each probe is scored in a fresh session on the one INT8 session; |score - reference| must be
# <= probe_tolerance. Missing file, bad pin, or any probe out of tolerance => refuse to start.
# File format: {"reference_version": str, "probes": [{"id", "purpose", "untrusted": [str],
#   "tool", "side_effect", "resource", "args": {...}, "score": float}]}


def self_check():
    """Probe check against the research pinned reference (handoff/probe_refs.json format). The file must be
    pinned to the ACTIVE config: same config_version, model sha256 and threshold, else refuse."""
    rp = os.path.join(a.scorer_dir, CFG["probe_reference_file"])
    if not os.path.exists(rp):
        return False, {"error": f"probe reference file missing: {CFG['probe_reference_file']}"}
    raw = open(rp, "rb").read()
    pin = CFG.get("probe_reference_sha256")
    if pin and hashlib.sha256(raw).hexdigest() != pin:
        return False, {"error": "probe reference sha256 != config pin"}
    ref = json.loads(raw)
    for k, want in (("config_version", CFG["config_version"]), ("model_sha256", CFG["model_sha256"])):
        if ref.get(k) != want:
            return False, {"error": f"probe reference {k} {ref.get(k)!r} != active {want!r}"}
    if not isinstance(ref.get("threshold"), (int, float)) or abs(float(ref["threshold"]) - THR) > 1e-12:
        return False, {"error": f"probe reference threshold {ref.get('threshold')!r} != active {THR}"}
    tol = min(float(CFG["probe_tolerance"]), float(ref.get("tolerance", CFG["probe_tolerance"])))
    out, ok = [], bool(ref.get("probes"))
    for pr in ref.get("probes", []):
        sc = new_scorer(scorer.Tier2Scorer)          # fresh state per probe, same INT8 session; never filtered
        for u in pr.get("untrusted", []):
            sc.ingest(u)
        r = sc.score_call(pr["purpose"], "send_email", "external_send", "mailto:probe@example.invalid", {"body": pr["outbound"]})
        got = None if r is None else r["score"]
        good = got is not None and abs(got - float(pr["ref_score"])) <= tol \
            and r["windows_read"] == pr.get("windows_read") and r["windows_total"] == pr.get("windows_total")
        ok &= good
        out.append({"id": pr.get("id"), "ref": pr["ref_score"], "got": got, "ok": good,
                    "windows": None if r is None else f"{r['windows_read']}/{r['windows_total']}"})
    return ok, {"reference": CFG["probe_reference_file"], "config_version": ref.get("config_version"), "tolerance": tol, "probes": out}


if a.diagnostic_no_probe:
    DET_OK, DET = True, {"skipped": "DIAGNOSTIC ONLY (--diagnostic-no-probe): no probe reference for this config"}
else:
    DET_OK, DET = self_check()
print(f"t2_server: probe self-check {'PASS' if DET_OK else 'FAIL'} {json.dumps(DET)}", file=sys.stderr, flush=True)
if not DET_OK:
    sys.exit("t2_server: probe self-check failed; refusing to start (Edge fails closed)")
SESS = {}
DIAG = []                                            # (score_id, session, purpose, text, untrusted snapshot, resp)


def session(k):
    if k not in SESS:
        SESS[k] = new_scorer()          # per (mandate, session) state; one shared INT8 session
    return SESS[k]


def _snap(sc, untrusted):
    tmp = new_scorer()
    tmp.chunk, tmp.pemb, tmp.untrusted = sc.chunk, sc.pemb, list(untrusted)
    return tmp


def window_scores(sc, purpose, text, untrusted, resp):
    """Raw score of each window the scorer read (same selector), for evidence/bench only."""
    if resp is None:
        return None
    if set(resp["reason_codes"]) & {scorer.RC_FRAG, scorer.RC_PLACEHOLDER}:
        return [resp["score"]]
    ws, _ = scorer.windows(ENC, text)
    idx = selected(ws, untrusted, purpose)
    tmp = _snap(sc, untrusted)
    tmp.cfg = dict(tmp.cfg, pooling="pooled")       # one window at a time = per-window features
    out = []
    for i in idx:
        f, _, _ = tmp._features(purpose, ws[i])
        out.append({"window": i, "score": round(scorer.score_from_features(f, tmp.W), 4)})
    return out


def feature_export(sc, purpose, text, untrusted, resp):
    """DEV / HELDOUT export (diag only, never on the decision path): window texts, the untrusted
    context the scorer saw, every feature value (decision features + per read window), scores."""
    if text is None:
        return {"text": None, "scored": resp is not None}
    ws, ntok = scorer.windows(ENC, text)
    idx = selected(ws, untrusted, purpose)
    tmp = _snap(sc, untrusted)
    dec = None
    if resp is not None and not (set(resp["reason_codes"]) & {scorer.RC_FRAG, scorer.RC_PLACEHOLDER}):
        try:
            f, r, t = tmp._features(purpose, text)
            dec = {"features": f, "score": round(scorer.score_from_features(f, tmp.W), 6), "windows_read": r, "windows_total": t}
        except WF._NothingRead as e:   # window filter skipped every window
            dec = {"features": None, "score": None, "windows_read": 0, "windows_total": e.total}
    per = []
    pw = _snap(sc, untrusted); pw.cfg = dict(pw.cfg, pooling="pooled")
    for i, w in enumerate(ws):
        e = {"window": i, "read": i in idx, "text": w}
        if untrusted:
            f, _, _ = pw._features(purpose, w)
            e.update(features=f, score=round(scorer.score_from_features(f, pw.W), 6))
        per.append(e)
    return {"purpose": purpose, "outbound_tokens": ntok, "untrusted_context": list(untrusted),
            "windows": per, "decision": dec, "weights": tmp.W, "threshold": THR,
            "response": resp}


def handle(m):
    op = m.get("op")
    if op == "hello":
        return {"id": m["id"], "op": "hello", "model_digest": scorer.MODEL_DIGEST, "model_version": scorer.MODEL_VERSION, "model_id": scorer.MODEL_ID,
                "config_version": CFG_ID, "window_filter": bool(a.window_filter), "determinism_ok": DET_OK, "determinism": DET}
    if op == "probe" and a.diagnostic_no_probe:
        return {"id": m["id"], "op": "probe", "determinism_ok": True, "determinism": DET}
    if op == "probe":   # periodic re-check, queued FIFO behind scoring on the one INT8 session
        ok, det = self_check()
        print(f"t2_server: periodic probe re-check {'PASS' if ok else 'FAIL'}", file=sys.stderr, flush=True)
        return {"id": m["id"], "op": "probe", "determinism_ok": ok, "determinism": det}
    if op == "ingest":
        session(m["session"]).ingest(m["text"])
        return {"ack": m["id"], "session": m["session"]}
    if op == "score":
        sc = session(m["session"])
        args = m.get("args") or {}
        r = sc.score_call(m["purpose"], m["tool"], m["side_effect"], m.get("resource"), args)
        if m.get("diag"):
            text = " ".join(v for k, v in args.items() if k in scorer.TEXT_FIELDS and isinstance(v, str)) or None
            DIAG.append((m["id"], m["session"], m["purpose"], text, list(sc.untrusted), r, m["tool"], bool(m.get("export")) and EXPORT))
        out = {"id": m["id"], "op": "score", "session": m["session"], "tool": m["tool"], "scored": r is not None}
        out.update(r or {})
        return out
    if op == "flush":
        outs = []
        for sid, sk, purpose, text, unt, r, tool, exp in DIAG:
            outs.append({"diag": sid, "session": sk, "tool": tool, "score": None if r is None else r["score"],
                         "window_scores": window_scores(SESS[sk], purpose, text, unt, r),
                         "export": feature_export(SESS[sk], purpose, text, unt, r) if exp else None})
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
