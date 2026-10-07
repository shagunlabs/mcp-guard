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
import argparse, json, os, socket, sys

ap = argparse.ArgumentParser()
ap.add_argument("--scorer-dir", required=True)
ap.add_argument("--socket", required=True)
ap.add_argument("--expect-sha256", required=True)
a = ap.parse_args()
sys.path.insert(0, a.scorer_dir)
import scorer  # noqa: E402  (the research single entrypoint)

model = os.path.join(a.scorer_dir, "onnx", "model_int8.onnx")
if a.expect_sha256 != scorer.EXPECTED_MODEL_SHA256:
    sys.exit(f"t2_server: Edge allowlist digest {a.expect_sha256} != scorer pin {scorer.EXPECTED_MODEL_SHA256}; refusing")
scorer.verify_model(model, a.expect_sha256)          # raises ModelDigestMismatch before loading
ENC = scorer.Encoder(model)                          # the one and only session
for _ in range(5):                                   # warm-up before accepting (stateless: no session data)
    ENC.one("warm-up text for the tier two scorer session " * 8)
SESS = {}
DIAG = []                                            # (score_id, session, purpose, text, untrusted snapshot, resp)


def session(k):
    if k not in SESS:
        SESS[k] = scorer.Tier2Scorer(encoder=ENC)
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
        return {"id": m["id"], "op": "hello", "model_digest": scorer.MODEL_DIGEST, "model_version": scorer.MODEL_VERSION, "model_id": scorer.MODEL_ID}
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
