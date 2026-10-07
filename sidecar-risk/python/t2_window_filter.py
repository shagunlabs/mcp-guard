"""Tier 2 window filter. PROTOTYPE, off by default (Edge `--tier2-window-filter` -> server `--window-filter`).

Scores only the windows of an outbound text that hold content traceable to untrusted output seen in the
session: a window is traceable when it shares at least one scorer token with the session's untrusted
outputs, after removing purpose words and stopwords (the same token set the scorer's carry_lex uses).
A text that fits in one window is always read in full.

HARD RULE: every skipped window counts as unread. The response carries `windows_skipped` and
`windows_read < windows_total`, so the Edge records T2_PARTIAL_READ and an outbound send escalates.
A text with no traceable window is read not at all: score 0.0 placeholder, windows_read 0 (the Edge
exports no score for it). The filter is lexical, so a paraphrased leak (no shared tokens) is skipped,
never scored: it can only be held by T2_PARTIAL_READ.

Feature maths is scorer.Tier2Scorer._features (the research, read-only) on the filtered window set, with each
distinct chunk encoded once per call (identical vectors: one text per inference call, deterministic path).
"""
import numpy as np


class _NothingRead(Exception):
    def __init__(self, total):
        self.total = total


def traceable(S, ws, untrusted, purpose):
    """Indexes of windows that share a scorer token with untrusted output (purpose words, stopwords out)."""
    if len(ws) <= 1:
        return list(range(len(ws)))
    ut = S.toks(" ".join(untrusted)) - S.toks(purpose) - S.STOP
    return [i for i, w in enumerate(ws) if ut & S.toks(w)]


def features_on(S, sc, purpose, read):
    """scorer.Tier2Scorer._features maths for a given list of read windows (v0 pooled / V1 perwin_max)."""
    U = np.stack([sc.chunk[S.H(c)] for u in sc.untrusted for c in S.chunks(u)])
    p = sc._purpose(purpose)
    ucov = np.clip(U @ p, 0, 1)
    ut = S.toks(" ".join(sc.untrusted)) - S.toks(purpose) - S.STOP
    cache = {}

    def E(c):
        if c not in cache:
            cache[c] = sc.enc.one(c)
        return cache[c]
    if sc.cfg["pooling"] == "perwin_max":
        best = None
        for w in read:
            Ow = np.stack([E(c) for c in S.chunks(w)])
            fw = dict(carry_sem=float(np.clip(((Ow @ U.T) * (1 - ucov)[None, :]).max(), 0, 1)),
                      carry_lex=min(1.0, len(ut & S.toks(w)) / max(1, min(len(ut), 6))),
                      purpose_align=float(np.clip(Ow @ p, -1, 1).min()), send_after_untrusted=1.0)
            if best is None or S.score_from_features(fw, sc.W) > S.score_from_features(best, sc.W):
                best = fw
        return best
    O = np.stack([E(c) for w in read for c in S.chunks(w)])
    carry_sem = float(np.clip(((O @ U.T) * (1 - ucov)[None, :]).max(), 0, 1))
    carry_lex = min(1.0, len(ut & S.toks(" ".join(read))) / max(1, min(len(ut), 6)))
    return dict(carry_sem=carry_sem, carry_lex=carry_lex, purpose_align=float(np.clip(O @ p, -1, 1).min()),
                send_after_untrusted=1.0)


def filtered(S, base):
    """Subclass of a scorer class (Tier2Scorer or a cached variant) that reads only traceable windows."""
    import time

    class WindowFiltered(base):
        window_filter = True

        def _features(self, purpose, outbound):
            ws, _ = S.windows(self.enc, outbound)
            idx = traceable(S, ws, self.untrusted, purpose)
            if not idx:
                raise _NothingRead(len(ws))
            return features_on(S, self, purpose, [ws[i] for i in idx]), len(idx), len(ws)

        def _resp(self, score, codes, factors, t0, read, total, escalate, side_effect):
            r = super()._resp(score, codes, factors, t0, read, total, escalate, side_effect)
            r["windows_skipped"] = int(total) - int(read)
            r["window_filter"] = True
            return r

        def score_call(self, purpose, tool, side_effect, resource, args):
            t0 = time.perf_counter()
            try:
                return super().score_call(purpose, tool, side_effect, resource, args)
            except _NothingRead as e:   # every window skipped: nothing read, never a score
                return self._resp(0.0, [], [], t0, 0, e.total, True, side_effect)

    return WindowFiltered
