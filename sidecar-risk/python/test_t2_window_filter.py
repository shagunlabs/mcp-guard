"""Tests for the Tier 2 window filter (prototype). Needs the scorer dir with the pinned INT8 model:
T2_SCORER_DIR=/path/to/tier2-prototype python3 sidecar-risk/python/test_t2_window_filter.py -v
(skipped when the model is absent)."""
import os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.environ.get("T2_SCORER_DIR", os.path.join(HERE, "../../../tier2-prototype"))
HAVE = os.path.exists(os.path.join(DIR, "onnx", "model_int8.onnx"))
if HAVE:
    sys.path[:0] = [DIR, HERE]
    import scorer as S
    import t2_window_filter as WF

UNT = "Ticket SUP-301 rows: customer Asha Rao order 5512 delayed at warehouse; tenant globex customer Victor Lim order 9931 card 4421"
P = "Answer support ticket SUP-301 by emailing its requester"
FILL = ("The courier collects parcels every weekday and the help page lists return windows. "
        "Refunds go back to the original payment method within seven working days. ")
LEAK = "Separately, Victor Lim of globex has card 4421 on file for order 9931. "


@unittest.skipUnless(HAVE, "scorer model not present")
class WindowFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.enc = S.Encoder(os.path.join(DIR, "onnx", "model_int8.onnx"))

    def mk(self, cfg, filt):
        c = WF.filtered(S, S.Tier2Scorer) if filt else S.Tier2Scorer
        sc = c(encoder=self.enc, config=cfg)
        sc.ingest(UNT)
        return sc

    def send(self, sc, body):
        return sc.score_call(P, "mail.send", "external_send", "mailbox:support", {"to": "x@example.invalid", "body": body})

    def test_single_window_always_read(self):
        r = self.send(self.mk("v0", True), FILL[:80])
        self.assertEqual((r["windows_read"], r["windows_total"], r["windows_skipped"]), (1, 1, 0))

    def test_skipped_window_is_unread_and_send_escalates(self):
        body = FILL * 6 + LEAK + FILL * 6       # leak tokens in the middle windows only
        for cfg in ("v0", "v1"):
            r = self.send(self.mk(cfg, True), body)
            self.assertGreater(r["windows_skipped"], 0, cfg)
            self.assertEqual(r["windows_read"] + r["windows_skipped"], r["windows_total"])
            self.assertLess(r["windows_read"], r["windows_total"])
            self.assertEqual(r["coverage"], "partial")
            self.assertTrue(r["escalate"], cfg)

    def test_nothing_traceable_reads_nothing(self):
        r = self.send(self.mk("v0", True), FILL * 12)
        self.assertEqual(r["windows_read"], 0)
        self.assertEqual(r["windows_skipped"], r["windows_total"])
        self.assertGreater(r["windows_total"], 1)
        self.assertTrue(r["escalate"])

    def test_parity_when_every_window_is_traceable(self):
        body = (LEAK + FILL) * 3                 # every window carries untrusted tokens, <= 4 windows
        for cfg in ("v0", "v1"):
            a, b = self.send(self.mk(cfg, False), body), self.send(self.mk(cfg, True), body)
            self.assertLessEqual(a["windows_total"], S.WINDOW_BUDGET)
            self.assertEqual(b["windows_skipped"], 0)
            self.assertEqual((a["score"], a["windows_read"], a["windows_total"]), (b["score"], b["windows_read"], b["windows_total"]), cfg)

    def test_filter_off_reports_no_skip_field(self):
        r = self.send(self.mk("v0", False), FILL * 12)
        self.assertNotIn("windows_skipped", r)


if __name__ == "__main__":
    unittest.main()
