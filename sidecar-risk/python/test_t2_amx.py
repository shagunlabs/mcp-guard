"""Tests for the scorer sidecar's AMX proof (t2_server.py). Needs the scorer dir with the pinned INT8 model
and the built shim (deploy/noamx/build.sh):
T2_SCORER_DIR=/path/to/tier2-prototype python3 sidecar-risk/python/test_t2_amx.py -v
The sidecar must read the kernel's XTILEDATA permission itself (raw ARCH_GET_XCOMP_PERM through libc's own
syscall(), which the shim cannot intercept) and refuse to start when it is granted."""
import json, os, socket, subprocess, sys, tempfile, time, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.environ.get("T2_SCORER_DIR", os.path.join(HERE, "../../../tier2-prototype"))
CODE = os.path.abspath(os.path.join(HERE, "../.."))
SHIM = os.path.join(CODE, "deploy/noamx/noamx.so")
CFG = os.path.join(CODE, "sidecar-risk/scorer-config.t2-v0-pooled.json")
MODEL_SHA = json.load(open(CFG))["model_sha256"]
HAVE = os.path.exists(os.path.join(DIR, "onnx", "model_int8.onnx")) and os.path.exists(SHIM)
AMX_CPU = any("amx_tile" in l.split() for l in open("/proc/cpuinfo") if l.startswith("flags"))


def launch(shim, *extra):
    sock = os.path.join(tempfile.mkdtemp(), "t2.sock")
    env = {k: v for k, v in os.environ.items() if k != "LD_PRELOAD"}
    if shim:
        env["LD_PRELOAD"] = SHIM
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "t2_server.py"), "--scorer-dir", DIR, "--socket", sock,
                          "--expect-sha256", MODEL_SHA, "--config", CFG, *extra],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    t0 = time.time()
    while time.time() - t0 < 60:
        if p.poll() is not None:
            return p, None, p.stderr.read()
        try:
            s = socket.socket(socket.AF_UNIX); s.connect(sock); break
        except OSError:
            time.sleep(0.05)
    f = s.makefile("rwb", buffering=0)
    f.write(b'{"op":"hello","id":1}\n'); hello = json.loads(f.readline())
    f.write(b'{"op":"probe","id":2}\n'); probe = json.loads(f.readline())
    f.close(); s.close(); p.wait(timeout=30)  # close the makefile too, or the fd stays open and the server never sees EOF
    return p, (hello, probe), p.stderr.read()


@unittest.skipUnless(HAVE, "scorer model or built shim not present")
class AmxProof(unittest.TestCase):
    def test_shim_on_reports_not_granted(self):
        p, r, err = launch(True)
        self.assertIsNotNone(r, err)
        hello, probe = r
        a = hello["amx"]
        self.assertIs(a["xtiledata_granted"], False)
        self.assertTrue(a["shim_mapped"])
        if a["arch"] == "x86_64":
            # the shim answers EPERM to ARCH_GET_XCOMP_PERM through the interposed syscall(), yet the
            # sidecar still read the real mask: its check does not go through the shim
            self.assertTrue(a["shim_interposing"])
            self.assertIsNotNone(a["xcomp_perm"])
            self.assertEqual(int(a["xcomp_perm"], 16) >> 18 & 1, 0)
        self.assertTrue(probe["determinism_ok"])
        self.assertIs(probe["amx"]["xtiledata_granted"], False)
        self.assertIs(probe["determinism"]["xtiledata_granted"], False)

    def test_shim_off_refuses_on_amx_cpu(self):
        p, r, err = launch(False)
        if AMX_CPU:
            self.assertIsNone(r, "sidecar must refuse to start with XTILEDATA granted")
            self.assertNotEqual(p.returncode, 0)
            self.assertIn('"xtiledata_granted": true', err)
            self.assertIn("refusing to start", err)
        else:
            print("note: CPU has no AMX (amx_tile); shim off still reports not granted", file=sys.stderr)
            self.assertIs(r[0]["amx"]["xtiledata_granted"], False)

    def test_diagnostic_allow_amx_reports_granted(self):
        p, r, err = launch(False, "--diagnostic-allow-amx")
        self.assertIsNotNone(r, err)
        hello, _ = r
        self.assertTrue(hello["config_version"].endswith("+diag-amx"))
        self.assertIs(hello["amx"]["xtiledata_granted"], AMX_CPU)


if __name__ == "__main__":
    unittest.main()
