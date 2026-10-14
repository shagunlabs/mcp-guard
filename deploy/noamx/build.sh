#!/bin/sh
# Reproducible build of the Tier 2 AMX-off shim (vendored verbatim from the research
# tier2-prototype/concurrency/noamx.c). The shim interposes libc syscall() and makes
# arch_prctl(ARCH_REQ_XCOMP_PERM / ARCH_GET_XCOMP_PERM) fail with EPERM, so ONNX Runtime / oneDNN never
# get XTILEDATA permission and fall back to non-AMX kernels (AMX INT8 drifted under load).
# The Edge pins the built .so by sha256 (noamx.so.sha256) and refuses Tier 2 on any mismatch; the scorer
# additionally proves AMX is off with a raw ARCH_GET_XCOMP_PERM after model load (the .so is not proof).
set -eu
cd "$(dirname "$0")"
CC="${CC:-gcc}"
sha256sum -c noamx.c.sha256 >/dev/null || { echo "noamx.c does not match its pin (noamx.c.sha256)" >&2; exit 1; }
# Fixed flags, fixed relative source path, no timestamps embedded => byte-identical output for a given
# toolchain. Pin produced with: gcc (Debian 14.2.0-19) 14.2.0, binutils 2.44 (also matches the research binary).
"$CC" -O2 -shared -fPIC -o noamx.so.tmp noamx.c
got=$(sha256sum noamx.so.tmp | cut -d' ' -f1)
want=$(cut -d' ' -f1 noamx.so.sha256)
if [ "$got" != "$want" ]; then
  echo "noamx.so sha256 $got != pin $want (toolchain: $("$CC" --version | head -1)); not installed." >&2
  echo "A different toolchain needs a reviewed re-pin of deploy/noamx/noamx.so.sha256 (the Edge refuses unpinned shims)." >&2
  rm -f noamx.so.tmp; exit 1
fi
mv noamx.so.tmp noamx.so
echo "built deploy/noamx/noamx.so sha256:$got"
