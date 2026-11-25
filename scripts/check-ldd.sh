#!/usr/bin/env bash
# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Lists the shared libraries a Linux binary built with the DuckDB engine needs
# at run time and fails if one is missing or not on the expected list. The
# engine is C++, so the binary links libstdc++ and libgcc_s dynamically, next to
# glibc: it runs on a glibc distribution that has libstdc++ installed, and not
# on scratch, distroless-static or Alpine. The tests workflow runs it.
#
# Usage: scripts/check-ldd.sh <binary>
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <binary>" >&2
  exit 2
fi

listing=$(ldd "$1")
echo "$listing"

if grep -q 'not found' <<<"$listing"; then
  echo "check-ldd: a library the binary needs is missing" >&2
  exit 1
fi

# The first field of each line, without its folder: libstdc++.so.6, libm.so.6,
# linux-vdso.so.1, ld-linux-x86-64.so.2 ...
unexpected=$(awk '{print $1}' <<<"$listing" | xargs -n1 basename |
  grep -Ev '^(linux-vdso\.so|ld-linux|libstdc\+\+\.so|libgcc_s\.so|libm\.so|libc\.so|libresolv\.so|libdl\.so|libpthread\.so|librt\.so)' || true)
if [ -n "$unexpected" ]; then
  echo "check-ldd: libraries that are not on the expected list:" >&2
  echo "$unexpected" >&2
  exit 1
fi

if ! grep -q 'libstdc++\.so' <<<"$listing"; then
  echo "check-ldd: the binary does not link libstdc++: is the engine in it?" >&2
  exit 1
fi
