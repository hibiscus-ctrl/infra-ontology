#!/usr/bin/env bash
# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Runs a release binary and checks it is the variant it says it is: it
# reports the expected version, and either answers a query ("query": the
# DuckDB engine is in it) or says the engine is not built in ("noquery").
# The release workflow runs it on the runner each binary was built on, so a
# binary that links but does not start is caught before it is published.
#
# Usage: scripts/smoke-release.sh <binary> <query|noquery> [<expected version>]
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
  echo "usage: $0 <binary> <query|noquery> [<expected version>]" >&2
  exit 2
fi
bin=$1
variant=$2
want=${3:-}

cd "$(dirname "$0")/.."

got=$("$bin" version)
echo "$got"
if [ -n "$want" ] && [ "$got" != "infra-ontology $want" ]; then
  echo "smoke: expected version $want" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$bin" snapshot build --from-json internal/snapshot/testdata/estate.json --out "$work/snapshots" >/dev/null
snap=$(find "$work/snapshots" -mindepth 1 -maxdepth 1 -type d | head -n 1)
"$bin" snapshot verify "$snap" >/dev/null
# A state file reads into a snapshot that verifies.
"$bin" snapshot build --state internal/ingest/testdata/states/net.tfstate --out "$work/state-snapshots" >/dev/null
"$bin" snapshot verify "$(find "$work/state-snapshots" -mindepth 1 -maxdepth 1 -type d | head -n 1)" >/dev/null
# A snapshot signs with a key and verifies with its public key, offline: the
# Sigstore client is in every variant. Skipped where openssl cannot make a key.
if command -v openssl >/dev/null 2>&1 &&
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/sign.key" 2>/dev/null &&
  openssl pkey -in "$work/sign.key" -pubout -out "$work/sign.pub" 2>/dev/null; then
  "$bin" snapshot sign --key "$work/sign.key" "$snap" >/dev/null
  "$bin" snapshot verify --key "$work/sign.pub" --require-signature "$snap" | grep -q 'signature verified' ||
    { echo "smoke: the signature did not verify" >&2; exit 1; }
else
  echo "smoke: no openssl key to sign with; signing is not exercised"
fi

sql='SELECT count(*) AS n FROM nodes'
case "$variant" in
query)
  out=$("$bin" query "$snap" --sql "$sql")
  echo "$out" | head -n 4
  grep -q 'duckdb' <<<"$out" || { echo "smoke: the answer does not name the DuckDB engine" >&2; exit 1; }
  ;;
noquery)
  if out=$("$bin" query "$snap" --sql "$sql" 2>&1); then
    echo "smoke: a noquery binary answered a query" >&2
    exit 1
  fi
  grep -q 'not built in' <<<"$out" || { echo "smoke: unexpected refusal: $out" >&2; exit 1; }
  echo "the query engine is not built in, as intended"
  ;;
*)
  echo "usage: $0 <binary> <query|noquery> [<expected version>]" >&2
  exit 2
  ;;
esac
