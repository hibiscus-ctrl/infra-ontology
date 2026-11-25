#!/usr/bin/env bash
# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Turns the binaries the release builds produced into release archives and a
# checksums file. Runs on Linux (GNU tar, gzip and zip), so every archive is
# made the same way whichever runner built the binary inside it.
#
# <bindir> holds one folder per build, named bin-<os>-<arch> for a binary with
# the query engine and bin-<os>-<arch>-noquery for one without, each holding
# the `infra-ontology` binary (`infra-ontology.exe` on Windows). The archives
# are named infra-ontology_<version>_<os>_<arch>[_noquery].tar.gz (.zip on
# Windows). The files are sorted and carry the commit's timestamp, so the same
# binaries always give the same archives.
#
# Usage: scripts/package-release.sh <version> <bindir> <outdir>
#   <version>  without the leading v, for example 1.2.3
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 <version> <bindir> <outdir>" >&2
  exit 2
fi
version=$1
bindir=$(cd "$2" && pwd)
mkdir -p "$3"
outdir=$(cd "$3" && pwd)

cd "$(dirname "$0")/.."
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}

# The builds a release must have: the query engine on every platform the
# engine ships prebuilt libraries for.
for want in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64; do
  if [ ! -d "$bindir/bin-$want" ]; then
    echo "package-release: the $want build with the query engine is missing" >&2
    exit 1
  fi
done

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

count=0
for dir in "$bindir"/bin-*; do
  name=$(basename "$dir")
  rest=${name#bin-}
  variant=
  case "$rest" in
  *-noquery)
    rest=${rest%-noquery}
    variant=_noquery
    ;;
  esac
  goos=${rest%%-*}
  goarch=${rest#*-}
  base="infra-ontology_${version}_${goos}_${goarch}${variant}"

  bin=infra-ontology
  [ "$goos" = windows ] && bin=infra-ontology.exe
  if [ ! -f "$dir/$bin" ]; then
    echo "package-release: $name has no $bin" >&2
    exit 1
  fi

  root="$stage/$base"
  mkdir -p "$root/LICENSES"
  install -m 0755 "$dir/$bin" "$root/$bin"
  install -m 0644 LICENSE README.md "$root/"
  install -m 0644 LICENSES/AGPL-3.0-only.txt LICENSES/Apache-2.0.txt "$root/LICENSES/"
  find "$root" -exec touch -h -d "@$epoch" {} +

  if [ "$goos" = windows ]; then
    (cd "$root" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | zip -X -q "$outdir/$base.zip" -@)
  else
    tar -C "$root" --sort=name --owner=0 --group=0 --numeric-owner \
      --mtime="@$epoch" -cf - . | gzip -n -9 >"$outdir/$base.tar.gz"
  fi
  count=$((count + 1))
done

if [ "$count" -eq 0 ]; then
  echo "package-release: no builds found in $bindir" >&2
  exit 1
fi

sums="infra-ontology_${version}_SHA256SUMS"
(cd "$outdir" && find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -printf '%f\n' | LC_ALL=C sort | xargs sha256sum >"$sums")
echo "$count archives, checksums in $sums"
cat "$outdir/$sums"
