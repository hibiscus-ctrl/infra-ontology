#!/usr/bin/env bash
# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Fails when a tracked file uses a word this public repository keeps out of
# its code and documents. The words are listed only as SHA-256 hashes, so the
# check itself never spells them. The tests workflow runs it on every pull
# request.
#
# Usage: scripts/check-names.sh [<file>...]
#   <file>  check only these files, relative to the repository's root
#           (default: every tracked file)
set -euo pipefail

hashes=(
  04d52bfb8ce8b5a37e6a15b8c002419d2555543855cb4a7972ca80b2d8eadbf0
  d873be638bf19976757a89d5c3d18d64be4b7b59711ec6d3f9e648b52af53b27
  e1b30ca15796f237e736c149c000108ba290024895d6d79fc8a31ef03b53c777
)

cd "$(dirname "$0")/.."

pathspec=(.)
if [ $# -gt 0 ]; then
  pathspec=()
  for file in "$@"; do
    pathspec+=(":(literal)$file")
  done
fi

found=0
while IFS= read -r word; do
  sum=$(printf %s "$word" | sha256sum | cut -d' ' -f1)
  for h in "${hashes[@]}"; do
    if [ "$sum" = "$h" ]; then
      git grep -n -I -i -w -F "$word" -- "${pathspec[@]}" || true
      found=1
    fi
  done
done < <(git grep -h -o -I -i -E '[a-z]{6,10}' -- "${pathspec[@]}" | tr '[:upper:]' '[:lower:]' | sort -u)

if [ "$found" -ne 0 ]; then
  echo "::error::A tracked file uses a word this repository keeps out (see scripts/check-names.sh)."
  exit 1
fi
echo "No kept-out words found."
