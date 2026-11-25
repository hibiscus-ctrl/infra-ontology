#!/usr/bin/env bash
# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Fails when a schema file under schemas/ is not one of the documents the
# schemas package registers (schemas.Names), or a registered document has no
# file, so a new schema cannot be added without the tests that validate
# against it. The schemas workflow and `make schemas` run it.
#
# Usage: scripts/check-schemas.sh
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
for file in schemas/*.schema.json; do
  name=$(basename "$file" -v1.schema.json)
  if ! grep -q "\"$name\"" schemas/schemas.go; then
    echo "check-schemas: $file is not in schemas.Names" >&2
    status=1
  fi
done

names=$(sed -n 's/^var Names = \[\]string{\(.*\)}$/\1/p' schemas/schemas.go | tr -d '" ' | tr ',' ' ')
for name in $names; do
  if [ ! -f "schemas/$name-v1.schema.json" ]; then
    echo "check-schemas: schemas/$name-v1.schema.json is missing" >&2
    status=1
  fi
done

exit "$status"
