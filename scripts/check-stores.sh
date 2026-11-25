#!/usr/bin/env bash
# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Fails if a release binary does not link the four state stores (S3, Cloud
# Storage, Blob Storage and HCP Terraform), which are behind the build tags
# s3, gcs, azblob and hcp: a binary built without them reads state files only
# and says so when it is given s3://, gs://, azblob:// or hcp://. The release
# workflow runs it on every binary it builds.
#
# Usage: scripts/check-stores.sh <binary>
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <binary>" >&2
  exit 2
fi

# The linked modules only: the build settings name the tags.
deps=$(go version -m "$1" | awk '$1 == "dep" {print $2}')

for want in \
  github.com/IgnatG/infraharvest \
  github.com/aws/aws-sdk-go-v2/service/s3 \
  google.golang.org/api \
  github.com/Azure/azure-sdk-for-go/sdk/storage/azblob \
  github.com/hashicorp/terraform-svchost; do
  if ! grep -qx "$want" <<<"$deps"; then
    echo "check-stores: $1 does not link $want: is it built with -tags s3,gcs,azblob,hcp?" >&2
    exit 1
  fi
done
echo "check-stores: ok"
