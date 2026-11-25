//go:build azblob

// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import "github.com/IgnatG/infraharvest/pkg/tfstate/stores/azblob"

func init() {
	stores.AzureBlob = azblob.New
	linked = append(linked, BackendAzBlob)
}
