//go:build gcs

// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import "github.com/IgnatG/infraharvest/pkg/tfstate/stores/gcs"

func init() {
	stores.GCS = gcs.New
	linked = append(linked, BackendGCS)
}
