// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package queries holds the stored queries: named, versioned SQL files
// compiled into the binary. internal/query reads them; the header of each file
// says what it is called, which version it is, and which parameters it takes.
package queries

import "embed"

// FS holds the *.sql files.
//
//go:embed *.sql
var FS embed.FS
