// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package schemas embeds the JSON Schemas (Apache-2.0) of the documents
// infra-ontology writes, so the command and its tests validate against the
// files published in this directory and not against a copy.
package schemas

import "embed"

// FS holds the *.schema.json files.
//
//go:embed *.schema.json
var FS embed.FS

// Names are the documents the schemas describe.
var Names = []string{"snapshot", "node", "edge", "source", "answer"}

// File is the name of the schema file of a document, for example
// "node-v1.schema.json".
func File(name string) string { return name + "-v1.schema.json" }
