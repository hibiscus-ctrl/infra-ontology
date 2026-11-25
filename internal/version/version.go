// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package version holds the version the binary reports.
package version

// Version is the release the binary was built from. The release build sets it
// with -ldflags "-X github.com/hibiscus-ctrl/infra-ontology/internal/version.Version=v1.2.3";
// a build from a checkout reports "dev".
var Version = "dev"
