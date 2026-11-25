// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"strings"

	"github.com/IgnatG/infraharvest/pkg/tfstate"
)

// stores are the object stores this build links. Each store is in a file of
// its own behind a build tag (s3, gcs, azblob, hcp), so that a build links
// the SDK of the clouds it names and no other. A build with none reads state
// files and directories only.
var stores tfstate.Stores

// linked names the stores this build links, for the message of a location it
// cannot read.
var linked = []string{BackendLocal}

// Stores returns the stores this build links.
func Stores() tfstate.Stores { return stores }

// Linked lists the backends this build reads: local, and each store built in.
func Linked() []string { return append([]string(nil), linked...) }

// tagFor is the build tag of the store that reads a backend.
var tagFor = map[string]string{BackendS3: "s3", BackendGCS: "gcs", BackendAzBlob: "azblob", BackendHCP: "hcp"}

// Check says why this build cannot read a location, or returns nil: the
// location is not one pkg/tfstate reads, or its store is not built in. It
// reads nothing.
func Check(location string) error {
	if err := tfstate.CheckLocations([]string{location}); err != nil {
		return err
	}
	backend := BackendOf(location)
	for _, l := range linked {
		if l == backend {
			return nil
		}
	}
	return &NotLinkedError{Backend: backend, Tag: tagFor[backend]}
}

// NotLinkedError is the error of a location whose store is not in the build.
type NotLinkedError struct{ Backend, Tag string }

func (e *NotLinkedError) Error() string {
	return "this build does not read " + e.Backend + " state (it reads " + strings.Join(linked, ", ") +
		"): build with -tags " + e.Tag + ", or use a release build, which reads them all"
}
