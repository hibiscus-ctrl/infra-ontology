// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// NodeID is the stable identifier of a real thing: the hex SHA-256 of its
// kind, cloud, account, region, type and native id. Ingest passes the type it
// settled on (the Terraform type, or the inventory type for an unmanaged
// thing).
func NodeID(kind, cloud, account, region, typ, nativeID string) string {
	return hashFields(kind, cloud, account, region, typ, nativeID)
}

// EdgeID is the identifier of an edge: the hex SHA-256 of its kind and its two
// ends. Two edges with the same id are the same edge.
func EdgeID(kind, fromID, toID string) string {
	return hashFields(kind, fromID, toID)
}

func hashFields(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		io.WriteString(h, f) //nolint:errcheck // a hash never fails
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ManifestID computes the snapshot id of a manifest document: the hex SHA-256
// of the document with its snapshot_id member removed, written in canonical
// form (member names sorted, no white space, numbers as written). It works on
// the document and not on the Go type, so a manifest with a member a later
// minor version added still hashes the way its writer hashed it.
func ManifestID(raw []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return "", fmt.Errorf("manifest is not a JSON object: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", fmt.Errorf("manifest has data after the JSON object")
	}
	delete(doc, "snapshot_id")
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil { // encoding/json sorts map keys
		return "", err
	}
	return sha256Hex(bytes.TrimRight(out.Bytes(), "\n")), nil
}

// DirName is the name of a snapshot's folder: its creation time in UTC and the
// first twelve hex digits of its id, for example 20261125T101500Z-3fa9c2d41b7e.
func DirName(m Manifest) (string, error) {
	t, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return "", fmt.Errorf("created_at: %w", err)
	}
	if len(m.SnapshotID) < 12 {
		return "", fmt.Errorf("snapshot_id %q is too short", m.SnapshotID)
	}
	return t.UTC().Format("20060102T150405Z") + "-" + strings.ToLower(m.SnapshotID[:12]), nil
}
