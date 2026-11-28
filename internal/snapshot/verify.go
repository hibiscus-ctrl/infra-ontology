// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The limits of reading a snapshot. A snapshot is read whole, so a file or a
// table that is larger than these is refused before it is read or decoded,
// with an error that says which limit. They are generous: 512 MiB is far more
// than any estate this tool writes, and five million rows of a table are in
// the order of a few gigabytes once decoded. They are variables only so that
// the tests can lower them; there is no flag or setting for them.
var (
	// maxTableBytes is the most bytes of one Parquet file.
	maxTableBytes int64 = 512 << 20
	// maxTableRows is the most rows of one table.
	maxTableRows = 5_000_000
	// maxManifestBytes is the most bytes of manifest.json.
	maxManifestBytes int64 = 16 << 20
)

// readRegular reads a file that is a regular file of at most max bytes. A
// symbolic link, a directory, a device or a pipe is refused rather than
// followed or waited on, and a file larger than max is refused before it is
// read; the size is also enforced while reading, in case it grows.
func readRegular(path string, max int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file (a link, directory or device is not part of a snapshot)")
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%d bytes, over the limit of %d", st.Size(), max)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// What was opened is what was looked at, not a file swapped in between.
	if opened, err := f.Stat(); err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("not a regular file (it changed while it was opened)")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("more than the limit of %d bytes", max)
	}
	return b, nil
}

// Loaded is a snapshot read from a folder after it verified.
type Loaded struct {
	Dir      string
	Manifest Manifest
	Tables   Tables
	// ManifestRaw is the exact bytes of manifest.json that were hashed and
	// parsed. A signature over the manifest is checked against these, not
	// against a second read of the file, which could have changed since.
	ManifestRaw []byte
	// files are the bytes of each table file that were hashed, by file name.
	files map[string][]byte
}

// Materialize writes the bytes that verified (the manifest and the table
// files) to a new private folder, and returns it with a function that deletes
// it. Open a snapshot from this folder, not from Dir, so that what is served
// is what was hashed: Dir can be changed between the hashing and a second
// read, this folder is made by this process, readable by its user alone.
func (l *Loaded) Materialize() (dir string, remove func(), err error) {
	dir, err = os.MkdirTemp("", "infra-ontology-snapshot-")
	if err != nil {
		return "", nil, err
	}
	remove = func() { _ = os.RemoveAll(dir) }
	write := func(name string, b []byte) error {
		return os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	if err := write(ManifestFile, l.ManifestRaw); err != nil {
		remove()
		return "", nil, err
	}
	for name, b := range l.files {
		if err := write(name, b); err != nil {
			remove()
			return "", nil, err
		}
	}
	return dir, remove, nil
}

// VerifyResult is what Verify found. It does not stop at the first problem.
type VerifyResult struct {
	Dir        string      `json:"dir"`
	SnapshotID string      `json:"snapshot_id,omitempty"`
	ParentID   string      `json:"parent_id,omitempty"`
	Label      string      `json:"label,omitempty"`
	Tables     []TableInfo `json:"tables,omitempty"`
	Problems   []string    `json:"problems"`
}

// OK reports whether the snapshot verified.
func (r VerifyResult) OK() bool { return len(r.Problems) == 0 }

// Error lists the problems, one a line.
func (r VerifyResult) Error() string { return strings.Join(r.Problems, "\n") }

// Verify checks a snapshot folder offline: the manifest is one this package
// reads, its id is the hash of its own content, every table the manifest names
// is there with the hash, the row count and the row schema it states, no other
// table is there, and the rows are consistent (ids unique, every edge joins two
// nodes, every row cites a source). Change a byte of any file and it fails.
func Verify(dir string) VerifyResult {
	_, res, _ := load(dir)
	return res
}

// VerifyWithManifest is Verify that also returns the bytes of manifest.json it
// checked, nil if it could not read the file. Check a signature against these
// bytes, so that what is signed is what was verified.
func VerifyWithManifest(dir string) (VerifyResult, []byte) {
	_, res, raw := load(dir)
	return res, raw
}

// Load verifies a snapshot folder and, if it verified, reads its rows. It
// returns the verification problems as an error otherwise, so nothing reads a
// tampered table.
func Load(dir string) (*Loaded, error) {
	l, res, _ := load(dir)
	if !res.OK() {
		return nil, fmt.Errorf("%s does not verify:\n%s", dir, res.Error())
	}
	return l, nil
}

func load(dir string) (*Loaded, VerifyResult, []byte) {
	res := VerifyResult{Dir: dir, Problems: []string{}}
	fail := func(format string, args ...any) { res.Problems = append(res.Problems, fmt.Sprintf(format, args...)) }

	raw, err := readRegular(filepath.Join(dir, ManifestFile), maxManifestBytes)
	if err != nil {
		fail("%s: %v", ManifestFile, reason(err))
		return nil, res, raw
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		fail("%s: not a manifest: %v", ManifestFile, err)
		return nil, res, raw
	}
	res.SnapshotID, res.ParentID, res.Label, res.Tables = m.SnapshotID, m.ParentID, m.Label, m.Tables
	if m.Format != Format {
		fail("%s: format %q is not supported (this reader reads %q)", ManifestFile, m.Format, Format)
		return nil, res, raw
	}
	id, err := ManifestID(raw)
	if err != nil {
		fail("%s: %v", ManifestFile, err)
		return nil, res, raw
	}
	if id != m.SnapshotID {
		fail("%s: snapshot_id is %q but the manifest hashes to %q", ManifestFile, m.SnapshotID, id)
	}

	want := map[string]string{"nodes": NodesFile, "edges": EdgesFile, "sources": SourcesFile}
	listed := map[string]bool{}
	data := map[string][]byte{}
	for _, t := range m.Tables {
		file, known := want[t.Name]
		switch {
		case !known:
			fail("table %q: not a table of this format", t.Name)
			continue
		case listed[t.Name]:
			fail("table %q: listed twice", t.Name)
			continue
		case t.File != file:
			fail("table %q: file is %q, want %q", t.Name, t.File, file)
			continue
		}
		listed[t.Name] = true
		b, err := readRegular(filepath.Join(dir, t.File), maxTableBytes)
		if err != nil {
			fail("%s: %v", t.File, reason(err))
			continue
		}
		if got := sha256Hex(b); got != t.SHA256 {
			fail("%s: sha256 is %s, the manifest says %s", t.File, got, t.SHA256)
			continue
		}
		data[t.Name] = b
	}
	for name := range want {
		if !listed[name] {
			fail("table %q: not in the manifest", name)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail("%v", reason(err))
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".parquet") && !listed[strings.TrimSuffix(e.Name(), ".parquet")] {
			fail("%s: a table the manifest does not list", e.Name())
		}
	}
	if !res.OK() {
		return nil, res, raw
	}

	var t Tables
	rows := func(info TableInfo, n int, err error) {
		switch {
		case err != nil:
			fail("%s: %v", info.File, err)
		case n != info.Rows:
			fail("%s: has %d rows, the manifest says %d", info.File, n, info.Rows)
		}
	}
	for _, info := range m.Tables {
		if info.Schema != schemaOf(info.Name) {
			fail("table %q: schema %q is not %q", info.Name, info.Schema, schemaOf(info.Name))
		}
		switch info.Name {
		case "nodes":
			var err error
			t.Nodes, err = decodeNodes(data[info.Name])
			rows(info, len(t.Nodes), err)
		case "edges":
			var err error
			t.Edges, err = decodeEdges(data[info.Name])
			rows(info, len(t.Edges), err)
		case "sources":
			var err error
			t.Sources, err = decodeSources(data[info.Name])
			rows(info, len(t.Sources), err)
		}
	}
	if res.OK() {
		if err := Validate(&t); err != nil {
			for _, line := range strings.Split(err.Error(), "\n") {
				fail("rows: %s", line)
			}
		}
	}
	if !res.OK() {
		return nil, res, raw
	}
	files := map[string][]byte{}
	for _, info := range m.Tables {
		files[info.File] = data[info.Name]
	}
	return &Loaded{Dir: dir, Manifest: m, Tables: t, ManifestRaw: raw, files: files}, res, raw
}

func schemaOf(table string) string {
	switch table {
	case "nodes":
		return NodeSchema
	case "edges":
		return EdgeSchema
	}
	return SourceSchema
}

// FindParent looks in the folder beside dir for the snapshot whose id is
// dir's parent_id. It returns "" and no error if dir has no parent, and an
// error if the parent is named but not there.
func FindParent(dir string) (string, error) {
	raw, err := readRegular(filepath.Join(dir, ManifestFile), maxManifestBytes)
	if err != nil {
		return "", err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	if m.ParentID == "" {
		return "", nil
	}
	if !hexID.MatchString(m.ParentID) {
		return "", fmt.Errorf("parent_id %q is not a snapshot id", m.ParentID)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	siblings := filepath.Dir(abs)
	entries, err := os.ReadDir(siblings)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.Contains(e.Name(), m.ParentID[:12]) {
			continue
		}
		cand := filepath.Join(siblings, e.Name())
		b, err := readRegular(filepath.Join(cand, ManifestFile), maxManifestBytes)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return "", err
		}
		var pm Manifest
		if json.NewDecoder(bytes.NewReader(b)).Decode(&pm) == nil && pm.SnapshotID == m.ParentID {
			return cand, nil
		}
	}
	return "", fmt.Errorf("the parent snapshot %s is not beside %s", m.ParentID, dir)
}

// reason is the cause of a file error without the path, which the message
// already names.
func reason(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
