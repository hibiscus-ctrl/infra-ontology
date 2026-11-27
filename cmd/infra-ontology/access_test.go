// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// accessState is a state of a role and a bucket.
const accessState = `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
{"mode":"managed","type":"aws_iam_role","name":"app","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
 "instances":[{"attributes":{"id":"app","arn":"arn:aws:iam::111111111111:role/app","assume_role_policy":"{\"Statement\":[]}"}}]},
{"mode":"managed","type":"aws_s3_bucket","name":"logs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
 "instances":[{"attributes":{"id":"acme-logs","arn":"arn:aws:s3:::acme-logs"}}]}]}`

// accessLens is what iam-lens printed for the bucket, wrapped with the bucket,
// with values planted in the members the reader must not keep.
const accessLens = `{"resource":"arn:aws:s3:::acme-logs","result":{"simulationCount":4,"allowed":[` +
	`{"principal":"arn:aws:iam::111111111111:role/app","service":"s3","action":"GetObject","level":"read","resourceType":"object"},` +
	`{"principal":"arn:aws:iam::111111111111:role/app","service":"s3","action":"PutObject","level":"write","resourceType":"object",` +
	`"conditions":{"conditionType":"condition","key":"PLANTED-COND-KEY","values":["PLANTED-COND-VALUE"]},` +
	`"details":[{"policyType":"identity","statementId":"PLANTED-SID","policyText":"PLANTED-POLICY-TEXT"}]},` +
	`{"principal":"arn:aws:iam::222222222222:role/vendor-PLANTEDNAME","service":"s3","action":"GetObject","level":"read","resourceType":"object"},` +
	`{"principal":"anonymous","service":"s3","action":"GetObject","level":"read","resourceType":"object"}],` +
	`"allAccountsChecked":true,"accountsNotFound":[],"organizationsNotFound":[],"organizationalUnitsNotFound":[],"principalsNotFound":[]}}` + "\n"

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestIAMLensResultsNeverReachAnOutputFile builds a snapshot from a state and an
// iam-lens file plain, with --hash-ids, with --drop-addresses and with both.
// The principals make can_read and can_write edges, but none of the planted
// policy text or condition values may be in any file the command writes or in
// what the commands that read the snapshot print; with a key, no ARN of the file
// is either.
func TestIAMLensResultsNeverReachAnOutputFile(t *testing.T) {
	dir := t.TempDir()
	state := writeFile(t, dir, "iam.tfstate", accessState)
	lens := writeFile(t, dir, "who-can.jsonl", accessLens)
	keyFile := writeKey(t, hashKey)

	for name, flags := range map[string][]string{
		"plain":                   nil,
		"hash-ids":                {"--hash-ids", "--hash-key-file", keyFile},
		"drop-addresses":          {"--drop-addresses"},
		"hash-ids drop-addresses": {"--hash-ids", "--drop-addresses", "--hash-key-file", keyFile},
	} {
		hashed := strings.Contains(strings.Join(flags, " "), "--hash-ids")
		out := t.TempDir()
		args := append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", state, "--iam-lens", lens}, flags...)
		code, stdout, stderr := exec(t, args...)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s%s", name, code, stdout, stderr)
		}
		var files []string
		_ = filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		snap := strings.SplitN(stdout, "\n", 2)[0]
		outputs := map[string]string{"stdout": stdout, "stderr": stderr}
		for _, f := range files {
			b, _ := os.ReadFile(f)
			outputs[filepath.Base(f)] = string(b)
		}
		for i, args := range [][]string{{"verify", snap}, {"export", "graph", snap}, {"diff", "--json", snap, snap}} {
			_, o, e := exec(t, args...)
			outputs[strings.Join(args[:2], " ")+string(rune('a'+i))+" stdout"] = o
			outputs[strings.Join(args[:2], " ")+string(rune('a'+i))+" stderr"] = e
		}

		secrets := []string{"PLANTED-COND", "PLANTED-SID", "PLANTED-POLICY-TEXT", "policyText", "statementId", "conditionType", "GetObject", "PutObject"}
		if hashed {
			secrets = append(secrets, "acme-logs", "vendor-PLANTEDNAME", "222222222222", "role/app", "who-can.jsonl")
		}
		for file, content := range outputs {
			for _, secret := range secrets {
				if strings.Contains(content, secret) {
					t.Errorf("%s: %s holds %q", name, file, secret)
				}
			}
		}

		l := loadSnapshot(t, snap)
		kinds := map[string]int{}
		for _, e := range l.Tables.Edges {
			if e.Kind == snapshot.EdgeCanRead || e.Kind == snapshot.EdgeCanWrite {
				kinds[e.Kind+" "+e.Confidence+" "+e.Basis]++
			}
		}
		// app reads, app writes under a condition, the vendor's role reads,
		// anyone reads.
		want := map[string]int{
			"can_read computed iam_lens":            2,
			"can_write inferred iam_lens_condition": 1,
			"can_read inferred iam_lens_public":     1,
		}
		for k, n := range want {
			if kinds[k] != n {
				t.Errorf("%s: %q edges: %d, want %d (%v)", name, k, kinds[k], n, kinds)
			}
		}
		if l.Manifest.FormatMinor != 3 {
			t.Errorf("%s: format_minor %d", name, l.Manifest.FormatMinor)
		}
		if l.Manifest.SourcesSummary.ByKind[snapshot.SourceIAMLens] != 1 {
			t.Errorf("%s: sources %v", name, l.Manifest.SourcesSummary.ByKind)
		}
	}
}

func TestIAMLensUsage(t *testing.T) {
	dir := t.TempDir()
	state := writeFile(t, dir, "iam.tfstate", accessState)
	lens := writeFile(t, dir, "who-can.jsonl", accessLens)
	bad := writeFile(t, dir, "bad.json", `{"simulationCount":1,"allowed":[]}`)
	out := t.TempDir()
	base := []string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z"}
	for _, tc := range []struct {
		name string
		args []string
		code int
		msg  string
	}{
		{"alone", []string{"--iam-lens", lens}, 2, "--state LOCATION or --inventory FILE is required"},
		{"with from-json", []string{"--from-json", "x.json", "--iam-lens", lens}, 2, "not both"},
		{"not a file", []string{"--state", state, "--iam-lens", dir}, 2, "is not a file"},
		{"missing", []string{"--state", state, "--iam-lens", filepath.Join(dir, "nope.json")}, 2, "is not a file"},
		{"wrong shape", []string{"--state", state, "--iam-lens", bad}, 3, "1 of 2 sources could not be read in full"},
		{"good and bad", []string{"--state", state, "--iam-lens", lens, "--iam-lens", bad}, 3, "1 of 3 sources"},
		{"good", []string{"--state", state, "--iam-lens", lens}, 0, ""},
	} {
		code, _, stderr := exec(t, append(append([]string(nil), base...), tc.args...)...)
		if code != tc.code || !strings.Contains(stderr, tc.msg) {
			t.Errorf("%s: exit %d, stderr %q; want %d and %q", tc.name, code, stderr, tc.code, tc.msg)
		}
	}
}
