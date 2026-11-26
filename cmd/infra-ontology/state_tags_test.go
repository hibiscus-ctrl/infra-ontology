// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlantedSecretsInStateTagsNeverReachAnOutputFile plants a credential-
// shaped value and a password=... value in the tags of a state, and builds a
// snapshot from it plain and with --hash-ids. Neither string may be in any
// file the command writes, in the manifest, or on its output, and the tags
// that are not secrets must be there.
func TestPlantedSecretsInStateTagsNeverReachAnOutputFile(t *testing.T) {
	// Put together here so that no file of the repository holds one.
	awsKey := "wJalrXUtnFEMI/K7MDENG/bPx" + "RfiCYEXAMPLEKEY"
	passwordTag := "pass" + "word=PLANTED-STATE-TAG-hunter2"
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"mode":"managed","type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"i-0f00aa11","arn":"arn:aws:ec2:eu-west-1:111111111111:instance/i-0f00aa11",
	   "tags":{"env":"dev","backup":"` + awsKey + `"},"tags_all":{"env":"prod","notes":"` + passwordTag + `","owner":"platform"}}}]},
	 {"mode":"managed","type":"google_storage_bucket","name":"b","provider":"provider[\"registry.terraform.io/hashicorp/google\"]",
	  "instances":[{"attributes":{"id":"projects/acme-prod/buckets/acme-bucket","labels":{"team":"data","hint":"` + awsKey + `"}}}]}]}`
	path := filepath.Join(t.TempDir(), "tags.tfstate")
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := writeKey(t, hashKey)

	for name, extra := range map[string][]string{
		"plain":    nil,
		"hash-ids": {"--hash-ids", "--hash-key-file", keyFile},
	} {
		out := t.TempDir()
		args := append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", path}, extra...)
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
		if len(files) != 4 {
			t.Fatalf("%s: %d files written: %v", name, len(files), files)
		}
		outputs := map[string]string{"stdout": stdout, "stderr": stderr}
		for _, f := range files {
			b, _ := os.ReadFile(f)
			outputs[filepath.Base(f)] = string(b)
		}
		for file, content := range outputs {
			for _, secret := range []string{awsKey, passwordTag, "PLANTED-STATE-TAG", "hunter2"} {
				if strings.Contains(content, secret) {
					t.Errorf("%s: %s holds the planted secret %q", name, file, secret)
				}
			}
		}

		// The tags that are not secrets are in the snapshot; the ones that are, are counted.
		l := loadSnapshot(t, strings.SplitN(stdout, "\n", 2)[0])
		kept := map[string]string{}
		for _, n := range l.Tables.Nodes {
			for k, v := range n.Tags {
				kept[k] = v
			}
		}
		if kept["env"] != "prod" || kept["owner"] != "platform" || kept["team"] != "data" || len(kept) != 3 {
			t.Errorf("%s: tags kept %v", name, kept)
		}
		if !strings.Contains(l.Manifest.Limits, "3 tags look like secrets") {
			t.Errorf("%s: limits: %s", name, l.Manifest.Limits)
		}
		if got := strings.Join(l.Manifest.Redaction.TagKeysDropped, ","); got != "backup,hint,notes" {
			t.Errorf("%s: tag keys dropped %q", name, got)
		}
	}
}
