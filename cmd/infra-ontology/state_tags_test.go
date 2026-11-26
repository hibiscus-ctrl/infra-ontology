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
// shaped value, a password=... value, the ARN of a queue (whose ID is its URL)
// and the names of a module call, an instance key and a short Terraform name
// in the tags of a state and of the inventories joined to it, and builds a
// snapshot plain, with --hash-ids, with --drop-addresses and with both, each
// with and without the inventories. None of the planted strings may be in any
// file the command writes, in the manifest, or on the output of the commands
// that read the snapshot, as far as the flags hide them; and the tags that are
// not secrets must be there.
func TestPlantedSecretsInStateTagsNeverReachAnOutputFile(t *testing.T) {
	// Put together here so that no file of the repository holds one.
	awsKey := "wJalrXUtnFEMI/K7MDENG/bPx" + "RfiCYEXAMPLEKEY"
	passwordTag := "pass" + "word=PLANTED-STATE-TAG-hunter2"
	invPassword := "pass" + "word=PLANTED-INV-TAG-hunter3"
	const (
		queueURL = "https://sqs.eu-west-1.amazonaws.com/111111111111/jobs-prod"
		queueARN = "arn:aws:sqs:eu-west-1:111111111111:jobs-prod"
	)
	instance := `{"mode":"managed","type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"i-0f00aa11","arn":"arn:aws:ec2:eu-west-1:111111111111:instance/i-0f00aa11",
	   "tags":{"env":"dev","backup":"` + awsKey + `"},"tags_all":{"env":"prod","notes":"` + passwordTag + `","owner":"platform"}}}]}`
	rest := `,{"mode":"managed","type":"google_storage_bucket","name":"b","provider":"provider[\"registry.terraform.io/hashicorp/google\"]",
	  "instances":[{"attributes":{"id":"projects/acme-prod/buckets/acme-bucket","labels":{"team":"data","hint":"` + awsKey + `"}}}]},
	 {"mode":"managed","type":"aws_sqs_queue","name":"qq","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"` + queueURL + `","arn":"` + queueARN + `",
	   "tags":{"queue_arn":"` + queueARN + `","` + queueARN + `":"1","stage":"blue"}}}]},
	 {"module":"module.plantedmod[\"plantkey\"]","mode":"managed","type":"aws_s3_bucket","name":"ws","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"acme-ws-bucket","tags":{"modref":"plantedmod","keyref":"plantkey","tf":"ws","env2":"stage"}}}]}`
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[` + instance + rest + `]}`
	other := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[` + instance + `]}`
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	path, otherPath := write("tags.tfstate", state), write("other.tfstate", other)
	invV1 := write("aws.inventory.json", `{"schema":"infraharvest/inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","generated_at":"2026-11-25T09:30:00Z",
	 "tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws","scopes":["aws/111111111111/eu-west-1"],"resources":[
	 {"type":"aws_instance","id":"i-0f00aa11","account":"111111111111","region":"eu-west-1","status":"managed","status_basis":"state",
	  "tags":{"env":"live","owner":"platform","leak":"`+invPassword+`"}},
	 {"type":"aws_s3_bucket","id":"acme-ws-bucket","account":"111111111111","status":"managed","status_basis":"state",
	  "tags":{"modref":"plantedmod","keyref":"plantkey","tf":"ws","env2":"stage"}}]}`)
	invOCSF := write("aws.ocsf-inventory.json", `{"schema":"infraharvest/ocsf-inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b45","ocsf_version":"1.9.0",
	 "redaction":{"tag_keys_dropped":[],"ids_hashed":false,"hash_alg":"hmac-sha256","addresses_dropped":false},
	 "events":[{"time":1795600800000,"metadata":{"product":{"name":"infraharvest","version":"0.9.0"}},
	  "cloud":{"provider":"AWS","account":{"uid":"111111111111"},"region":"eu-west-1"},
	  "resources":[{"type":"aws_sqs_queue","uid":"`+queueARN+`","uid_alt":"`+queueURL+`","labels":["status:managed","status_basis:state"],
	   "tags":[{"name":"queue_arn","value":"`+queueARN+`"},{"name":"stage","value":"blue"}]}]}]}`)
	keyFile := writeKey(t, hashKey)

	for name, c := range map[string]struct {
		flags     []string
		inventory bool
	}{
		"plain":                             {nil, false},
		"hash-ids":                          {[]string{"--hash-ids", "--hash-key-file", keyFile}, false},
		"drop-addresses":                    {[]string{"--drop-addresses"}, false},
		"hash-ids drop-addresses":           {[]string{"--hash-ids", "--drop-addresses", "--hash-key-file", keyFile}, false},
		"inventory":                         {nil, true},
		"inventory hash-ids":                {[]string{"--hash-ids", "--hash-key-file", keyFile}, true},
		"inventory drop-addresses":          {[]string{"--drop-addresses"}, true},
		"inventory hash-ids drop-addresses": {[]string{"--hash-ids", "--drop-addresses", "--hash-key-file", keyFile}, true},
	} {
		hashed := strings.Contains(strings.Join(c.flags, " "), "--hash-ids")
		dropped := strings.Contains(strings.Join(c.flags, " "), "--drop-addresses")
		build := func(statePath, outDir string) (int, string, string) {
			args := []string{"snapshot", "build", "--out", outDir, "--created-at", "2026-11-25T12:00:00Z", "--state", statePath}
			if c.inventory {
				args = append(args, "--inventory", invV1, "--inventory", invOCSF)
			}
			return exec(t, append(args, c.flags...)...)
		}
		out := t.TempDir()
		code, stdout, stderr := build(path, out)
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
		snap := strings.SplitN(stdout, "\n", 2)[0]
		outputs := map[string]string{"stdout": stdout, "stderr": stderr}
		for _, f := range files {
			b, _ := os.ReadFile(f)
			outputs[filepath.Base(f)] = string(b)
		}
		// The commands that read the snapshot: verify, the graph, and a diff
		// with a snapshot of one state, each way.
		otherOut := t.TempDir()
		if code, so, se := build(otherPath, otherOut); code != 0 {
			t.Fatalf("%s: second build: exit %d: %s%s", name, code, so, se)
		} else {
			otherSnap := strings.SplitN(so, "\n", 2)[0]
			for i, args := range [][]string{
				{"verify", snap}, {"export", "graph", snap}, {"export", "graph", "--cloud", "aws", snap},
				{"diff", "--json", otherSnap, snap}, {"diff", otherSnap, snap}, {"diff", "--json", snap, otherSnap}, {"diff", snap, otherSnap},
			} {
				_, o, e := exec(t, args...)
				outputs[strings.Join(args[:2], " ")+string(rune('a'+i))+" stdout"] = o
				outputs[strings.Join(args[:2], " ")+string(rune('a'+i))+" stderr"] = e
			}
		}

		secrets := []string{awsKey, passwordTag, invPassword, "PLANTED-STATE-TAG", "PLANTED-INV-TAG", "hunter2", "hunter3"}
		if hashed {
			secrets = append(secrets, "jobs-prod", "i-0f00aa11", "acme-ws-bucket", "acme-bucket")
		}
		if dropped {
			secrets = append(secrets, "plantedmod", "plantkey", "aws_s3_bucket.ws")
		}
		for file, content := range outputs {
			for _, secret := range secrets {
				if strings.Contains(content, secret) {
					t.Errorf("%s: %s holds %q", name, file, secret)
				}
			}
		}

		// The tags that are not secrets are in the snapshot; the ones that are, are counted.
		l := loadSnapshot(t, snap)
		kept := map[string]string{}
		for _, n := range l.Tables.Nodes {
			for k, v := range n.Tags {
				kept[k] = v
			}
		}
		if kept["env"] != "prod" && kept["env"] != "live" || kept["owner"] != "platform" || kept["team"] != "data" || kept["stage"] != "blue" || kept["env2"] != "stage" {
			t.Errorf("%s: tags kept %v", name, kept)
		}
		switch {
		case hashed && (kept["queue_arn"] == queueARN || len(kept["queue_arn"]) != 64):
			t.Errorf("%s: queue_arn is %q, want a hash", name, kept["queue_arn"])
		case !hashed && kept["queue_arn"] != queueARN:
			t.Errorf("%s: queue_arn is %q", name, kept["queue_arn"])
		}
		for _, k := range []string{"modref", "keyref", "tf"} {
			if _, ok := kept[k]; ok == dropped {
				t.Errorf("%s: tag %s kept is %v, with --drop-addresses %v", name, k, ok, dropped)
			}
		}
		if _, ok := kept[queueARN]; ok && hashed {
			t.Errorf("%s: a tag keyed by the queue's ARN is kept", name)
		}
		if !strings.Contains(l.Manifest.Limits, " tags look like secrets") {
			t.Errorf("%s: limits: %s", name, l.Manifest.Limits)
		}
		// The inventory's password tag is dropped and listed; the others keys are as before.
		want := "backup,hint,notes"
		if c.inventory {
			want = "backup,hint,leak,notes"
		}
		if got := strings.Join(l.Manifest.Redaction.TagKeysDropped, ","); got != want {
			t.Errorf("%s: tag keys dropped %q, want %q", name, got, want)
		}
		if l.Manifest.Redaction.AllTagsDropped {
			t.Errorf("%s: the manifest says all tags were dropped", name)
		}
	}
}
