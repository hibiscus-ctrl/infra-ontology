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

// TestTrustPolicyNeverReachesAnOutputFile plants values in the trust policy of
// roles (a Sid, an external ID in a condition, a condition key, a federated
// provider and the policy's version and action text) and builds a snapshot
// plain, with --hash-ids, with --drop-addresses and with both. The principals
// make can_assume edges, but none of the planted text may be in any file the
// command writes, in the manifest, or on the output of the commands that read
// the snapshot; with a key, no principal ARN is either.
func TestTrustPolicyNeverReachesAnOutputFile(t *testing.T) {
	const partner = "arn:aws:iam::222222222222:role/partner-PLANTEDNAME"
	policy := `{"Version":"2012-10-17","Statement":[` +
		`{"Sid":"PLANTED-SID","Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":["arn:aws:iam::111111111111:role/ci","` + partner + `"],"Service":"ec2.amazonaws.com"},` +
		`"Condition":{"StringEquals":{"sts:ExternalId":"PLANTED-EXTERNAL-ID","PLANTED-COND-KEY":"PLANTED-COND-VALUE"}}},` +
		`{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/PLANTED-PROVIDER"}},` +
		`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}`
	quoted := strings.ReplaceAll(strings.ReplaceAll(policy, `\`, `\\`), `"`, `\"`)
	role := func(name string) string {
		return `{"mode":"managed","type":"aws_iam_role","name":"` + name + `","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
		 "instances":[{"attributes":{"id":"` + name + `","arn":"arn:aws:iam::111111111111:role/` + name + `","assume_role_policy":"` + quoted + `"}}]}`
	}
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[` + role("ci") + `,` + role("app") + `]}`
	path := filepath.Join(t.TempDir(), "iam.tfstate")
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	keyFile := writeKey(t, hashKey)

	for name, flags := range map[string][]string{
		"plain":                   nil,
		"hash-ids":                {"--hash-ids", "--hash-key-file", keyFile},
		"drop-addresses":          {"--drop-addresses"},
		"hash-ids drop-addresses": {"--hash-ids", "--drop-addresses", "--hash-key-file", keyFile},
	} {
		hashed := strings.Contains(strings.Join(flags, " "), "--hash-ids")
		out := t.TempDir()
		args := append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", path}, flags...)
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

		secrets := []string{"PLANTED-SID", "PLANTED-EXTERNAL-ID", "PLANTED-COND", "PLANTED-PROVIDER", "2012-10-17", "sts:AssumeRole", "ExternalId", "StringEquals", "oidc-provider"}
		if hashed {
			secrets = append(secrets, "partner-PLANTEDNAME", "ec2.amazonaws.com", "role/ci")
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
			if e.Kind == snapshot.EdgeCanAssume {
				kinds[e.Confidence+" "+e.Basis]++
			}
		}
		// ci trusts the partner, the service and anyone; app also trusts ci:
		// the named ones are inferred or computed by a condition that is not
		// evaluated, and the wildcard is inferred.
		if kinds["inferred trust_policy_wildcard"] != 2 || kinds["inferred trust_policy_condition"] < 4 {
			t.Errorf("%s: can_assume edges: %v", name, kinds)
		}
		if l.Manifest.FormatMinor != 3 {
			t.Errorf("%s: format_minor %d", name, l.Manifest.FormatMinor)
		}
	}
}
