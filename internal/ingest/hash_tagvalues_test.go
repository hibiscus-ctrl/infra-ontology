// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"maps"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"
	"github.com/IgnatG/infraharvest/pkg/tfstate"
)

// Raw cloud identifiers in tag values: with --hash-ids none stays readable,
// whichever resource it names.
func identifierTags() map[string]string {
	return map[string]string{
		"vpc_id":    "vpc-0abc123def4567890",
		"stack":     "arn:aws:cloudformation:eu-west-1:999988887777:stack/other/0f1e2d3c",
		"data":      "s3://other-bucket/some/key",
		"account":   "999988887777",
		"sub":       "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourceGroups/rg-other",
		"proj":      "projects/other-proj/buckets/other-b",
		"tenant":    "cccccccc-4444-5555-6666-dddddddddddd",
		"host":      "https://other.example.com/path",
		"sibling":   "peer of acme-logs-app, see it",
		"module":    "module.network",
		"statefile": "kept in /work/states/prod.tfstate",
		"env":       "prod",
		"team":      "web",
		"cost":      "42",
	}
}

func tagValueState(t *testing.T) []Read {
	t.Helper()
	const loc = "/work/states/prod.tfstate"
	doc := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"module":"module.network","mode":"managed","type":"aws_vpc","name":"main","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"vpc-0a1b2c3d4e5f60718","arn":"arn:aws:ec2:eu-west-1:111111111111:vpc/vpc-0a1b2c3d4e5f60718","tags":` + jsonTags(identifierTags()) + `}}]},
	 {"mode":"managed","type":"aws_s3_bucket","name":"logs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"acme-logs-app"}}]}]}`
	d, err := tfstate.Parse([]byte(doc), loc)
	if err != nil {
		t.Fatal(err)
	}
	return []Read{{Location: loc, Docs: []tfstate.Document{d}}}
}

func jsonTags(m map[string]string) string {
	var sb strings.Builder
	sb.WriteString("{")
	first := true
	for k, v := range m {
		if !first {
			sb.WriteString(",")
		}
		first = false
		sb.WriteString(`"` + k + `":"` + v + `"`)
	}
	sb.WriteString("}")
	return sb.String()
}

func TestHashedTagValuesThatNameAnIdentifierAreHashed(t *testing.T) {
	res := buildHashed(t, testKey, tagValueState(t), nil)
	files := writeHashed(t, res)
	for _, raw := range []string{
		"vpc-0abc123def4567890", "other/0f1e2d3c", "999988887777", "s3://other-bucket", "other-bucket", "rg-other", "other-proj",
		"cccccccc-4444", "other.example.com", "acme-logs-app", "module.network", "/work/states/prod.tfstate",
	} {
		for file, data := range files {
			if bytes.Contains(data, []byte(raw)) {
				t.Errorf("%s holds %q", file, raw)
			}
		}
	}
	var tags map[string]string
	for _, n := range res.Tables.Nodes {
		if n.TFType == "aws_vpc" {
			tags = n.Tags
		}
	}
	for k, raw := range identifierTags() {
		got, ok := tags[k]
		switch k {
		case "env", "team", "cost":
			if got != raw {
				t.Errorf("tag %s = %q, want %q: it names nothing", k, got, raw)
			}
		default:
			if !ok || got != secretscan.HashID(testKey, raw) {
				t.Errorf("tag %s = %q, want the hash of %q", k, got, raw)
			}
		}
	}
	if !strings.Contains(res.Limits, "tag values have the shape of a cloud identifier") {
		t.Errorf("limits do not say tag values were hashed: %s", res.Limits)
	}
}

func TestPlainBuildKeepsIdentifierTagValues(t *testing.T) {
	res := build(t, tagValueState(t))
	for _, n := range res.Tables.Nodes {
		if n.TFType == "aws_vpc" && !maps.Equal(n.Tags, identifierTags()) {
			t.Errorf("tags %v", n.Tags)
		}
	}
}

func TestHashedInventoryTagValuesThatNameAnIdentifierAreHashed(t *testing.T) {
	// An inventory that did hash its IDs left the other identifiers of its
	// tags as they were.
	id := secretscan.Hash(testKey, "vpc-0a1b2c3d4e5f60718")
	doc := `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","tool":{"name":"infraharvest","version":"0.9.0"},
	 "cloud":"aws","redaction":{"ids_hashed":true},"resources":[{"type":"aws_vpc","id":"` + id + `","account":"111111111111","region":"eu-west-1",
	 "status":"unmanaged","status_basis":"none","tags":{"vpc_id":"vpc-0abc123def4567890","team":"web","where":"s3://other-bucket/k"}}]}`
	inv, err := ParseInventory([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	res, err := BuildAll(nil, []InventoryRead{{Location: "h.json", Inv: inv}}, hashedOpts(testKey))
	if err != nil {
		t.Fatal(err)
	}
	for file, data := range writeHashed(t, res) {
		for _, raw := range []string{"vpc-0abc123def4567890", "other-bucket"} {
			if bytes.Contains(data, []byte(raw)) {
				t.Errorf("%s holds %q", file, raw)
			}
		}
	}
	n := res.Tables.Nodes[0]
	if n.Tags["team"] != "web" || n.Tags["vpc_id"] != secretscan.HashID(testKey, "vpc-0abc123def4567890") {
		t.Errorf("tags %v", n.Tags)
	}
}

func TestIdentifierShaped(t *testing.T) {
	for v, want := range map[string]bool{
		"vpc-0abc123def4567890": true, "i-0123456789abcdef0": true, "sg-12345678": true, "vpc-0abc": false,
		"arn:aws:s3:::b": true, "ARN:aws-us-gov:iam::1:root": true, "/Subscriptions/x/y": true, "projects/p/zones/z": true,
		"s3://b/k": true, "gs://b": true, "https://x.example.com": true, "123456789012": true, "acct 123456789012.": true,
		"1234567890123": false, "release-20240101": false, "deadbeef-cafe": false, "feature-deadbeef1": true, "web": false,
		"prod": false, "team-a/b": false, "": false, strings.Repeat("a", 64): false,
		"aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb": true, "bucket.s3.amazonaws.com": true,
	} {
		if got := identifierShaped(v); got != want {
			t.Errorf("identifierShaped(%q) = %v, want %v", v, got, want)
		}
	}
}
