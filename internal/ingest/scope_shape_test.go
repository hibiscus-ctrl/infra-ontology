// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// The account and the region of a node are cut from an ID, an ARN or an
// identity, and written as they are cut: only a value of the shape of an
// account or a region of its cloud may be, since the rest of an identifier is
// not what the snapshot says it is.
func TestScopeOfKeepsOnlyKnownShapes(t *testing.T) {
	const sub = "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"
	for _, c := range []struct {
		name, cloud, id, arn, identity string
		account, region                string
	}{
		{"aws arn", "aws", "vpc-0a1b", "arn:aws:ec2:eu-west-1:111111111111:vpc/vpc-0a1b", "", "111111111111", "eu-west-1"},
		{"aws gov", "aws", "x", "arn:aws-us-gov:ec2:us-gov-west-1:111111111111:vpc/x", "", "111111111111", "us-gov-west-1"},
		{"aws account is not 12 digits", "aws", "x", "arn:aws:ec2:eu-west-1:PLANTED-ACCOUNT:vpc/x", "", "", "eu-west-1"},
		{"aws region is not a region", "aws", "x", "arn:aws:ec2:PLANTED-REGION:111111111111:vpc/x", "", "111111111111", ""},
		{"aws id arn", "aws", "arn:aws:iam::111111111111:role/r", "", "", "111111111111", ""},
		{"aws identity", "aws", "x", "", "account_id=111111111111,region=eu-west-2", "111111111111", "eu-west-2"},
		{"aws identity not shaped", "aws", "x", "", "account_id=PLANTED,region=PLANTED", "", ""},
		{"azure", "azure", "/subscriptions/" + sub + "/resourceGroups/rg", "", "", sub, ""},
		{"azure subscription not a uuid", "azure", "/subscriptions/PLANTED-SUB/resourceGroups/rg", "", "", "", ""},
		{"gcp", "gcp", "projects/acme-prod/regions/europe-west1/subnetworks/s", "", "", "acme-prod", "europe-west1"},
		{"gcp zone", "gcp", "projects/acme-prod/zones/europe-west1-b/instances/i", "", "", "acme-prod", "europe-west1"},
		{"gcp location", "gcp", "projects/acme-prod/locations/us/keyRings/k", "", "", "acme-prod", "us"},
		{"gcp project not shaped", "gcp", "projects/Not A Project/regions/PLANTED/subnetworks/s", "", "", "", ""},
	} {
		s := scopeOf(c.cloud, c.id, c.arn, c.identity)
		if s.account != c.account || s.region != c.region {
			t.Errorf("%s: account %q region %q, want %q %q", c.name, s.account, s.region, c.account, c.region)
		}
	}
}

func TestUnshapedAccountAndRegionAreNotWritten(t *testing.T) {
	doc := tfstate.Document{Source: boundsRoot, Serial: 1, Lineage: "l", Instances: []tfstate.Instance{{
		Mode: "managed", Type: "aws_vpc", Name: "v", Address: "aws_vpc.v", Provider: `provider["registry.terraform.io/hashicorp/aws"]`,
		ID: "vpc-0a1b", ARN: "arn:aws:ec2:PLANTED-REGION-X:PLANTED-ACCOUNT-X:vpc/vpc-0a1b",
	}}}
	res := build(t, []Read{{Location: boundsRoot, Docs: []tfstate.Document{doc}}})
	// The ARN is the node's path and is written; the account and region are
	// what is cut from it, and stand in their own columns and in the manifest.
	for _, n := range res.Tables.Nodes {
		if n.Kind == snapshot.KindResource && (n.Account != "" || n.Region != "") {
			t.Errorf("node has account %q and region %q", n.Account, n.Region)
		}
	}
	for file, data := range writeFilesWith(t, res) {
		if file == "manifest.json" && (bytes.Contains(data, []byte("PLANTED-ACCOUNT-X")) || bytes.Contains(data, []byte("PLANTED-REGION-X"))) {
			t.Errorf("the manifest holds an account or a region that is not one")
		}
	}
}

func TestInventoryAccountAndRegionKeepOnlyKnownShapes(t *testing.T) {
	inv, err := ParseInventory([]byte(`{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","tool":{"name":"infraharvest","version":"0.9.0"},
	 "cloud":"aws","redaction":{},"resources":[
	 {"type":"aws_s3_bucket","id":"acme-logs","account":"PLANTED-ACCOUNT-Y","region":"PLANTED-REGION-Y","status":"unmanaged","status_basis":"none"},
	 {"type":"aws_s3_bucket","id":"acme-ok","account":"111111111111","region":"eu-west-1","status":"unmanaged","status_basis":"none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := BuildAll(nil, []InventoryRead{{Location: "i.json", Inv: inv}}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for file, data := range writeFilesWith(t, res) {
		for _, bad := range []string{"PLANTED-ACCOUNT-Y", "PLANTED-REGION-Y"} {
			if bytes.Contains(data, []byte(bad)) {
				t.Errorf("%s holds %q", file, bad)
			}
		}
	}
	ok := resourceNode(t, res.Tables, "aws_s3_bucket", "acme-ok")
	if ok.Account != "111111111111" || ok.Region != "eu-west-1" {
		t.Errorf("a well-formed account and region were changed: %q %q", ok.Account, ok.Region)
	}
}
