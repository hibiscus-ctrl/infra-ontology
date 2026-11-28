// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// document_sha256 is an unkeyed hash, so it must not cover what the snapshot
// withholds: anyone could confirm a guess at it.

func stateDigest(t *testing.T, res Result) string {
	t.Helper()
	for _, s := range res.Tables.Sources {
		if s.Kind == snapshot.SourceState {
			return s.DocumentSHA256
		}
	}
	t.Fatal("no state source")
	return ""
}

func digestState(t *testing.T, bucketID, password, tag string) Result {
	t.Helper()
	token := "gh" + "p_" + strings.Repeat("a1B2c3", 6)
	doc := tfstate.Document{Source: boundsRoot, Serial: 3, Lineage: "l", TerraformVersion: "1.9.0", Instances: []tfstate.Instance{
		{Mode: "managed", Type: "aws_s3_bucket", Name: "b", Address: "aws_s3_bucket.b", Provider: `provider["registry.terraform.io/hashicorp/aws"]`, ID: bucketID, Tags: map[string]string{"env": tag}},
		// The ID of a random_password is its secret; an ID that is a token is withheld.
		{Mode: "managed", Type: "random_password", Name: "p", Address: "random_password.p", Provider: `provider["registry.terraform.io/hashicorp/random"]`, ID: password},
		{Mode: "managed", Type: "aws_iam_access_key", Name: "k", Address: "aws_iam_access_key.k", Provider: `provider["registry.terraform.io/hashicorp/aws"]`, ID: token + password},
	}}
	return build(t, []Read{{Location: boundsRoot, Docs: []tfstate.Document{doc}}})
}

func TestStateDigestLeavesOutWhatTheSnapshotWithholds(t *testing.T) {
	base := stateDigest(t, digestState(t, "acme-logs", "guess-one", "dev"))
	if len(base) != 64 {
		t.Fatalf("digest %q", base)
	}
	if got := stateDigest(t, digestState(t, "acme-logs", "guess-two", "dev")); got != base {
		t.Error("the digest changes with the ID of a random_password or of a credential, which are withheld")
	}
	if got := stateDigest(t, digestState(t, "acme-logs", "guess-one", "prod")); got != base {
		t.Error("the digest changes with a tag")
	}
	if got := stateDigest(t, digestState(t, "acme-other", "guess-one", "dev")); got == base {
		t.Error("the digest does not change with the ID of a resource that is written")
	}
}

func digestInventory(t *testing.T, name, tag, id string) Inventory {
	t.Helper()
	inv, err := ParseInventory([]byte(`{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","tool":{"name":"infraharvest","version":"0.9.0"},
	 "cloud":"aws","redaction":{},"resources":[
	 {"type":"aws_s3_bucket","id":"acme-logs","account":"111111111111","status":"unmanaged","status_basis":"none","name":"` + name + `","tags":{"env":"` + tag + `"}},
	 {"type":"aws_s3_bucket","id":"` + id + `","account":"111111111111","status":"unmanaged","status_basis":"none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestInventoryDigestLeavesOutWhatTheSnapshotWithholds(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("a1B2c3", 6)
	token2 := "gh" + "p_" + strings.Repeat("z9Y8x7", 6)
	base := digestInventory(t, "logs", "dev", token).Digest
	if got := digestInventory(t, "logs", "prod", token).Digest; got != base {
		t.Error("the digest changes with a tag")
	}
	if got := digestInventory(t, "logs", "dev", token2).Digest; got != base {
		t.Error("the digest changes with the ID of a resource left out for being a credential")
	}
	if got := digestInventory(t, "other", "dev", token).Digest; got == base {
		t.Error("the digest does not change with the name of a resource, which is written")
	}
	a := digestInventory(t, token, "dev", token).Digest
	b := digestInventory(t, token2, "dev", token).Digest
	if a != b {
		t.Error("the digest changes with a name that is a credential, which is cleared")
	}
}
