// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A document that says ids_hashed but holds raw values must not put them in a
// hashed snapshot: the flag is a claim, and only a value with the shape of a
// hash is kept as it is.

const mislabelledV1 = `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z",
 "tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws","scopes":["aws/111111111111/eu-west-1"],
 "redaction":{"ids_hashed":true,"tag_keys_dropped":[]},
 "resources":[
  {"type":"aws_vpc","id":"vpc-0rawid1234","account":"111111111111","region":"eu-west-1","status":"unmanaged","status_basis":"none","name":"raw-name-prod"},
  {"type":"aws_s3_bucket","id":"raw-bucket-name","account":"111111111111","status":"unmanaged","status_basis":"none"}]}`

var mislabelledOCSF = `{"schema":"infraharvest/ocsf-inventory/v1","redaction":{"ids_hashed":true},
 "events":[{"time":1795600800000,"metadata":{"product":{"name":"infraharvest","version":"0.9.0"}},
  "cloud":{"provider":"AWS","account":{"uid":"111111111111"},"region":"eu-west-1"},
  "resources":[{"type":"aws_vpc","uid":"` + strings.Repeat("a", 64) + `","name":"raw-ocsf-name",
   "labels":["status:managed","status_basis:state"],
   "iac":{"address":"module.raw.aws_vpc.rawaddr","module_address":"module.raw","state_key":"raw/state/key.tfstate"}}]}]}`

func mislabelledReads(t *testing.T, docs ...string) []InventoryRead {
	t.Helper()
	var reads []InventoryRead
	for i, d := range docs {
		inv, err := ParseInventory([]byte(d))
		if err != nil {
			t.Fatal(err)
		}
		if !inv.IDsHashed {
			t.Fatal("the fixture does not claim to be hashed")
		}
		inv.Location = "mislabelled-" + string(rune('a'+i)) + ".json"
		reads = append(reads, InventoryRead{Location: inv.Location, Inv: inv})
	}
	return reads
}

func TestInventoryThatClaimsHashedIDsButHoldsRawOnesIsHashed(t *testing.T) {
	res, err := BuildAll(nil, mislabelledReads(t, mislabelledV1, mislabelledOCSF), hashedOpts(testKey))
	if err != nil {
		t.Fatal(err)
	}
	for file, data := range writeHashed(t, res) {
		for _, raw := range []string{"vpc-0rawid1234", "raw-name-prod", "raw-bucket-name", "raw-ocsf-name", "module.raw", "rawaddr", "raw/state/key"} {
			if bytes.Contains(data, []byte(raw)) {
				t.Errorf("%s holds %q", file, raw)
			}
		}
	}
	// The raw ID is hashed as an unflagged inventory's would be.
	found := false
	for _, n := range res.Tables.Nodes {
		found = found || n.NativeID == secretscan.Hash(testKey, "vpc-0rawid1234")
		for _, v := range []string{n.NativeID, n.ARNOrPath, n.Name, n.Address, n.Module, n.Root} {
			if v != "" && !hashedValue(v) {
				t.Errorf("node %s holds %q, which is not a hash", n.NodeID, v)
			}
		}
	}
	if !found {
		t.Error("no node has the keyed hash of the raw ID")
	}
	if !strings.Contains(res.Limits, "not hashes") {
		t.Errorf("limits do not say the inventories were mislabelled: %s", res.Limits)
	}
	if !res.Redaction.IDsHashed || res.Redaction.HashAlgorithm != HashAlgorithm {
		t.Errorf("redaction %+v", res.Redaction)
	}
	s, err := snapshot.Build(res.Tables, snapshot.BuildOptions{CreatedAt: opts.CollectedAt, Limits: res.Limits, Redaction: res.Redaction})
	if err != nil {
		t.Fatal(err)
	}
	if s.Manifest.Redaction.HashAlgorithm != HashAlgorithm {
		t.Errorf("manifest says %q", s.Manifest.Redaction.HashAlgorithm)
	}
}

func TestMislabelledInventoryJoinsLikeAPlainOne(t *testing.T) {
	// Hashed here, it joins the state as the plain inventory does.
	plain := mislabelledV1
	plain = strings.Replace(plain, `"ids_hashed":true`, `"ids_hashed":false`, 1)
	pinv, err := ParseInventory([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	a, err := BuildAll(nil, []InventoryRead{{Location: "x.json", Inv: pinv}}, hashedOpts(testKey))
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildAll(nil, mislabelledReads(t, mislabelledV1), hashedOpts(testKey))
	if err != nil {
		t.Fatal(err)
	}
	ids := func(r Result) map[string]bool { return nodeIDs(r) }
	for id := range ids(a) {
		if !ids(b)[id] {
			t.Errorf("node %s of the honest inventory is not in the mislabelled one", id)
		}
	}
}

func TestHashFieldKeepsOnlyHashShapedValues(t *testing.T) {
	b := &builder{key: testKey, preHashed: map[string]bool{}}
	b.markHashed("n", "name", "address")
	hashed := secretscan.Hash(testKey, "x")
	if got := b.hashField("n", "name", hashed); got != hashed {
		t.Errorf("a hash was hashed again: %q", got)
	}
	if got := b.hashField("n", "address", "module.raw.aws_vpc.x"); got != secretscan.Hash(testKey, "module.raw.aws_vpc.x") {
		t.Errorf("a raw value in a pre-hashed field was kept: %q", got)
	}
}
