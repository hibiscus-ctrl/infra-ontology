// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// canary is the secret the fuzz test plants. It is written into the input
// after the fuzzer has mutated it, in places the reader must drop, so the
// fuzzer cannot move it into a field the snapshot keeps.
const canary = "PLANTED-FUZZ-CANARY-7Q3ZK9XW4M2B"

// fuzzKey stands in for a --hash-ids key.
var fuzzKey = []byte("fuzz-key-0123456789-abcdef-ZZZZ")

// plant writes the canary into every place of a state the reader must
// drop: the values of attributes, of tags, of outputs, and the settings of a
// terraform_remote_state. A document that is not a JSON object is returned as
// it is.
func plant(raw []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || doc == nil {
		return raw
	}
	if outputs, ok := doc["outputs"].(map[string]any); ok {
		outputs["zz_planted"] = map[string]any{"value": canary, "type": "string", "sensitive": true}
	}
	resources, _ := doc["resources"].([]any)
	for _, r := range resources {
		res, _ := r.(map[string]any)
		instances, _ := res["instances"].([]any)
		for _, i := range instances {
			in, _ := i.(map[string]any)
			attrs, ok := in["attributes"].(map[string]any)
			if !ok {
				continue
			}
			attrs["zz_planted"] = canary
			attrs["password"] = canary
			attrs["tags"] = map[string]any{"zz_planted": canary}
			plantInto(attrs["config"])
			plantInto(attrs["outputs"])
		}
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return out
}

// plantInto adds the canary to a remote state's config or outputs, as
// Terraform writes them ({"value": {...}, "type": ...}) or as a plain object.
func plantInto(v any) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	if inner, ok := m["value"].(map[string]any); ok {
		inner["zz_planted"] = canary
		inner["secret_key"] = canary
		return
	}
	m["zz_planted"] = canary
	m["secret_key"] = canary
}

// FuzzStateIngest reads whatever bytes it is given as a Terraform state, with
// secrets planted in it, and builds a snapshot from it. The state reader and
// the builder must not panic, must give the same rows twice and rows that
// validate, and no planted secret, and no hash key, may be in anything they
// return. A document the reader refuses is skipped.
func FuzzStateIngest(f *testing.F) {
	f.Fuzz(func(t *testing.T, raw []byte) {
		// A state is read whole by the reader; keep the fuzzer to the
		// small documents where the interesting shapes are.
		if len(raw) > 1<<16 {
			t.Skip()
		}
		input := plant(raw)
		const where = "s3://acme-tfstate/prod/net.tfstate"
		doc, err := tfstate.Parse(input, where)
		if err != nil {
			return
		}
		// What the reader keeps, field by field.
		if kept := fmt.Sprintf("%#v", doc); strings.Contains(kept, canary) {
			t.Fatalf("the reader kept a planted secret: %s", kept)
		}

		for _, key := range [][]byte{nil, fuzzKey} {
			o := opts
			o.HashKey = key
			reads := []Read{{Location: where, Docs: []tfstate.Document{doc}}}
			res, err := Build(reads, o)
			if err != nil {
				t.Fatalf("a state that parsed does not build: %v", err)
			}
			again, err := Build(reads, o)
			if err != nil {
				t.Fatal(err)
			}
			out := marshalSorted(t, res)
			if second := marshalSorted(t, again); !bytes.Equal(out, second) {
				t.Fatalf("two builds of one state differ:\n%.2000s\n%.2000s", out, second)
			}
			if err := snapshot.Validate(&res.Tables); err != nil {
				t.Fatalf("the rows do not validate: %v", err)
			}
			if bytes.Contains(out, []byte(canary)) {
				t.Fatalf("a planted secret is in the rows: %s", out)
			}
			if key != nil && bytes.Contains(out, key) {
				t.Fatalf("the hash key is in the rows: %s", out)
			}
		}
	})
}

// marshalSorted is a Result as JSON with its rows in order. Build collects
// them from maps, and the snapshot writer sorts them, so their order here is
// not part of what is compared.
func marshalSorted(t *testing.T, r Result) []byte {
	t.Helper()
	tb := r.Tables
	tb.Nodes = slices.Clone(tb.Nodes)
	tb.Edges = slices.Clone(tb.Edges)
	tb.Sources = slices.Clone(tb.Sources)
	slices.SortFunc(tb.Nodes, func(a, b snapshot.Node) int { return strings.Compare(a.NodeID, b.NodeID) })
	slices.SortFunc(tb.Edges, func(a, b snapshot.Edge) int { return strings.Compare(a.EdgeID, b.EdgeID) })
	slices.SortFunc(tb.Sources, func(a, b snapshot.Source) int { return strings.Compare(a.SourceID, b.SourceID) })
	r.Tables = tb
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPlantWritesTheCanary keeps the fuzz test honest: the canary must be in
// the states it is planted in, in the places the reader drops.
func TestPlantWritesTheCanary(t *testing.T) {
	for _, f := range fixtures {
		raw, err := os.ReadFile(filepath.Join("testdata", "states", f.file))
		if err != nil {
			t.Fatal(err)
		}
		planted := plant(raw)
		if n := bytes.Count(planted, []byte(canary)); n < 2 {
			t.Errorf("%s: %d canaries planted", f.file, n)
		}
		if _, err := tfstate.Parse(planted, f.source); err != nil {
			t.Errorf("%s: a state with the canary planted does not parse: %v", f.file, err)
		}
	}
}
