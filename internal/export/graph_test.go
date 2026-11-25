// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package export_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/hibiscus-ctrl/infra-ontology/internal/export"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// update rewrites the golden file: go test ./internal/export -update. Review
// the diff before committing.
var update = flag.Bool("update", false, "rewrite the golden file")

const (
	estateDir  = "../snapshot/testdata/golden/estate"
	goldenFile = "testdata/estate.graph.json"
)

var tool = snapshot.Tool{Name: "infra-ontology", Version: "dev"}

func loadEstate(t *testing.T) *snapshot.Loaded {
	t.Helper()
	l, err := snapshot.Load(estateDir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func exportJSON(t *testing.T, l *snapshot.Loaded, opts export.Options) ([]byte, *export.Result) {
	t.Helper()
	opts.Tool = tool
	res, err := export.ToGraph(l, opts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := export.Marshal(res.Graph)
	if err != nil {
		t.Fatal(err)
	}
	return raw, res
}

// schema compiles the graph/v1 schema infraharvest publishes, vendored
// unchanged in testdata (see testdata/NOTICE).
func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile("testdata/graph-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		ID string `json:"$id"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	if err := c.AddResource(meta.ID, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// valid checks a document against the schema, and against what a schema
// cannot say and Terragram's reader checks: every edge and parent is an index
// of a node, and a parent is a module call.
func valid(t *testing.T, raw []byte) {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema(t).Validate(doc); err != nil {
		t.Fatalf("does not validate against graph/v1: %v", err)
	}
	var g export.Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	seen := map[export.Edge]bool{}
	for i, e := range g.Edges {
		if e.From >= len(g.Nodes) || e.To >= len(g.Nodes) {
			t.Errorf("edge %d points at no node", i)
		}
		if e.From == e.To {
			t.Errorf("edge %d refers to itself", i)
		}
		if seen[e] {
			t.Errorf("edge %d is repeated", i)
		}
		seen[e] = true
	}
	for i, n := range g.Nodes {
		if n.Parent != nil && (*n.Parent >= len(g.Nodes) || g.Nodes[*n.Parent].Kind != "module") {
			t.Errorf("node %d has a parent that is not a module call", i)
		}
	}
}

func TestEstateExportValidatesAndMatchesTheGolden(t *testing.T) {
	raw, res := exportJSON(t, loadEstate(t), export.Options{})
	valid(t, raw)
	if *update {
		if err := os.WriteFile(goldenFile, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) {
		t.Errorf("the export differs from %s; review the change and rewrite it with -update\n%s", goldenFile, raw)
	}
	g := res.Graph
	if g.Cloud != "aws" || g.Schema != "infraharvest/graph/v1" || g.GeneratedAt != "2026-11-25T10:15:00Z" {
		t.Errorf("root fields: %s %s %s", g.Cloud, g.Schema, g.GeneratedAt)
	}
}

func TestEstateMapping(t *testing.T) {
	res := mustExport(t, loadEstate(t), export.Options{})
	var resources, modules, parents int
	for _, n := range res.Graph.Nodes {
		switch n.Kind {
		case "resource":
			resources++
			if n.Parent != nil {
				parents++
			}
		case "module":
			modules++
			if n.Account == "" || n.Environment == "" || n.ModuleAddress != "module.network" || n.Source != "other" {
				t.Errorf("a module call lost its scope: %+v", n)
			}
		}
	}
	// Eight resources (three a root, the prod bucket and the unmanaged one),
	// two module calls, two references a root, and the four resources in a module.
	if resources != 8 || modules != 2 || parents != 4 || len(res.Graph.Edges) != 4 {
		t.Errorf("got %d resources, %d modules, %d parents, %d edges", resources, modules, parents, len(res.Graph.Edges))
	}
	wantNodes := map[string]int{"account": 2, "state_root": 2, "external": 1}
	wantEdges := map[string]int{"contained_in": 3, "defined_in": 2, "reads_state_of": 2}
	if !mapsEqual(res.Dropped.Nodes, wantNodes) || !mapsEqual(res.Dropped.Edges, wantEdges) {
		t.Errorf("dropped %s", res.Dropped)
	}
	// An unmanaged resource is drawn like any other, with the type the
	// inventory gives it.
	if !slices.ContainsFunc(res.Graph.Nodes, func(n export.Node) bool { return n.ID == "acme-legacy-uploads" && n.Address == "" }) {
		t.Error("the unmanaged bucket is not in the export")
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func mustExport(t *testing.T, l *snapshot.Loaded, opts export.Options) *export.Result {
	t.Helper()
	_, res := exportJSON(t, l, opts)
	return res
}

func TestExportIsDeterministic(t *testing.T) {
	first, _ := exportJSON(t, loadEstate(t), export.Options{})
	for seed := uint64(1); seed <= 20; seed++ {
		l := loadEstate(t)
		r := rand.New(rand.NewPCG(seed, seed))
		r.Shuffle(len(l.Tables.Nodes), func(i, j int) { l.Tables.Nodes[i], l.Tables.Nodes[j] = l.Tables.Nodes[j], l.Tables.Nodes[i] })
		r.Shuffle(len(l.Tables.Edges), func(i, j int) { l.Tables.Edges[i], l.Tables.Edges[j] = l.Tables.Edges[j], l.Tables.Edges[i] })
		got, _ := exportJSON(t, l, export.Options{})
		if !bytes.Equal(first, got) {
			t.Fatalf("rows in another order (seed %d) gave other bytes", seed)
		}
	}
	// And with the addresses dropped, where only the type and id tell nodes apart.
	l := loadEstate(t)
	l.Manifest.Redaction.AddressesDropped = true
	a, _ := exportJSON(t, l, export.Options{})
	slices.Reverse(l.Tables.Nodes)
	slices.Reverse(l.Tables.Edges)
	b, _ := exportJSON(t, l, export.Options{})
	if !bytes.Equal(a, b) {
		t.Error("dropping the addresses made the order depend on the rows' order")
	}
}

// The run id and the time come from the snapshot, never from the clock, and
// another snapshot or cloud gets another run id.
func TestRunIDAndTimeFollowTheSnapshot(t *testing.T) {
	l := loadEstate(t)
	a := mustExport(t, l, export.Options{}).Graph
	l.Manifest.SnapshotID = strings.Repeat("a", 64)
	b := mustExport(t, l, export.Options{}).Graph
	if a.RunID == b.RunID {
		t.Error("two snapshots share a run id")
	}
	l.Manifest.CreatedAt = "2026-11-25T11:15:00+01:00"
	if got := mustExport(t, l, export.Options{}).Graph.GeneratedAt; got != "2026-11-25T10:15:00Z" {
		t.Errorf("generated_at = %s, want the snapshot's time in UTC", got)
	}
}

func TestPlainRedaction(t *testing.T) {
	raw, res := exportJSON(t, loadEstate(t), export.Options{})
	if r := res.Graph.Redaction; r.IDsHashed || r.Addresses != "plain" || r.HashAlg != "hmac-sha256" {
		t.Errorf("redaction = %+v", r)
	}
	if !bytes.Contains(raw, []byte(`"address": "module.network.aws_vpc.main"`)) || !bytes.Contains(raw, []byte(`"root": "net/prod"`)) {
		t.Error("a plain snapshot lost its addresses")
	}
}

// What a snapshot keeps and a graph cannot hold never reaches the document.
func TestNoTagsNamesOrARNs(t *testing.T) {
	raw, _ := exportJSON(t, loadEstate(t), export.Options{})
	for _, s := range []string{"platform", "owner", "arn:", "prod-account", "acme-other", "s3://", "tags", "legacy-uploads-name"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("the export has %q", s)
		}
	}
}

func TestDroppedAddressesStayDropped(t *testing.T) {
	l := loadEstate(t)
	l.Manifest.Redaction.AddressesDropped = true // the rows still carry them
	raw, res := exportJSON(t, l, export.Options{})
	valid(t, raw)
	if res.Graph.Redaction.Addresses != "dropped" {
		t.Errorf("addresses = %s", res.Graph.Redaction.Addresses)
	}
	for _, key := range []string{`"address"`, `"module_address"`, `"root"`, "module.network", "net/prod"} {
		if bytes.Contains(raw, []byte(key)) {
			t.Errorf("the export has %s although the addresses were dropped", key)
		}
	}
	// What is not an address is kept, and the structure is the same.
	if !bytes.Contains(raw, []byte(`"environment": "prod"`)) || len(res.Graph.Edges) != 4 {
		t.Error("dropping the addresses lost more than the addresses")
	}
	// Dropped wins over hashed.
	l.Manifest.Redaction = snapshot.Redaction{HashAlgorithm: "hmac-sha256", IDsHashed: true, AddressesDropped: true}
	l = hashed(l)
	if got := mustExport(t, l, export.Options{}).Graph.Redaction; got.Addresses != "dropped" || !got.IDsHashed {
		t.Errorf("redaction = %+v", got)
	}
}

// hashed returns a copy of l written as ids-hashed snapshot would be: the
// native ids, addresses and roots as an HMAC.
func hashed(l *snapshot.Loaded) *snapshot.Loaded {
	h := func(s string) string {
		if s == "" {
			return ""
		}
		m := hmac.New(sha256.New, []byte("test key"))
		m.Write([]byte(s))
		return hex.EncodeToString(m.Sum(nil))
	}
	out := *l
	out.Tables.Nodes = slices.Clone(l.Tables.Nodes)
	for i, n := range out.Tables.Nodes {
		out.Tables.Nodes[i].NativeID, out.Tables.Nodes[i].Address, out.Tables.Nodes[i].Root = h(n.NativeID), h(n.Address), h(n.Root)
		out.Tables.Nodes[i].ARNOrPath, out.Tables.Nodes[i].Name = h(n.ARNOrPath), h(n.Name)
	}
	return &out
}

func TestHashedIDsAndAddressesStayHashed(t *testing.T) {
	l := hashed(loadEstate(t))
	l.Manifest.Redaction = snapshot.Redaction{HashAlgorithm: "hmac-sha256", IDsHashed: true}
	raw, res := exportJSON(t, l, export.Options{})
	valid(t, raw)
	if r := res.Graph.Redaction; !r.IDsHashed || r.Addresses != "hashed" || r.HashAlg != "hmac-sha256" {
		t.Errorf("redaction = %+v", r)
	}
	for _, n := range res.Graph.Nodes {
		for _, v := range []string{n.ID, n.Address, n.Root, n.ModuleAddress} {
			if v != "" && len(v) != 64 {
				t.Errorf("a hashed value was changed: %q", v)
			}
		}
	}
	for _, s := range []string{"module.network", "net/prod", "acme", "aws_vpc.main", "-vpc-"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("a hashed export has %q", s)
		}
	}
	// The structure is the plain export's.
	plain := mustExport(t, loadEstate(t), export.Options{})
	if len(res.Graph.Nodes) != len(plain.Graph.Nodes) || len(res.Graph.Edges) != len(plain.Graph.Edges) {
		t.Error("hashing changed what is drawn")
	}
}

// A snapshot that claims hashed ids or addresses, and has plain ones, is
// refused: the document would say hashed of a name.
func TestPlainValuesInAHashedSnapshotAreRefused(t *testing.T) {
	cases := map[string]func(l *snapshot.Loaded){
		"an id": func(l *snapshot.Loaded) {
			for i, n := range l.Tables.Nodes {
				if n.Kind == snapshot.KindResource {
					l.Tables.Nodes[i].NativeID = "acme-prod-logs"
				}
			}
		},
		"an address": func(l *snapshot.Loaded) {
			for i, n := range l.Tables.Nodes {
				if n.Kind == snapshot.KindResource {
					l.Tables.Nodes[i].Address = "aws_s3_bucket.logs"
				}
			}
		},
		"a module call": func(l *snapshot.Loaded) {
			for i, n := range l.Tables.Nodes {
				if n.Kind == snapshot.KindModuleCall {
					l.Tables.Nodes[i].Address = "module.network"
				}
			}
		},
		"a root": func(l *snapshot.Loaded) {
			for i, n := range l.Tables.Nodes {
				if n.Kind == snapshot.KindResource {
					l.Tables.Nodes[i].Root = "net/prod"
				}
			}
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			l := hashed(loadEstate(t))
			l.Manifest.Redaction = snapshot.Redaction{HashAlgorithm: "hmac-sha256", IDsHashed: true}
			spoil(l)
			if _, err := export.ToGraph(l, export.Options{Tool: tool}); err == nil || !strings.Contains(err.Error(), "nothing is written") {
				t.Errorf("err = %v, want a refusal", err)
			}
		})
	}
	l := loadEstate(t)
	l.Manifest.Redaction = snapshot.Redaction{HashAlgorithm: "none", IDsHashed: true}
	if _, err := export.ToGraph(l, export.Options{Tool: tool}); err == nil {
		t.Error("ids hashed with no algorithm were accepted")
	}
}

func TestCloudChoice(t *testing.T) {
	l := loadEstate(t)
	// A second cloud: the same estate's prod resources, as Google ones.
	for _, n := range slices.Clone(l.Tables.Nodes) {
		if n.Kind == snapshot.KindResource && n.Environment == "staging" {
			n.NodeID = snapshot.NodeID(n.Kind, "gcp", n.Account, n.Region, n.TFType, n.NativeID)
			n.Cloud, n.TFType, n.Account = "gcp", "google_compute_network", "my-project"
			l.Tables.Nodes = append(l.Tables.Nodes, n)
		}
	}
	if _, err := export.ToGraph(l, export.Options{Tool: tool}); err == nil || !strings.Contains(err.Error(), "--cloud") {
		t.Fatalf("err = %v, want it to ask for --cloud", err)
	}
	g := mustExport(t, l, export.Options{Cloud: "gcp"})
	raw, err := export.Marshal(g.Graph)
	if err != nil {
		t.Fatal(err)
	}
	valid(t, raw)
	if g.Graph.Cloud != "google" || len(g.Graph.Nodes) != 3 {
		t.Errorf("cloud %s with %d nodes: want google with the three resources", g.Graph.Cloud, len(g.Graph.Nodes))
	}
	for _, n := range g.Graph.Nodes {
		if n.Account != "my-project" || n.Parent != nil {
			t.Errorf("a node of another cloud or a parent in it: %+v", n)
		}
	}
	if g.Dropped.Nodes["other_cloud"] == 0 {
		t.Errorf("dropped %s", g.Dropped)
	}
	aws := mustExport(t, l, export.Options{Cloud: "aws"})
	if aws.Graph.Cloud != "aws" || len(aws.Graph.Nodes) != 10 {
		t.Errorf("aws: %d nodes", len(aws.Graph.Nodes))
	}
	for _, bad := range []string{"azure", "oracle"} {
		if _, err := export.ToGraph(l, export.Options{Cloud: bad, Tool: tool}); err == nil {
			t.Errorf("--cloud %s was accepted", bad)
		}
	}
}

func TestNothingToDraw(t *testing.T) {
	l := loadEstate(t)
	l.Tables.Nodes = slices.DeleteFunc(slices.Clone(l.Tables.Nodes), func(n snapshot.Node) bool { return n.Kind == snapshot.KindResource })
	if _, err := export.ToGraph(l, export.Options{Tool: tool}); err == nil {
		t.Error("a snapshot without resources was exported")
	}
}

// A resource the snapshot knows only by an inventory type is drawn by it; one
// with no id cannot be drawn.
func TestTypeAndIDFallbacks(t *testing.T) {
	l := loadEstate(t)
	l.Tables.Nodes = slices.Clone(l.Tables.Nodes)
	var typed, noID int
	for i, n := range l.Tables.Nodes {
		if n.Kind != snapshot.KindResource {
			continue
		}
		switch n.NativeID {
		case "acme-legacy-uploads":
			l.Tables.Nodes[i].TFType = ""
			typed++
		case "acme-prod-logs":
			l.Tables.Nodes[i].NativeID = ""
			noID++
		}
	}
	res := mustExport(t, l, export.Options{})
	if typed != 1 || noID != 1 || res.Dropped.Nodes["no_type_or_id"] != 1 {
		t.Errorf("dropped %s", res.Dropped)
	}
	if !slices.ContainsFunc(res.Graph.Nodes, func(n export.Node) bool { return n.Type == "AWS::S3::Bucket" }) {
		t.Error("the inventory type was not used")
	}
}

func TestMarshalEndsWithANewlineAndKeepsHTMLAsItIs(t *testing.T) {
	l := loadEstate(t)
	l.Tables.Nodes = slices.Clone(l.Tables.Nodes)
	for i, n := range l.Tables.Nodes {
		if n.Kind == snapshot.KindResource {
			l.Tables.Nodes[i].Region = "<eu>&"
			break
		}
	}
	raw, _ := exportJSON(t, l, export.Options{})
	if !bytes.HasSuffix(raw, []byte("}\n")) || !bytes.Contains(raw, []byte("<eu>&")) {
		t.Error("unexpected encoding")
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	if *update {
		if err := os.MkdirAll(filepath.Dir(goldenFile), 0o755); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}
