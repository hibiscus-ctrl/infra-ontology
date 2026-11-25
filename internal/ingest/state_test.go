// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/IgnatG/infraharvest/pkg/tfstate"
	"github.com/IgnatG/infraharvest/pkg/typemap"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// fixtures are the states under testdata/states and the places they are
// pretended to have been read from, one for each kind of backend.
var fixtures = []struct{ file, source string }{
	{"net.tfstate", "s3://acme-tfstate/prod/net.tfstate"},
	{"app.tfstate", "s3://acme-tfstate/prod/app.tfstate"},
	{"platform.tfstate", "tfc://acme/platform"},
	{"dns.tfstate", "gs://acme-gcs-state/dns/default.tfstate"},
	{"hub.tfstate", "https://acmestate.blob.core.windows.net/tfstate/hub.tfstate"},
}

func parseFixture(t *testing.T, file, source string) tfstate.Document {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "states", file))
	if err != nil {
		t.Fatal(err)
	}
	d, err := tfstate.Parse(raw, source)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fixtureReads(t *testing.T) []Read {
	t.Helper()
	var reads []Read
	for _, f := range fixtures {
		d := parseFixture(t, f.file, f.source)
		reads = append(reads, Read{Location: f.source, Docs: []tfstate.Document{d}})
	}
	return reads
}

var opts = Options{
	CollectedAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
	Collector:   "infra-ontology", CollectorVersion: "test",
}

func build(t *testing.T, reads []Read) Result {
	t.Helper()
	res, err := Build(reads, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// nodeAt finds the node at a Terraform address in the state at root.
func nodeAt(t *testing.T, tb snapshot.Tables, root, address string) snapshot.Node {
	t.Helper()
	for _, n := range tb.Nodes {
		if n.Root == root && n.Address == address {
			return n
		}
	}
	t.Fatalf("no node at %s in %s", address, root)
	return snapshot.Node{}
}

func hasEdge(tb snapshot.Tables, kind, basis string, from, to string) bool {
	for _, e := range tb.Edges {
		if e.Kind == kind && e.Basis == basis && e.FromID == from && e.ToID == to {
			return true
		}
	}
	return false
}

const (
	netRoot = "s3://acme-tfstate/prod/net.tfstate"
	appRoot = "s3://acme-tfstate/prod/app.tfstate"
)

func TestInstancesBecomeNodes(t *testing.T) {
	tb := build(t, fixtureReads(t)).Tables

	vpc := nodeAt(t, tb, netRoot, "module.network.aws_vpc.main")
	want := snapshot.Node{
		Kind: snapshot.KindResource, Cloud: "aws", Account: "111111111111", Region: "eu-west-1",
		TFType: "aws_vpc", NativeID: "vpc-0a1b", ARNOrPath: "arn:aws:ec2:eu-west-1:111111111111:vpc/vpc-0a1b",
		Name: "main", Address: "module.network.aws_vpc.main", Module: "module.network", Root: netRoot,
		ManagedStatus: snapshot.Managed, Confidence: snapshot.Observed,
	}
	vpc.NodeID, vpc.SourceID = "", ""
	if fmt.Sprint(vpc) != fmt.Sprint(want) {
		t.Errorf("vpc node\n got %+v\nwant %+v", vpc, want)
	}

	// count: one node for each index, each its own thing.
	s0 := nodeAt(t, tb, netRoot, "module.network.aws_subnet.private[0]")
	s1 := nodeAt(t, tb, netRoot, "module.network.aws_subnet.private[1]")
	if s0.NativeID != "subnet-0c20" || s1.NativeID != "subnet-0c21" || s0.NodeID == s1.NodeID {
		t.Errorf("count instances: %+v %+v", s0, s1)
	}
	// for_each: the key is in the address, not in the name.
	a := nodeAt(t, tb, netRoot, `aws_s3_bucket.logs["app"]`)
	if a.NativeID != "acme-logs-app" || a.Name != "logs" || a.Module != "" || a.Region != "" || a.Account != "" {
		t.Errorf("for_each instance: %+v", a)
	}
	// A module that is itself in a module with a key.
	ep := nodeAt(t, tb, netRoot, `module.network.module.endpoints["s3"].aws_vpc_endpoint.this`)
	if ep.Module != `module.network.module.endpoints["s3"]` {
		t.Errorf("endpoint module %q", ep.Module)
	}
	// The type is the one the catalogue calls it by.
	lb := nodeAt(t, tb, netRoot, "aws_alb.front")
	if lb.TFType != "aws_lb" {
		t.Errorf("aws_alb is %q, want aws_lb", lb.TFType)
	}
	// A data source is not managed by the state that reads it, and is
	// identified by where it is read.
	d := nodeAt(t, tb, netRoot, "data.aws_caller_identity.current")
	if d.ManagedStatus != snapshot.Unknown || d.NativeID != "111111111111" || d.TFType != "aws_caller_identity" {
		t.Errorf("data source: %+v", d)
	}
}

func TestIDsOfGeneratedValuesAreNotKept(t *testing.T) {
	tb := build(t, fixtureReads(t)).Tables
	for _, addr := range []string{"random_password.db", "random_string.suffix"} {
		n := nodeAt(t, tb, netRoot, addr)
		if n.NativeID != "" || n.ARNOrPath != "" {
			t.Errorf("%s keeps an id: %+v", addr, n)
		}
	}
	// A terraform_remote_state's id is not a cloud identifier either.
	if n := nodeAt(t, tb, appRoot, "data.terraform_remote_state.net"); n.NativeID != "" {
		t.Errorf("remote state keeps an id: %+v", n)
	}
	// The same ID in two states is two states of one thing.
}

func TestCloudAndScopeOfOtherClouds(t *testing.T) {
	tb := build(t, fixtureReads(t)).Tables
	rg := nodeAt(t, tb, "https://acmestate.blob.core.windows.net/tfstate/hub.tfstate", "azurerm_resource_group.hub")
	if rg.Cloud != "azure" || rg.Account != "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb" ||
		rg.NativeID != "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg" {
		t.Errorf("azure resource group: %+v", rg)
	}
	sub := nodeAt(t, tb, "gs://acme-gcs-state/dns/default.tfstate", "google_compute_subnetwork.a")
	vm := nodeAt(t, tb, "gs://acme-gcs-state/dns/default.tfstate", "google_compute_instance.vm")
	if sub.Cloud != "gcp" || sub.Account != "acme-prod" || sub.Region != "europe-west1" || vm.Region != "europe-west2" {
		t.Errorf("google: %+v %+v", sub, vm)
	}
	if tf := nodeAt(t, tb, netRoot, "terraform_data.note"); tf.Cloud != "" {
		t.Errorf("terraform_data is in no cloud: %+v", tf)
	}
}

func TestDependenciesAndModules(t *testing.T) {
	tb := build(t, fixtureReads(t)).Tables
	id := func(addr string) string { return nodeAt(t, tb, netRoot, addr).NodeID }
	call := func(addr string) string {
		return snapshot.NodeID(snapshot.KindModuleCall, "", "", "", "", netRoot+"|"+addr)
	}
	root := snapshot.NodeID(snapshot.KindStateRoot, "", "", "", "", netRoot)

	dep := func(from, to string) bool {
		return hasEdge(tb, snapshot.EdgeDependsOn, BasisStateDependency, from, to)
	}
	// A dependency has no instance key, so it reaches every instance.
	if !dep(id("module.network.aws_subnet.private[0]"), id("module.network.aws_vpc.main")) ||
		!dep(id("module.network.aws_subnet.private[1]"), id("module.network.aws_vpc.main")) {
		t.Error("subnets do not depend on the vpc")
	}
	if !dep(id("aws_alb.front"), id("module.network.aws_subnet.private[0]")) ||
		!dep(id("aws_alb.front"), id("module.network.aws_subnet.private[1]")) {
		t.Error("the load balancer does not depend on both subnets")
	}
	if !dep(id("aws_alb.front"), id(`aws_s3_bucket.logs["app"]`)) || !dep(id("aws_alb.front"), id(`aws_s3_bucket.logs["audit"]`)) {
		t.Error("the load balancer does not depend on both buckets")
	}
	if !dep(id("aws_alb.front"), id("data.aws_caller_identity.current")) {
		t.Error("no dependency on a data source")
	}
	// A dependency on a module is on its call.
	if !dep(id("aws_alb.front"), call(`module.network.module.endpoints["s3"]`)) {
		t.Error("no dependency on a module call")
	}
	if !dep(id("aws_db_instance.main"), id("random_password.db")) {
		t.Error("no dependency on the random password")
	}

	contained := func(from, to string) bool {
		return hasEdge(tb, snapshot.EdgeContainedIn, BasisModuleContainment, from, to)
	}
	net, ep := call("module.network"), call(`module.network.module.endpoints["s3"]`)
	if !contained(id("module.network.aws_vpc.main"), net) ||
		!contained(id(`module.network.module.endpoints["s3"].aws_vpc_endpoint.this`), ep) ||
		!contained(ep, net) || !contained(net, root) {
		t.Error("module containment edges are missing")
	}
	// A resource in the root module is in no module call.
	for _, e := range tb.Edges {
		if e.FromID == id("aws_alb.front") && e.Kind == snapshot.EdgeContainedIn {
			t.Errorf("a root resource is in a module: %+v", e)
		}
	}
	// Every instance is defined in its state.
	if !hasEdge(tb, snapshot.EdgeDefinedIn, BasisStateMembership, id("module.network.aws_vpc.main"), root) {
		t.Error("the vpc is not defined in its state")
	}
	// The dependency on aws_s3_bucket.gone, which the state does not hold, is
	// noted, not invented.
	if res := build(t, fixtureReads(t)); !strings.Contains(res.Limits, "1 dependencies name an address the state does not hold") {
		t.Errorf("limits do not mention the missing dependency: %s", res.Limits)
	}
}

func TestRemoteStates(t *testing.T) {
	res := build(t, fixtureReads(t))
	tb := res.Tables
	rootOf := func(loc string) string { return snapshot.NodeID(snapshot.KindStateRoot, "", "", "", "", loc) }
	reads := func(name, toLoc string) bool {
		return hasEdge(tb, snapshot.EdgeReadsStateOf, BasisRemoteState,
			nodeAt(t, tb, appRoot, "data.terraform_remote_state."+name).NodeID, rootOf(toLoc))
	}
	for name, loc := range map[string]string{
		"net":      netRoot,
		"platform": "tfc://acme/platform",
		"dns":      "gs://acme-gcs-state/dns/default.tfstate",
		"hub":      "https://acmestate.blob.core.windows.net/tfstate/hub.tfstate",
	} {
		if !reads(name, loc) {
			t.Errorf("data.terraform_remote_state.%s does not read %s", name, loc)
		}
	}

	// A state that is not in the snapshot is an external placeholder, and the
	// limits say so.
	externals := map[string]snapshot.Node{}
	for _, n := range tb.Nodes {
		if n.Kind == snapshot.KindExternal {
			externals[n.Name] = n
		}
	}
	for _, loc := range []string{"s3://acme-other/shared.tfstate", "s3://acme-tfstate/env:/staging/net.tfstate"} {
		n, ok := externals[loc]
		if !ok {
			t.Errorf("no external node for %s", loc)
			continue
		}
		if n.Confidence != snapshot.Inferred || n.ManagedStatus != snapshot.Unknown || n.NativeID != loc {
			t.Errorf("external %s: %+v", loc, n)
		}
		if !strings.Contains(res.Limits, loc) {
			t.Errorf("limits do not name %s: %s", loc, res.Limits)
		}
	}
	if len(externals) != 3 { // the third is the kubernetes backend, which names no state
		t.Errorf("%d external nodes, want 3: %v", len(externals), keys(externals))
	}
	if !strings.Contains(res.Limits, "1 terraform_remote_state data sources use a backend whose settings name no state") {
		t.Errorf("limits do not mention the backend that names no state: %s", res.Limits)
	}
	// What depends on the data node follows through the ordinary edges.
	if !hasEdge(tb, snapshot.EdgeDependsOn, BasisStateDependency,
		nodeAt(t, tb, appRoot, "aws_instance.app[0]").NodeID, nodeAt(t, tb, appRoot, "data.terraform_remote_state.net").NodeID) {
		t.Error("the instance does not depend on the remote state")
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSources(t *testing.T) {
	tb := build(t, fixtureReads(t)).Tables
	bySource := map[string]snapshot.Source{}
	for _, s := range tb.Sources {
		bySource[s.Location] = s
	}
	net := bySource[netRoot]
	if net.Kind != "state" || net.Backend != "s3" || net.Workspace != "default" || net.Serial == nil || *net.Serial != 17 ||
		net.Lineage != "7a2e9b1c-3f4d-4c5a-8b6e-1d2c3b4a5f60" || net.TerraformVersion != "1.9.8" || len(net.DocumentSHA256) != 64 ||
		net.Status != "ok" || net.CollectedAt != "2026-11-25T12:00:00Z" || net.Collector != "infra-ontology" {
		t.Errorf("net source: %+v", net)
	}
	if got := bySource["tfc://acme/platform"]; got.Backend != "hcp" || got.Workspace != "platform" {
		t.Errorf("platform source: %+v", got)
	}
	if got := bySource["https://acmestate.blob.core.windows.net/tfstate/hub.tfstate"]; got.Backend != "azblob" || got.Workspace != "default" {
		t.Errorf("hub source: %+v", got)
	}
	if got := bySource["gs://acme-gcs-state/dns/default.tfstate"]; got.Backend != "gcs" {
		t.Errorf("dns source: %+v", got)
	}
}

func TestFailedLocationIsAFailedSource(t *testing.T) {
	reads := fixtureReads(t)
	reads = append(reads, Read{Location: "s3://other/state.tfstate?token=PLANTED-TOKEN", Err: fmt.Errorf("access denied reading https://user:PLANTED-PASSWORD@host/path")})
	res := build(t, reads)
	if res.Failed != 1 {
		t.Fatalf("Failed = %d", res.Failed)
	}
	var failed []snapshot.Source
	for _, s := range res.Tables.Sources {
		if s.Status == snapshot.StatusFailed {
			failed = append(failed, s)
		}
	}
	if len(failed) != 1 || failed[0].Location != "s3://other/state.tfstate" || failed[0].Backend != "s3" ||
		strings.Contains(failed[0].Reason, "PLANTED") || !strings.Contains(failed[0].Reason, "access denied") {
		t.Errorf("failed source: %+v", failed)
	}
	if _, err := Build(reads[len(reads)-1:], opts); err == nil || strings.Contains(err.Error(), "PLANTED") {
		t.Errorf("Build with nothing read: %v", err)
	}
	// The rows are a valid snapshot, and it is partial.
	s, err := snapshot.Build(res.Tables, snapshot.BuildOptions{CreatedAt: opts.CollectedAt, Limits: res.Limits})
	if err != nil {
		t.Fatal(err)
	}
	if s.Manifest.Status != snapshot.StatusPartial || len(s.Manifest.Coverage.FailedSources) != 1 {
		t.Errorf("manifest: %+v", s.Manifest)
	}
}

func TestSameThingInTwoStates(t *testing.T) {
	a := parseFixture(t, "net.tfstate", "s3://b/one.tfstate")
	b := parseFixture(t, "net.tfstate", "s3://b/two.tfstate")
	res := build(t, []Read{{Docs: []tfstate.Document{b}}, {Docs: []tfstate.Document{a}}})
	if n := countNodes(res.Tables, "aws_vpc"); n != 1 {
		t.Errorf("%d vpc nodes, want 1", n)
	}
	if !strings.Contains(res.Limits, "held by more than one state") {
		t.Errorf("limits: %s", res.Limits)
	}
	one := snapshot.NodeID(snapshot.KindStateRoot, "", "", "", "", "s3://b/one.tfstate")
	two := snapshot.NodeID(snapshot.KindStateRoot, "", "", "", "", "s3://b/two.tfstate")
	vpc := nodeAt(t, res.Tables, "s3://b/one.tfstate", "module.network.aws_vpc.main")
	if !hasEdge(res.Tables, snapshot.EdgeDefinedIn, BasisStateMembership, vpc.NodeID, one) ||
		!hasEdge(res.Tables, snapshot.EdgeDefinedIn, BasisStateMembership, vpc.NodeID, two) {
		t.Error("the vpc is not defined in both states")
	}
}

func countNodes(tb snapshot.Tables, tfType string) int {
	n := 0
	for _, x := range tb.Nodes {
		if x.TFType == tfType {
			n++
		}
	}
	return n
}

func TestOrderOfInputDoesNotMatter(t *testing.T) {
	reads := fixtureReads(t)
	want := writeFiles(t, build(t, reads))
	for i := range 5 {
		shuffled := slices.Clone(reads)
		for j := range shuffled {
			k := (j*7 + i*3 + 1) % len(shuffled)
			shuffled[j], shuffled[k] = shuffled[k], shuffled[j]
		}
		got := writeFiles(t, build(t, shuffled))
		for name, data := range want {
			if !bytes.Equal(got[name], data) {
				t.Fatalf("order %d: %s differs", i, name)
			}
		}
	}
}

func writeFiles(t *testing.T, res Result) map[string][]byte {
	t.Helper()
	s, err := snapshot.Build(res.Tables, snapshot.BuildOptions{
		CreatedAt: opts.CollectedAt, Label: "fixture", Limits: res.Limits,
		Tool: snapshot.Tool{Name: "infra-ontology", Version: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Files
}

// TestGolden pins the rows of the fixture states in a form a person can
// review, and the bytes of the snapshot through the hashes in its manifest.
func TestGolden(t *testing.T) {
	files := writeFiles(t, build(t, fixtureReads(t)))
	got := map[string][]byte{"manifest.json": files["manifest.json"], "graph.txt": []byte(render(build(t, fixtureReads(t)).Tables))}
	dir := filepath.Join("testdata", "golden")
	for name, data := range got {
		path := filepath.Join(dir, name)
		if *update {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test ./internal/ingest -update)", err)
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s differs from the golden file (run go test ./internal/ingest -update and review the diff)", name)
		}
	}
	// The snapshot is one that verifies.
	var m snapshot.Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil || m.Status != snapshot.StatusOK {
		t.Errorf("manifest: %v %+v", err, m.Status)
	}
}

// render lists the nodes and edges of the rows, one to a line and sorted, so
// that a change to them shows in a diff.
func render(tb snapshot.Tables) string {
	label := map[string]string{}
	for _, n := range tb.Nodes {
		label[n.NodeID] = n.Kind + " " + first(n.Address, n.NativeID, n.Name)
		if n.Kind == snapshot.KindResource || n.Kind == snapshot.KindModuleCall {
			label[n.NodeID] += " @ " + n.Root
		}
	}
	var lines []string
	for _, n := range tb.Nodes {
		lines = append(lines, fmt.Sprintf("node %s | cloud=%s account=%s region=%s type=%s native=%s path=%s name=%s module=%s managed=%s confidence=%s",
			label[n.NodeID], n.Cloud, n.Account, n.Region, n.TFType, n.NativeID, n.ARNOrPath, n.Name, n.Module, n.ManagedStatus, n.Confidence))
	}
	for _, e := range tb.Edges {
		lines = append(lines, fmt.Sprintf("edge %s/%s/%s | %s -> %s", e.Kind, e.Basis, e.Confidence, label[e.FromID], label[e.ToID]))
	}
	for _, s := range tb.Sources {
		serial := "-"
		if s.Serial != nil {
			serial = fmt.Sprint(*s.Serial)
		}
		lines = append(lines, fmt.Sprintf("source %s | backend=%s workspace=%s serial=%s version=%s status=%s", s.Location, s.Backend, s.Workspace, serial, s.TerraformVersion, s.Status))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func TestCredentialIDsAreNotKept(t *testing.T) {
	key := "gh" + "p_" + strings.Repeat("a1", 18)
	d := tfstate.Document{Source: "s3://b/k.tfstate", Instances: []tfstate.Instance{{
		Mode: "managed", Type: "aws_iam_access_key", Name: "ci", Address: "aws_iam_access_key.ci",
		Provider: `provider["registry.terraform.io/hashicorp/aws"]`, ID: key,
	}}}
	res := build(t, []Read{{Docs: []tfstate.Document{d}}})
	raw, _ := json.Marshal(res)
	if bytes.Contains(raw, []byte(key)) {
		t.Errorf("the rows hold the token: %s", raw)
	}
	n := nodeAt(t, res.Tables, "s3://b/k.tfstate", "aws_iam_access_key.ci")
	if n.NativeID != "" || !strings.Contains(res.Limits, "looks like a credential") {
		t.Errorf("node %+v, limits %s", n, res.Limits)
	}
}

func TestIDsThatHoldSecretsOrFreeTextAreNotKept(t *testing.T) {
	tm, err := typemap.New()
	if err != nil {
		t.Fatal(err)
	}
	b := &builder{tm: tm}
	s := &docState{loc: "state.tfstate", source: "src"}
	token := "ghp_" + strings.Repeat("a1B2", 9)
	for _, in := range []tfstate.Instance{
		{Mode: "data", Type: "http", Provider: `provider["registry.terraform.io/hashicorp/http"]`, Address: "data.http.x", ID: "https://api.example.com/v1?token=abc"},
		{Mode: "data", Type: "external", Provider: `provider["registry.terraform.io/hashicorp/external"]`, Address: "data.external.x", ID: "anything the program printed"},
		{Mode: "managed", Type: "aws_s3_object", Provider: `provider["registry.terraform.io/hashicorp/aws"]`, Address: "aws_s3_object.a", ID: "https://user:pass@example.com/x"},
		{Mode: "managed", Type: "aws_s3_object", Provider: `provider["registry.terraform.io/hashicorp/aws"]`, Address: "aws_s3_object.b", ID: "prefix " + token},
	} {
		n := b.instanceNode(s, in)
		if n.NativeID != "" || n.ARNOrPath != "" {
			t.Errorf("%s keeps an id: %q %q", in.Address, n.NativeID, n.ARNOrPath)
		}
	}
	// An ordinary URL ID with nothing secret in it is kept.
	in := tfstate.Instance{Mode: "managed", Type: "google_storage_bucket", Provider: `provider["registry.terraform.io/hashicorp/google"]`, Address: "google_storage_bucket.a", ID: "https://www.googleapis.com/storage/v1/b/a"}
	if n := b.instanceNode(s, in); n.NativeID == "" {
		t.Errorf("a plain URL id was dropped: %+v", n)
	}
}
