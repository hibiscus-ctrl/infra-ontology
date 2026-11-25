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
	"sort"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

var inventoryFixtures = []string{"aws.inventory.json", "azure.ocsf-inventory.json", "gcp.inventory.json"}

func inventoryReads(t *testing.T) []InventoryRead {
	t.Helper()
	var paths []string
	for _, f := range inventoryFixtures {
		paths = append(paths, filepath.Join("testdata", "inventory", f))
	}
	reads := ReadInventories(paths)
	for _, r := range reads {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Location, r.Err)
		}
	}
	return reads
}

func buildBoth(t *testing.T, states []Read, invs []InventoryRead) Result {
	t.Helper()
	res, err := BuildAll(states, invs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// resourceNode finds the resource node of a Terraform type and native id.
func resourceNode(t *testing.T, tb snapshot.Tables, typ, native string) snapshot.Node {
	t.Helper()
	var found []snapshot.Node
	for _, n := range tb.Nodes {
		if n.Kind == snapshot.KindResource && n.TFType == typ && strings.EqualFold(n.NativeID, native) {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d nodes of %s %s, want 1", len(found), typ, native)
	}
	return found[0]
}

func containedIn(tb snapshot.Tables, from, to snapshot.Node) (snapshot.Edge, bool) {
	for _, e := range tb.Edges {
		if e.FromID == from.NodeID && e.ToID == to.NodeID && e.Kind == snapshot.EdgeContainedIn {
			return e, true
		}
	}
	return snapshot.Edge{}, false
}

func TestInventoryResourcesJoinTheStateNodes(t *testing.T) {
	stateOnly := build(t, fixtureReads(t))
	res := buildBoth(t, fixtureReads(t), inventoryReads(t))
	tb := res.Tables

	// A resource in both is the state's node, and managed, whatever the
	// inventory called it: the inventory of a discover run says nothing of
	// who manages a thing.
	vpc := resourceNode(t, tb, "aws_vpc", "vpc-0a1b")
	if vpc.ManagedStatus != snapshot.Managed || vpc.Address != "module.network.aws_vpc.main" || vpc.Account != "111111111111" ||
		vpc.InventoryType != "aws_vpc" || vpc.Tags["env"] != "prod" || vpc.Name != "main" {
		t.Errorf("vpc: %+v", vpc)
	}
	if want := resourceNode(t, stateOnly.Tables, "aws_vpc", "vpc-0a1b"); want.NodeID != vpc.NodeID || want.SourceID != vpc.SourceID {
		t.Errorf("the joined node is not the state's: %s and %s", want.NodeID, vpc.NodeID)
	}
	if n := resourceNode(t, tb, "aws_subnet", "subnet-0c21"); n.ManagedStatus != snapshot.Managed || n.Address == "" {
		t.Errorf("a subnet in state that the inventory calls unmanaged: %+v", n)
	}
	// The ARN of a bucket has no account: the inventory gives it one.
	if n := resourceNode(t, tb, "aws_s3_bucket", "acme-logs-app"); n.ManagedStatus != snapshot.Managed || n.Account != "111111111111" || n.Tags["owner"] != "platform" {
		t.Errorf("bucket: %+v", n)
	}
	// Joined by the import ID of an OCSF event whose uid is the ARN.
	if n := resourceNode(t, tb, "aws_s3_bucket", "acme-logs-audit"); n.ManagedStatus != snapshot.Managed || n.Account != "111111111111" || n.Address != `aws_s3_bucket.logs["audit"]` {
		t.Errorf("bucket the OCSF event names by ARN: %+v", n)
	}
	// The same ID in an Azure inventory of another case, and a Google project.
	if n := resourceNode(t, tb, "azurerm_virtual_network", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg/providers/microsoft.network/virtualnetworks/hub-vnet"); n.ManagedStatus != snapshot.Managed || n.Tags["env"] != "prod" {
		t.Errorf("vnet: %+v", n)
	}
	if n := resourceNode(t, tb, "google_compute_instance", "projects/acme-prod/zones/europe-west2-b/instances/vm"); n.ManagedStatus != snapshot.Managed || n.Account != "acme-prod" || n.Region != "europe-west2" || n.Tags["team"] != "infra" {
		t.Errorf("google instance: %+v", n)
	}
	// A state-only node stays as it was, managed, and the limits count it.
	if n := resourceNode(t, tb, "aws_db_instance", "db-ABCDEFG"); n.ManagedStatus != snapshot.Managed || n.InventoryType != "" {
		t.Errorf("db: %+v", n)
	}
	if !strings.Contains(res.Limits, "2 resources in the states read are not in the inventories") {
		t.Errorf("limits: %s", res.Limits)
	}
	// Nothing joined makes a second node: the nodes added are the ones only
	// an inventory lists.
	if added := len(tb.Nodes) - len(stateOnly.Tables.Nodes); added != 10 {
		t.Errorf("%d nodes added", added)
	}
}

func TestInventoryOnlyResourcesTakeTheInventoryStatus(t *testing.T) {
	tb := buildBoth(t, fixtureReads(t), inventoryReads(t)).Tables
	cases := []struct {
		typ, id, status, conf, source string
	}{
		{"aws_s3_bucket", "acme-orphan", snapshot.Unmanaged, snapshot.Observed, "inventory"},
		{"aws_instance", "i-0f00", snapshot.Unmanaged, snapshot.Observed, "inventory"},
		{"aws_iam_role", "legacy-admin", snapshot.OtherIaC, snapshot.Observed, "inventory"},
		{"aws_sqs_queue", "stray", snapshot.Unmanaged, snapshot.Observed, "inventory"},
		{"google_storage_bucket", "acme-prod-assets", snapshot.Unmanaged, snapshot.Observed, "inventory"},
		{"azurerm_subnet", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourceGroups/Hub-RG/providers/Microsoft.Network/virtualNetworks/Hub-VNet/subnets/snet-a", snapshot.Unmanaged, snapshot.Observed, "inventory"},
	}
	sources := map[string]snapshot.Source{}
	for _, s := range tb.Sources {
		sources[s.SourceID] = s
	}
	for _, c := range cases {
		n := resourceNode(t, tb, c.typ, c.id)
		if n.ManagedStatus != c.status || n.Confidence != c.conf || sources[n.SourceID].Kind != c.source || n.Address != "" {
			t.Errorf("%s %s: %+v", c.typ, c.id, n)
		}
		if n.InventoryType != c.typ {
			t.Errorf("%s: inventory type %q", c.id, n.InventoryType)
		}
	}
	// The unmanaged ones are what `queries/unmanaged.sql` lists.
	unmanaged := 0
	for _, n := range tb.Nodes {
		if n.ManagedStatus == snapshot.Unmanaged {
			unmanaged++
		}
	}
	if unmanaged != 9 {
		t.Errorf("%d unmanaged nodes", unmanaged)
	}
}

func TestCatalogueChildAndResourcePathEdges(t *testing.T) {
	tb := buildBoth(t, fixtureReads(t), inventoryReads(t)).Tables
	sources := map[string]snapshot.Source{}
	for _, s := range tb.Sources {
		sources[s.SourceID] = s
	}
	bucket := resourceNode(t, tb, "aws_s3_bucket", "acme-logs-app")
	versioning := resourceNode(t, tb, "aws_s3_bucket_versioning", "acme-logs-app")
	e, ok := containedIn(tb, versioning, bucket)
	if !ok || e.Basis != BasisCatalogueChild || e.Confidence != snapshot.Computed || sources[e.SourceID].Kind != snapshot.SourceInventory {
		t.Errorf("versioning of a bucket in state: %+v %v", e, ok)
	}
	orphan := resourceNode(t, tb, "aws_s3_bucket", "acme-orphan")
	if e, ok := containedIn(tb, resourceNode(t, tb, "aws_s3_bucket_versioning", "acme-orphan"), orphan); !ok || e.Basis != BasisCatalogueChild {
		t.Errorf("versioning of an unmanaged bucket: %+v %v", e, ok)
	}
	// Only the bucket whose versioning is listed is a parent.
	if _, ok := containedIn(tb, resourceNode(t, tb, "aws_s3_bucket_versioning", "acme-orphan"), bucket); ok {
		t.Error("a child of another bucket")
	}

	vnet := resourceNode(t, tb, "azurerm_virtual_network", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg/providers/microsoft.network/virtualnetworks/hub-vnet")
	rg := resourceNode(t, tb, "azurerm_resource_group", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg")
	subnet := resourceNode(t, tb, "azurerm_subnet", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg/providers/microsoft.network/virtualnetworks/hub-vnet/subnets/snet-a")
	storage := resourceNode(t, tb, "azurerm_storage_account", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg/providers/microsoft.storage/storageaccounts/acmehubdiag")
	if e, ok := containedIn(tb, subnet, vnet); !ok || e.Basis != BasisResourcePath || e.Confidence != snapshot.Computed {
		t.Errorf("subnet in its network: %+v %v", e, ok)
	}
	if _, ok := containedIn(tb, subnet, rg); ok {
		t.Error("a subnet is in its network, not in the resource group around it")
	}
	if e, ok := containedIn(tb, storage, rg); !ok || e.Basis != BasisResourcePath {
		t.Errorf("storage account in its resource group: %+v %v", e, ok)
	}
	// The state-only snapshot has neither kind of edge.
	for _, e := range build(t, fixtureReads(t)).Tables.Edges {
		if e.Basis == BasisCatalogueChild || e.Basis == BasisResourcePath {
			t.Errorf("an edge from state only: %+v", e)
		}
	}
}

func TestInventoryTagsPassTheSecretDetectors(t *testing.T) {
	res := buildBoth(t, fixtureReads(t), inventoryReads(t))
	n := resourceNode(t, res.Tables, "aws_instance", "i-0f00")
	if len(n.Tags) != 2 || n.Tags["env"] != "dev" || n.Tags["Owner"] != "data-team" {
		t.Errorf("tags: %v", n.Tags)
	}
	if !slices.Equal(res.Redaction.TagKeysDropped, []string{"db_password"}) || res.Redaction.AllTagsDropped {
		t.Errorf("redaction: %+v", res.Redaction)
	}
	raw, _ := json.Marshal(res.Tables)
	if strings.Contains(string(raw), "PLANTED-TAG-VALUE-1") || strings.Contains(res.Limits, "PLANTED") {
		t.Error("a secret tag value is in the rows")
	}
	if !strings.Contains(res.Limits, "1 tags look like secrets") {
		t.Errorf("limits: %s", res.Limits)
	}

	// --drop-tag and --drop-tags.
	o := opts
	o.DropTags = []string{"Owner"}
	res2, err := BuildAll(fixtureReads(t), inventoryReads(t), o)
	if err != nil {
		t.Fatal(err)
	}
	if n := resourceNode(t, res2.Tables, "aws_instance", "i-0f00"); len(n.Tags) != 1 || n.Tags["env"] != "dev" {
		t.Errorf("tags with Owner dropped: %v", n.Tags)
	}
	if !slices.Equal(res2.Redaction.TagKeysDropped, []string{"Owner", "db_password"}) {
		t.Errorf("redaction: %+v", res2.Redaction)
	}
	o = opts
	o.DropAllTags = true
	res3, err := BuildAll(fixtureReads(t), inventoryReads(t), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range res3.Tables.Nodes {
		if len(n.Tags) > 0 {
			t.Errorf("%s keeps tags: %v", n.NativeID, n.Tags)
		}
	}
	if !res3.Redaction.AllTagsDropped {
		t.Errorf("redaction: %+v", res3.Redaction)
	}
}

func TestInventoryAlone(t *testing.T) {
	res := buildBoth(t, nil, inventoryReads(t))
	if !strings.HasPrefix(res.Limits, "Read from infraharvest inventories only: no Terraform state was read") {
		t.Errorf("limits: %s", res.Limits)
	}
	for _, n := range res.Tables.Nodes {
		if n.Kind != snapshot.KindResource {
			t.Errorf("node: %+v", n)
		}
	}
	// What the inventory says of who manages a thing stands, where there is
	// no state to say otherwise.
	if n := resourceNode(t, res.Tables, "aws_vpc", "vpc-0a1b"); n.ManagedStatus != snapshot.Managed || n.Address != "" {
		t.Errorf("vpc: %+v", n)
	}
	if n := resourceNode(t, res.Tables, "aws_subnet", "subnet-0c21"); n.ManagedStatus != snapshot.Unmanaged {
		t.Errorf("subnet: %+v", n)
	}
	// An import's address and root are kept from the OCSF inventory.
	if n := resourceNode(t, res.Tables, "aws_s3_bucket", "acme-logs-audit"); n.Address != `aws_s3_bucket.logs["audit"]` || n.Root != "s3://acme-tfstate/prod/net.tfstate" {
		t.Errorf("bucket: %+v", n)
	}
	if n := resourceNode(t, res.Tables, "azurerm_resource_group", "/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg"); n.Root != "infrastructure/hub" || n.Address != "azurerm_resource_group.hub" {
		t.Errorf("resource group: %+v", n)
	}
	if err := snapshot.Validate(&res.Tables); err != nil {
		t.Error(err)
	}
}

func TestInventorySources(t *testing.T) {
	res := buildBoth(t, fixtureReads(t), inventoryReads(t))
	var got []string
	for _, s := range res.Tables.Sources {
		if s.Kind != snapshot.SourceInventory {
			continue
		}
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%s|%s", s.Location, s.Backend, s.Collector, s.CollectorVersion, s.CollectedAt, s.Status))
		if len(s.DocumentSHA256) != 64 {
			t.Errorf("%s: digest %q", s.Location, s.DocumentSHA256)
		}
	}
	sort.Strings(got)
	want := []string{
		"testdata/inventory/aws.inventory.json|file|infraharvest|0.9.0|2026-11-25T09:30:00Z|ok",
		"testdata/inventory/azure.ocsf-inventory.json|file|infraharvest|0.9.0|2026-11-25T10:00:00Z|ok",
		"testdata/inventory/gcp.inventory.json|file|infraharvest|0.9.0|2026-11-25T09:30:00Z|ok",
	}
	if !slices.Equal(got, want) {
		t.Errorf("sources:\n%s", strings.Join(got, "\n"))
	}
}

func TestBadInventoryIsAFailedSource(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := filepath.Join("testdata", "inventory", "gcp.inventory.json")
	bad := []struct{ name, content, reason string }{
		{"graph.json", `{"schema":"infraharvest/graph/v1","nodes":[]}`, "is not infraharvest/inventory/v1 or infraharvest/ocsf-inventory/v1"},
		{"none.json", `{"nodes":[]}`, "no schema member"},
		{"text.json", `not json`, "not JSON of the expected shape"},
		{"two.json", `{"schema":"x"} {}`, "data after the JSON document"},
		{"status.json", `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","cloud":"aws","resources":[{"type":"aws_vpc","id":"v","account":"1","status":"mine"}]}`, `status "mine"`},
		{"cloud.json", `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","cloud":"ibm","resources":[]}`, `cloud "ibm"`},
		{"noid.json", `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","cloud":"aws","resources":[{"type":"aws_vpc","account":"1","status":"managed"}]}`, "a type and an id are required"},
		{"time.json", `{"schema":"infraharvest/inventory/v1","generated_at":"yesterday","cloud":"aws","resources":[]}`, "generated_at"},
	}
	paths := []string{good}
	for _, b := range bad {
		paths = append(paths, write(b.name, b.content))
	}
	paths = append(paths, filepath.Join(dir, "missing.json"))
	res, err := BuildAll(nil, ReadInventories(paths), opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != len(bad)+1 {
		t.Errorf("%d failed, want %d", res.Failed, len(bad)+1)
	}
	failed := map[string]snapshot.Source{}
	for _, s := range res.Tables.Sources {
		if s.Status == snapshot.StatusFailed {
			failed[filepath.Base(s.Location)] = s
		}
	}
	for _, b := range bad {
		if s, ok := failed[b.name]; !ok || !strings.Contains(s.Reason, b.reason) {
			t.Errorf("%s: %+v", b.name, s)
		}
	}
	if len(failed) != len(bad)+1 || len(res.Tables.Nodes) != 2 {
		t.Errorf("%d failed sources, %d nodes", len(failed), len(res.Tables.Nodes))
	}

	// Nothing read at all is an error, and not an empty snapshot.
	if _, err := BuildAll(nil, ReadInventories(paths[2:3]), opts); err == nil || !strings.Contains(err.Error(), "no state or inventory could be read") {
		t.Errorf("error: %v", err)
	}
}

func TestInventoryThatCountsFailedImportsIsPartial(t *testing.T) {
	doc := `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws",
	  "resources":[{"type":"aws_vpc","id":"vpc-1","account":"111111111111","status":"unmanaged","status_basis":"none"}],
	  "coverage":{"totals":{"failed":3}}}`
	p := filepath.Join(t.TempDir(), "i.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	res := buildBoth(t, nil, ReadInventories([]string{p}))
	if res.Failed != 1 || res.Tables.Sources[0].Status != snapshot.StatusPartial || !strings.Contains(res.Tables.Sources[0].Reason, "3 resources whose import failed") {
		t.Errorf("failed %d, source %+v", res.Failed, res.Tables.Sources[0])
	}
}

func TestHashedInventoryCannotBeMatchedToState(t *testing.T) {
	doc := `{"schema":"infraharvest/inventory/v1","generated_at":"2026-11-25T09:30:00Z","tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws",
	  "resources":[{"type":"aws_vpc","id":"` + strings.Repeat("ab", 32) + `","account":"111111111111","status":"unmanaged","status_basis":"none"},
	   {"type":"aws_vpc","id":"` + strings.Repeat("cd", 32) + `","account":"111111111111","status":"managed","status_basis":"state"}],
	  "redaction":{"tag_keys_dropped":[],"ids_hashed":true,"hash_alg":"hmac-sha256"}}`
	p := filepath.Join(t.TempDir(), "i.json")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	res := buildBoth(t, fixtureReads(t), ReadInventories([]string{p}))
	byID := map[string]snapshot.Node{}
	for _, n := range res.Tables.Nodes {
		byID[n.NativeID] = n
	}
	if n := byID[strings.Repeat("ab", 32)]; n.ManagedStatus != snapshot.Unknown {
		t.Errorf("a hashed ID the states cannot be searched for: %+v", n)
	}
	if n := byID[strings.Repeat("cd", 32)]; n.ManagedStatus != snapshot.Managed {
		t.Errorf("what the inventory says is managed stays so: %+v", n)
	}
	if !strings.Contains(res.Limits, "1 inventories hash their IDs") || !strings.Contains(res.Limits, "1 resources are managed according to an inventory but are in none of the states read") {
		t.Errorf("limits: %s", res.Limits)
	}
}

func TestInventoryOrderDoesNotMatter(t *testing.T) {
	invs := inventoryReads(t)
	want := writeFilesWith(t, buildBoth(t, fixtureReads(t), invs))
	for i := range 4 {
		shuffled := slices.Clone(invs)
		for j := range shuffled {
			k := (j*5 + i*2 + 1) % len(shuffled)
			shuffled[j], shuffled[k] = shuffled[k], shuffled[j]
		}
		states := fixtureReads(t)
		slices.Reverse(states)
		got := writeFilesWith(t, buildBoth(t, states, shuffled))
		for name, data := range want {
			if !bytes.Equal(got[name], data) {
				t.Fatalf("order %d: %s differs", i, name)
			}
		}
	}
}

func writeFilesWith(t *testing.T, res Result) map[string][]byte {
	t.Helper()
	s, err := snapshot.Build(res.Tables, snapshot.BuildOptions{
		CreatedAt: opts.CollectedAt, Label: "fixture", Limits: res.Limits, Redaction: res.Redaction,
		Tool: snapshot.Tool{Name: "infra-ontology", Version: "test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Files
}

// renderInventory is render with what an inventory adds to a node.
func renderInventory(tb snapshot.Tables) string {
	sources := map[string]string{}
	for _, s := range tb.Sources {
		sources[s.SourceID] = s.Kind + ":" + filepath.Base(s.Location)
	}
	var extra []string
	for _, n := range tb.Nodes {
		if n.Kind != snapshot.KindResource {
			continue
		}
		var tags []string
		for k, v := range n.Tags {
			tags = append(tags, k+"="+v)
		}
		sort.Strings(tags)
		extra = append(extra, fmt.Sprintf("detail %s %s %s | inventory_type=%s address=%s root=%s tags=%s source=%s",
			n.Cloud, first(n.TFType, n.InventoryType), n.NativeID, n.InventoryType, n.Address, n.Root, strings.Join(tags, ","), sources[n.SourceID]))
	}
	for _, e := range tb.Edges {
		if e.Basis == BasisCatalogueChild || e.Basis == BasisResourcePath {
			extra = append(extra, fmt.Sprintf("edge-source %s %s %s -> %s | %s", e.Kind, e.Basis, e.FromID[:8], e.ToID[:8], sources[e.SourceID]))
		}
	}
	sort.Strings(extra)
	return render(tb) + strings.Join(extra, "\n") + "\n"
}

// TestInventoryGolden pins the rows of the fixture states joined to the fixture
// inventories in a form a person can review, and the bytes of the snapshot
// through the hashes in its manifest.
func TestInventoryGolden(t *testing.T) {
	res := buildBoth(t, fixtureReads(t), inventoryReads(t))
	got := map[string][]byte{
		"inventory-manifest.json": writeFilesWith(t, res)["manifest.json"],
		"inventory-graph.txt":     []byte(renderInventory(res.Tables)),
	}
	dir := filepath.Join("testdata", "golden")
	for name, data := range got {
		path := filepath.Join(dir, name)
		if *update {
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
	var m snapshot.Manifest
	if err := json.Unmarshal(got["inventory-manifest.json"], &m); err != nil || m.Status != snapshot.StatusOK ||
		m.SourcesSummary.ByKind[snapshot.SourceInventory] != 3 || !slices.Equal(m.Redaction.TagKeysDropped, []string{"db_password"}) {
		t.Errorf("manifest: %v %+v", err, m)
	}
}

// TestPlantedSecretsInAnInventoryAreNotKept feeds inventories that hold
// secrets as IDs, names, addresses, tags and members the reader does not name,
// and checks that none is in the rows, the limits or the sources.
func TestPlantedSecretsInAnInventoryAreNotKept(t *testing.T) {
	// Credential formats are written out here, so that no file in the
	// repository holds one.
	token := "gh" + "p_" + strings.Repeat("a1", 18)
	pw := "https://deploy:PLANTED-URL-PASSWORD@example.com/x"
	q := "https://example.com/hook?token=PLANTED-QUERY-TOKEN"
	v1 := `{"schema":"infraharvest/inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","generated_at":"2026-11-25T09:30:00Z",
	 "tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws","scopes":["aws/111111111111/eu-west-1"],
	 "attributes":{"password":"PLANTED-ATTRIBUTE-1"},
	 "resources":[
	  {"type":"aws_ssm_parameter","id":"` + token + `","account":"111111111111","status":"unmanaged","status_basis":"none"},
	  {"type":"aws_secretsmanager_secret","id":"` + pw + `","account":"111111111111","status":"unmanaged","status_basis":"none"},
	  {"type":"aws_apigatewayv2_api","id":"` + q + `","account":"111111111111","status":"unmanaged","status_basis":"none"},
	  {"type":"aws_instance","id":"i-0aa1","account":"111111111111","status":"unmanaged","status_basis":"none","name":"` + token + `",
	   "attributes":{"user_data":"PLANTED-ATTRIBUTE-2"},"values":{"secret":"PLANTED-ATTRIBUTE-3"},
	   "tags":{"Name":"web","api_key":"PLANTED-TAG-KEY-VALUE","deploy":"` + token + `","build":"` + pw + `","session":"A9f3Qz7LmN2xW8vB5kRt1YpD6sHc4EuJ","env":"prod"}},
	  {"type":"aws_instance","id":"i-0aa2","account":"111111111111","status":"managed","status_basis":"state","name":"web 2","tags":{"` + token + `":"x","secret_key":"PLANTED-TAG-KEY-2"}}],
	 "redaction":{"tag_keys_dropped":["` + token + `"],"ids_hashed":false,"hash_alg":"hmac-sha256"},"coverage":{"totals":{"failed":0}}}`
	ocsf := `{"schema":"infraharvest/ocsf-inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","ocsf_version":"1.9.0",
	 "redaction":{"tag_keys_dropped":[],"ids_hashed":false,"hash_alg":"hmac-sha256","addresses_dropped":false},
	 "events":[{"time":1795600800000,"metadata":{"product":{"name":"infraharvest","version":"0.9.0"}},
	  "cloud":{"provider":"AWS","account":{"uid":"111111111111"},"region":"eu-west-1"},
	  "unmapped":{"password":"PLANTED-OCSF-EXTRA"},
	  "resources":[{"type":"aws_instance","uid":"i-0bb1","name":"` + pw + `","labels":["status:unmanaged","status_basis:none"],
	   "tags":[{"name":"token","value":"PLANTED-OCSF-TAG"},{"name":"env","value":"prod"}],
	   "iac":{"address":"aws_instance.` + token + `","module_address":"module.` + token + `","path":"` + q + `","state_key":"` + pw + `"}}]}]}`
	dir := t.TempDir()
	var paths []string
	for name, content := range map[string]string{"v1.json": v1, "ocsf.json": ocsf} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	res := buildBoth(t, fixtureReads(t), ReadInventories(paths))
	files := writeFilesWith(t, res)
	var all strings.Builder
	for name, b := range files {
		all.WriteString(name + string(b))
	}
	raw, _ := json.Marshal(res)
	all.Write(raw)
	for _, secret := range []string{token, "PLANTED-URL-PASSWORD", "PLANTED-QUERY-TOKEN", "PLANTED-ATTRIBUTE", "PLANTED-TAG", "PLANTED-OCSF", "A9f3Qz7LmN2xW8vB5kRt1YpD6sHc4EuJ", "deploy:"} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("the snapshot holds %q", secret)
		}
	}

	byID := map[string]snapshot.Node{}
	for _, n := range res.Tables.Nodes {
		byID[n.NativeID] = n
	}
	// The three resources whose ID is a credential are left out.
	for _, typ := range []string{"aws_ssm_parameter", "aws_secretsmanager_secret", "aws_apigatewayv2_api"} {
		for _, n := range res.Tables.Nodes {
			if n.TFType == typ {
				t.Errorf("%s is in the snapshot: %+v", typ, n)
			}
		}
	}
	if !strings.Contains(res.Limits, "3 inventory resources have an ID that looks like a credential and are left out") {
		t.Errorf("limits: %s", res.Limits)
	}
	// What is not a secret stays: the resource, its name and its tags.
	i1 := byID["i-0aa1"]
	if i1.Name != "" || len(i1.Tags) != 2 || i1.Tags["Name"] != "web" || i1.Tags["env"] != "prod" {
		t.Errorf("i-0aa1: %+v", i1)
	}
	if n := byID["i-0aa2"]; n.Name != "web 2" || len(n.Tags) != 0 {
		t.Errorf("i-0aa2: %+v", n)
	}
	// The address, module and root that are credentials are dropped; the node stays.
	if n := byID["i-0bb1"]; n.Address != "" || n.Module != "" || n.Root != "" || n.Name != "" || n.Tags["env"] != "prod" || len(n.Tags) != 1 {
		t.Errorf("i-0bb1: %+v", n)
	}
	// A key that is a credential is not listed, whoever dropped it.
	for _, k := range res.Redaction.TagKeysDropped {
		if strings.Contains(k, "gh"+"p_") {
			t.Errorf("a credential listed as a dropped key: %q", k)
		}
	}
	if !slices.Contains(res.Redaction.TagKeysDropped, "api_key") {
		t.Errorf("dropped keys: %v", res.Redaction.TagKeysDropped)
	}
	if err := snapshot.Validate(&res.Tables); err != nil {
		t.Error(err)
	}
}
