// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Keys of the tests: no real secret, and not shorter than the 16 bytes
// --hash-ids asks for.
var (
	testKey  = []byte("test-key-0123456789-abcdef-AAAA")
	otherKey = []byte("test-key-0123456789-abcdef-BBBB")
)

func hashedOpts(key []byte) Options {
	o := opts
	o.HashKey = key
	return o
}

func buildHashed(t *testing.T, key []byte, states []Read, invs []InventoryRead) Result {
	t.Helper()
	res, err := BuildAll(states, invs, hashedOpts(key))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// hashInventoryFile writes what infraharvest export --hash-ids writes for the
// inventory fixture in file: the same document with its IDs, names, addresses
// and paths hashed under key, and the tags that give them away. With fold, the IDs of
// Azure resources are hashed in lower case, as the states' are compared; without,
// as infraharvest wrote them.
func hashInventoryFile(t *testing.T, file string, key []byte, fold bool) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "inventory", file))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	hash := func(m map[string]any, ks ...string) {
		for _, k := range ks {
			if s := str(m, k); s != "" {
				m[k] = secretscan.Hash(key, s)
			}
		}
	}
	filter := secretscan.NewTagFilter(nil, false, key)
	switch doc["schema"] {
	case SchemaInventory:
		for _, r := range doc["resources"].([]any) {
			res := r.(map[string]any)
			if tags, ok := res["tags"].(map[string]any); ok {
				plain := map[string]string{}
				for k, v := range tags {
					plain[k], _ = v.(string)
				}
				res["tags"] = filter.Tags(plain, str(res, "id"), str(res, "name"))
			}
			hash(res, "id", "name")
		}
	case SchemaOCSFInventory:
		for _, e := range doc["events"].([]any) {
			for _, r := range e.(map[string]any)["resources"].([]any) {
				res := r.(map[string]any)
				id := first(str(res, "uid_alt"), str(res, "uid"))
				if tags, ok := res["tags"].([]any); ok {
					plain := map[string]string{}
					for _, tg := range tags {
						m := tg.(map[string]any)
						plain[str(m, "name")] = str(m, "value")
					}
					var kept []map[string]string
					for k, v := range filter.Tags(plain, id, str(res, "name")) {
						kept = append(kept, map[string]string{"name": k, "value": v})
					}
					res["tags"] = kept
				}
				if fold {
					for _, k := range []string{"uid", "uid_alt"} {
						if s := str(res, k); isAzureID(s) {
							res[k] = strings.ToLower(s)
						}
					}
				}
				hash(res, "uid", "uid_alt", "name")
				if iac, ok := res["iac"].(map[string]any); ok {
					hash(iac, "address", "module_address", "path", "state_key")
				}
			}
		}
	default:
		t.Fatalf("%s: schema %v", file, doc["schema"])
	}
	red := doc["redaction"].(map[string]any)
	red["ids_hashed"] = true
	red["tag_keys_dropped"] = filter.DroppedKeys()
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "hashed."+file)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func hashedInventoryReads(t *testing.T, key []byte, fold bool) []InventoryRead {
	t.Helper()
	var paths []string
	for _, f := range inventoryFixtures {
		paths = append(paths, hashInventoryFile(t, f, key, fold))
	}
	reads := ReadInventories(paths)
	for _, r := range reads {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Location, r.Err)
		}
		if !r.Inv.IDsHashed {
			t.Fatalf("%s: not hashed", r.Location)
		}
	}
	return reads
}

func writeHashed(t *testing.T, res Result) map[string][]byte {
	t.Helper()
	return writeFilesWith(t, res)
}

// nodeKey is what names a node whatever its identifier: its fields, hashed as
// a hashed build hashes them.
func nodeKey(key []byte, n snapshot.Node) string {
	h := func(s string) string { return secretscan.Hash(key, s) }
	return strings.Join([]string{
		n.Kind, n.Cloud, n.Account, n.Region, n.TFType, n.InventoryType, h(n.NativeID), h(n.ARNOrPath), h(n.Name),
		h(n.Address), h(n.Module), h(n.Root), n.ManagedStatus, n.Confidence,
	}, "|")
}

func TestHashedStateIsThePlainStateHashed(t *testing.T) {
	plain := build(t, fixtureReads(t))
	hashed := buildHashed(t, testKey, fixtureReads(t), nil)

	if r := hashed.Redaction; r.HashAlgorithm != "hmac-sha256" || !r.IDsHashed {
		t.Errorf("redaction: %+v", r)
	}
	if r := plain.Redaction; r.IDsHashed || r.HashAlgorithm == "hmac-sha256" {
		t.Errorf("plain redaction: %+v", r)
	}
	if len(plain.Tables.Nodes) != len(hashed.Tables.Nodes) || len(plain.Tables.Edges) != len(hashed.Tables.Edges) ||
		len(plain.Tables.Sources) != len(hashed.Tables.Sources) {
		t.Fatalf("rows: %d/%d/%d plain, %d/%d/%d hashed",
			len(plain.Tables.Nodes), len(plain.Tables.Edges), len(plain.Tables.Sources),
			len(hashed.Tables.Nodes), len(hashed.Tables.Edges), len(hashed.Tables.Sources))
	}

	// Every node of the plain build is one of the hashed build, with its text
	// hashed and nothing else changed, and every edge joins the same nodes.
	hashedByKey := map[string]string{}
	for _, n := range hashed.Tables.Nodes {
		hashedByKey[nodeKey(nil, n)] = n.NodeID
	}
	idOf := map[string]string{}
	for _, n := range plain.Tables.Nodes {
		id, ok := hashedByKey[nodeKey(testKey, n)]
		if !ok {
			t.Errorf("no hashed node for %s %s", n.Kind, first(n.Address, n.NativeID, n.Name))
		}
		idOf[n.NodeID] = id
	}
	edges := map[string]bool{}
	for _, e := range hashed.Tables.Edges {
		edges[e.FromID+"|"+e.ToID+"|"+e.Kind+"|"+e.Basis+"|"+e.Confidence] = true
	}
	for _, e := range plain.Tables.Edges {
		if !edges[idOf[e.FromID]+"|"+idOf[e.ToID]+"|"+e.Kind+"|"+e.Basis+"|"+e.Confidence] {
			t.Errorf("no hashed edge for %s %s", e.Kind, e.Basis)
		}
	}

	// Ids are hex, derived from the key, and not the plain ones.
	plainIDs := map[string]bool{}
	for _, n := range plain.Tables.Nodes {
		plainIDs[n.NodeID] = true
	}
	for _, n := range hashed.Tables.Nodes {
		if plainIDs[n.NodeID] {
			t.Errorf("node %s has the id it has without a key", n.NodeID)
		}
	}
	for _, s := range hashed.Tables.Sources {
		if len(s.Location) != 64 {
			t.Errorf("location %q is not a hash", s.Location)
		}
	}
	if !strings.Contains(hashed.Limits, "HMAC-SHA256 hashes under a key this snapshot does not hold") {
		t.Errorf("limits: %s", hashed.Limits)
	}
	// What terraform_remote_state reads that is not in the snapshot is not
	// named: its location is a hash.
	if strings.Contains(hashed.Limits, "acme-other") {
		t.Errorf("limits name a location: %s", hashed.Limits)
	}
}

func TestHashedIDsMatchInfraharvestsHash(t *testing.T) {
	// The hash of an ID is the hash infraharvest export --hash-ids writes,
	// which is what lets the two tools join.
	hashed := buildHashed(t, testKey, fixtureReads(t), nil)
	want := secretscan.Hash(testKey, "vpc-0a1b")
	for _, n := range hashed.Tables.Nodes {
		if n.NativeID == want && n.TFType == "aws_vpc" {
			return
		}
	}
	t.Errorf("no aws_vpc node has the HMAC-SHA256 of its ID %s", want)
}

func TestHashedNodeIDsAreStableForTheSameKey(t *testing.T) {
	want := writeHashed(t, buildHashed(t, testKey, fixtureReads(t), inventoryReads(t)))
	for i := range 3 {
		states := fixtureReads(t)
		invs := inventoryReads(t)
		if i%2 == 1 {
			slices.Reverse(states)
			slices.Reverse(invs)
		}
		got := writeHashed(t, buildHashed(t, slices.Clone(testKey), states, invs))
		for name, data := range want {
			if !bytes.Equal(got[name], data) {
				t.Fatalf("run %d: %s differs", i, name)
			}
		}
	}
	other := writeHashed(t, buildHashed(t, otherKey, fixtureReads(t), inventoryReads(t)))
	if bytes.Equal(other["nodes.parquet"], want["nodes.parquet"]) {
		t.Error("another key gives the same nodes")
	}
	a, b := nodeIDs(buildHashed(t, testKey, fixtureReads(t), nil)), nodeIDs(buildHashed(t, otherKey, fixtureReads(t), nil))
	for id := range a {
		if b[id] {
			t.Errorf("node id %s is the same under two keys", id)
		}
	}
}

func nodeIDs(res Result) map[string]bool {
	ids := map[string]bool{}
	for _, n := range res.Tables.Nodes {
		ids[n.NodeID] = true
	}
	return ids
}

func TestHashedStateAndPlainInventoryJoin(t *testing.T) {
	plain := buildBoth(t, fixtureReads(t), inventoryReads(t))
	hashed := buildHashed(t, testKey, fixtureReads(t), inventoryReads(t))
	if got, want := statusCounts(hashed.Tables), statusCounts(plain.Tables); got != want {
		t.Errorf("statuses %s, want %s", got, want)
	}
	if got, want := joinedCount(hashed.Tables), joinedCount(plain.Tables); got != want || got == 0 {
		t.Errorf("%d joined nodes, want %d", got, want)
	}
	// A tag that holds a name is hashed with it, as infraharvest does.
	for _, n := range hashed.Tables.Nodes {
		if n.TFType == "aws_vpc" && n.Tags["Name"] == "main" {
			t.Errorf("a Name tag gives away what the name hashes: %+v", n.Tags)
		}
	}
}

func statusCounts(tb snapshot.Tables) string {
	counts := map[string]int{}
	for _, n := range tb.Nodes {
		counts[n.ManagedStatus]++
	}
	return fmt.Sprint(counts)
}

// joinedCount counts the nodes a state made that an inventory added to.
func joinedCount(tb snapshot.Tables) int {
	states := map[string]bool{}
	for _, s := range tb.Sources {
		if s.Kind == snapshot.SourceState {
			states[s.SourceID] = true
		}
	}
	n := 0
	for _, node := range tb.Nodes {
		if states[node.SourceID] && node.Kind == snapshot.KindResource && node.InventoryType != "" {
			n++
		}
	}
	return n
}

func TestHashedStateAndHashedInventoryJoin(t *testing.T) {
	plainInv := buildHashed(t, testKey, fixtureReads(t), inventoryReads(t))
	res := buildHashed(t, testKey, fixtureReads(t), hashedInventoryReads(t, testKey, true))

	// The same things join as when the inventory is read as it is, and
	// what is only in the inventory keeps the status it gives it: the IDs are
	// comparable, so being absent from the states says something.
	if got, want := joinedCount(res.Tables), joinedCount(plainInv.Tables); got != want || got == 0 {
		t.Errorf("%d joined nodes, want %d", got, want)
	}
	for _, s := range []string{snapshot.Managed, snapshot.Unmanaged, snapshot.OtherIaC} {
		if got, want := countStatus(res.Tables, s), countStatus(plainInv.Tables, s); got != want {
			t.Errorf("%d %s nodes, want %d", got, s, want)
		}
	}
	if n := countStatus(res.Tables, snapshot.Unknown); n != countStatus(plainInv.Tables, snapshot.Unknown) {
		t.Errorf("%d unknown nodes: hashed IDs of the same key are not matched", n)
	}
	// The state's nodes are the same as without the inventory, joined to it.
	stateOnly := nodeIDs(buildHashed(t, testKey, fixtureReads(t), nil))
	for id := range stateOnly {
		if !nodeIDs(res)[id] {
			t.Errorf("state node %s is not in the joined snapshot", id)
		}
	}
	if strings.Contains(res.Limits, "cannot be matched to state") || strings.Contains(res.Limits, "another key") {
		t.Errorf("limits: %s", res.Limits)
	}
	// A joined node is the state's, with what the inventory adds.
	for _, n := range res.Tables.Nodes {
		if n.TFType == "aws_vpc" && n.NativeID == secretscan.Hash(testKey, "vpc-0a1b") {
			if n.ManagedStatus != snapshot.Managed || n.InventoryType != "aws_vpc" || n.Address == "" || n.Address == "aws_vpc.main" {
				t.Errorf("joined vpc: %+v", n)
			}
			return
		}
	}
	t.Error("no aws_vpc node")
}

func countStatus(tb snapshot.Tables, status string) int {
	n := 0
	for _, node := range tb.Nodes {
		if node.ManagedStatus == status {
			n++
		}
	}
	return n
}

func TestHashedInventoryOfAnotherKeyDoesNotJoin(t *testing.T) {
	res := buildHashed(t, testKey, fixtureReads(t), hashedInventoryReads(t, otherKey, true))
	// Nothing joins: no node has both a state's address and an inventory
	// type.
	if n := joinedCount(res.Tables); n != 0 {
		t.Errorf("%d nodes joined across two keys", n)
	}
	// What the inventories call unmanaged is not said to be: with another
	// key, it says nothing.
	if n := countStatus(res.Tables, snapshot.Unmanaged); n != 0 {
		t.Errorf("%d unmanaged nodes", n)
	}
	if n := countStatus(res.Tables, snapshot.Unknown); n == 0 {
		t.Error("no unknown node")
	}
	if !strings.Contains(res.Limits, "hashed with another key") {
		t.Errorf("limits: %s", res.Limits)
	}
}

func TestOneSideHashedKeepsTheNote(t *testing.T) {
	// States as they are and an inventory that hashed its IDs: the note stays,
	// and there is no join, whatever the key.
	res := buildBoth(t, fixtureReads(t), hashedInventoryReads(t, testKey, true))
	if n := joinedCount(res.Tables); n != 0 {
		t.Errorf("%d nodes joined", n)
	}
	if !strings.Contains(res.Limits, "3 inventories hash their IDs, so their resources cannot be matched to state") {
		t.Errorf("limits: %s", res.Limits)
	}
	if res.Redaction.IDsHashed {
		t.Errorf("redaction: %+v", res.Redaction)
	}
}

// secrets is what must not be in any file of a hashed snapshot.
func plainMarkers(t *testing.T) []string {
	t.Helper()
	plain := buildBoth(t, fixtureReads(t), inventoryReads(t))
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if len(s) >= 8 && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	// What stays readable is not a marker: accounts, regions, types and tags.
	readable := map[string]bool{}
	for _, n := range plain.Tables.Nodes {
		for _, s := range []string{n.Account, n.Region, n.TFType, n.InventoryType} {
			readable[s] = true
		}
		for k, v := range n.Tags {
			readable[k], readable[v] = true, true
		}
	}
	for _, n := range plain.Tables.Nodes {
		for _, s := range []string{n.NativeID, n.ARNOrPath, n.Name, n.Address, n.Module, n.Root} {
			if !readable[s] {
				add(s)
			}
		}
	}
	for _, s := range plain.Tables.Sources {
		add(s.Location)
		if !readable[s.Workspace] {
			add(s.Workspace)
		}
	}
	sort.Strings(out)
	return out
}

func TestKeyAndPlainValuesAreNotInTheOutput(t *testing.T) {
	markers := plainMarkers(t)
	// The check means something only if the plain snapshot holds them.
	plainFiles := writeFilesWith(t, buildBoth(t, fixtureReads(t), inventoryReads(t)))
	found := 0
	for _, m := range markers {
		for _, data := range plainFiles {
			if bytes.Contains(data, []byte(m)) {
				found++
				break
			}
		}
	}
	if found < len(markers)/2 {
		t.Fatalf("only %d of %d plain values are in the plain files: the check proves nothing", found, len(markers))
	}

	failedRead := Read{Location: "s3://secret-bucket-name/private/path.tfstate", Err: fmt.Errorf("open s3://secret-bucket-name/private/path.tfstate: access denied")}
	for name, invs := range map[string][]InventoryRead{
		"plain inventories":  inventoryReads(t),
		"hashed inventories": hashedInventoryReads(t, testKey, true),
	} {
		res := buildHashed(t, testKey, append(fixtureReads(t), failedRead), invs)
		files := writeHashed(t, res)
		keyForms := [][]byte{testKey, []byte(hex.EncodeToString(testKey)), []byte(base64.StdEncoding.EncodeToString(testKey)),
			[]byte(base64.RawURLEncoding.EncodeToString(testKey))}
		for file, data := range files {
			for _, k := range keyForms {
				if bytes.Contains(data, k) {
					t.Errorf("%s: %s holds the key", name, file)
				}
			}
			for _, m := range append(markers, "secret-bucket-name", "private/path.tfstate", t.TempDir()) {
				if m != "" && bytes.Contains(data, []byte(m)) {
					t.Errorf("%s: %s holds %q", name, file, m)
				}
			}
		}
		var failed []snapshot.Source
		for _, s := range res.Tables.Sources {
			if s.Status == snapshot.StatusFailed {
				failed = append(failed, s)
			}
		}
		if len(failed) != 1 || failed[0].Reason != withheld || failed[0].Location != secretscan.Hash(testKey, "s3://secret-bucket-name/private/path.tfstate") {
			t.Errorf("%s: failed source %+v", name, failed)
		}
		// The rows are a snapshot that verifies.
		s, err := snapshot.Build(res.Tables, snapshot.BuildOptions{CreatedAt: opts.CollectedAt, Limits: res.Limits, Redaction: res.Redaction})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		dir, err := s.Write(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if v := snapshot.Verify(dir); !v.OK() {
			t.Errorf("%s: %v", name, v.Problems)
		}
	}
}

func TestHashedTagsAreFilteredOnceAndKeysAreListed(t *testing.T) {
	res := buildHashed(t, testKey, fixtureReads(t), hashedInventoryReads(t, testKey, true))
	// The Name tag of a hashed inventory was hashed by its export: it is not
	// hashed again, so it is what the export wrote.
	want := secretscan.Hash(testKey, "main")
	for _, n := range res.Tables.Nodes {
		if n.TFType == "aws_vpc" && n.NativeID == secretscan.Hash(testKey, "vpc-0a1b") && len(n.Tags) > 0 {
			if n.Tags["Name"] != want {
				t.Errorf("Name tag %q, want %q", n.Tags["Name"], want)
			}
		}
	}
	plain := buildBoth(t, fixtureReads(t), inventoryReads(t))
	if !slices.Equal(res.Redaction.TagKeysDropped, plain.Redaction.TagKeysDropped) {
		t.Errorf("dropped keys %v, want %v", res.Redaction.TagKeysDropped, plain.Redaction.TagKeysDropped)
	}
}

// TestHashedGolden pins the rows of the fixtures hashed under a test key in a
// form a person can review, and the bytes of the snapshot through the hashes in
// its manifest.
func TestHashedGolden(t *testing.T) {
	res := buildHashed(t, testKey, fixtureReads(t), inventoryReads(t))
	got := map[string][]byte{
		"hashed-manifest.json": writeHashed(t, res)["manifest.json"],
		"hashed-graph.txt":     []byte(renderInventory(res.Tables)),
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
	if err := json.Unmarshal(got["hashed-manifest.json"], &m); err != nil || m.Status != snapshot.StatusOK ||
		m.Redaction.HashAlgorithm != "hmac-sha256" || !m.Redaction.IDsHashed {
		t.Errorf("manifest: %v %+v", err, m.Redaction)
	}
	if bytes.Contains(got["hashed-manifest.json"], testKey) || bytes.Contains(got["hashed-graph.txt"], testKey) {
		t.Error("the key is in a golden file")
	}
}

// TestHashedAzureIDsJoinInTheCaseTheyAreWritten: an export hashes an Azure
// resource ID as it wrote it, and a hash cannot be folded to lower case, so an
// Azure resource joins when its ID is written in the case the state has it (or
// in lower case), and does not when the two differ. Nothing else is lost.
func TestHashedAzureIDsJoinInTheCaseTheyAreWritten(t *testing.T) {
	folded := buildHashed(t, testKey, fixtureReads(t), hashedInventoryReads(t, testKey, true))
	asWritten := buildHashed(t, testKey, fixtureReads(t), hashedInventoryReads(t, testKey, false))
	joined := func(res Result) map[string]snapshot.Node {
		m := map[string]snapshot.Node{}
		states := map[string]bool{}
		for _, s := range res.Tables.Sources {
			states[s.SourceID] = s.Kind == snapshot.SourceState
		}
		for _, n := range res.Tables.Nodes {
			if states[n.SourceID] && n.Kind == snapshot.KindResource && n.InventoryType != "" {
				m[n.NodeID] = n
			}
		}
		return m
	}
	all, some := joined(folded), joined(asWritten)
	lost := 0
	for id, n := range all {
		if _, ok := some[id]; !ok {
			lost++
			if n.Cloud != "azure" {
				t.Errorf("%s %s is not joined, and is not an Azure resource", n.TFType, n.Cloud)
			}
		}
	}
	if lost == 0 {
		t.Error("every resource joins whatever the case: the fixture does not test it")
	}
}
