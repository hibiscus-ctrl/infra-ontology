// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// inventoryDir is where the fixture inventories are, as an absolute path: the
// tests change directory.
var inventoryDir, _ = filepath.Abs("../../internal/ingest/testdata/inventory")

// buildWithInventory runs `snapshot build` in the folder of the fixture
// states, with the fixture inventories named by `--inventory`.
func buildWithInventory(t *testing.T, args ...string) (code int, dir, stdout, stderr string) {
	t.Helper()
	return buildState(t, args...)
}

func allInventories() []string {
	var args []string
	for _, f := range []string{"aws.inventory.json", "azure.ocsf-inventory.json", "gcp.inventory.json"} {
		args = append(args, "--inventory", filepath.Join(inventoryDir, f))
	}
	return args
}

func loadSnapshot(t *testing.T, dir string) *snapshot.Loaded {
	t.Helper()
	if res := snapshot.Verify(dir); !res.OK() {
		t.Fatalf("does not verify: %s", res.Error())
	}
	l, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func statusCounts(l *snapshot.Loaded) map[string]int {
	counts := map[string]int{}
	for _, n := range l.Tables.Nodes {
		if n.Kind == snapshot.KindResource {
			counts[n.ManagedStatus]++
		}
	}
	return counts
}

func TestBuildFromStateAndInventory(t *testing.T) {
	args := append([]string{"--label", "prod", "--state", "net.tfstate", "--state", "app.tfstate", "--state", "hub.tfstate", "--state", "dns.tfstate"}, allInventories()...)
	code, dir, out, errs := buildWithInventory(t, args...)
	if code != 0 || errs != "" || dir == "" || !strings.Contains(out, "snapshot ") {
		t.Fatalf("exit %d: %s%s", code, out, errs)
	}
	l := loadSnapshot(t, dir)
	if l.Manifest.Status != snapshot.StatusOK || l.Manifest.SourcesSummary.ByKind["state"] != 4 || l.Manifest.SourcesSummary.ByKind["inventory"] != 3 {
		t.Errorf("manifest: %+v", l.Manifest)
	}
	counts := statusCounts(l)
	if counts[snapshot.Managed] != 18 || counts[snapshot.Unmanaged] != 9 || counts[snapshot.OtherIaC] != 1 {
		t.Errorf("statuses: %v", counts)
	}
	if !strings.Contains(l.Manifest.Limits, "Read from Terraform state and infraharvest inventories") ||
		strings.Contains(l.Manifest.Limits, "no live inventory was read") {
		t.Errorf("limits: %s", l.Manifest.Limits)
	}
	if got := l.Manifest.Redaction.TagKeysDropped; len(got) != 1 || got[0] != "db_password" {
		t.Errorf("tag keys dropped: %v", got)
	}
	bases := map[string]int{}
	for _, e := range l.Tables.Edges {
		bases[e.Basis]++
	}
	if bases["catalogue_child"] != 2 || bases["resource_path"] != 3 {
		t.Errorf("edges by basis: %v", bases)
	}
	// The same build twice is the same snapshot.
	_, dir2, _, _ := buildWithInventory(t, args...)
	if filepath.Base(dir) != filepath.Base(dir2) {
		t.Errorf("two builds: %s and %s", filepath.Base(dir), filepath.Base(dir2))
	}
}

func TestBuildFromInventoryAlone(t *testing.T) {
	code, dir, out, errs := buildWithInventory(t, allInventories()...)
	if code != 0 || errs != "" || dir == "" {
		t.Fatalf("exit %d: %s%s", code, out, errs)
	}
	l := loadSnapshot(t, dir)
	if l.Manifest.SourcesSummary.ByKind["state"] != 0 || l.Manifest.SourcesSummary.ByKind["inventory"] != 3 {
		t.Errorf("sources: %+v", l.Manifest.SourcesSummary)
	}
	if !strings.HasPrefix(l.Manifest.Limits, "Read from infraharvest inventories only") {
		t.Errorf("limits: %s", l.Manifest.Limits)
	}
}

func TestDropTagsFlags(t *testing.T) {
	_, dir, _, _ := buildWithInventory(t, append([]string{"--drop-tag", "env,Owner", "--drop-tag", "team"}, allInventories()...)...)
	l := loadSnapshot(t, dir)
	for _, n := range l.Tables.Nodes {
		for k := range n.Tags {
			if k == "env" || k == "Owner" || k == "team" {
				t.Errorf("%s keeps tag %s", n.NativeID, k)
			}
		}
	}
	if got := strings.Join(l.Manifest.Redaction.TagKeysDropped, ","); got != "Owner,db_password,env,team" {
		t.Errorf("tag keys dropped: %s", got)
	}
	_, dir, _, _ = buildWithInventory(t, append([]string{"--drop-tags"}, allInventories()...)...)
	l = loadSnapshot(t, dir)
	for _, n := range l.Tables.Nodes {
		if len(n.Tags) > 0 {
			t.Errorf("%s keeps tags %v", n.NativeID, n.Tags)
		}
	}
	if !l.Manifest.Redaction.AllTagsDropped {
		t.Errorf("redaction: %+v", l.Manifest.Redaction)
	}
}

func TestInventoryFlagErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"infraharvest/graph/v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(inventoryDir, "gcp.inventory.json")
	out := t.TempDir()
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no source", nil, 2, "--state LOCATION or --inventory FILE is required"},
		{"with from-json", []string{"--from-json", "x.json", "--inventory", good}, 2, "not both"},
		{"missing file", []string{"--inventory", filepath.Join(out, "none.json")}, 2, "is not a file"},
		{"a folder", []string{"--inventory", inventoryDir}, 2, "is not a file"},
		{"not an inventory", []string{"--inventory", bad}, 1, "no state or inventory could be read"},
		{"one bad one good", []string{"--inventory", good, "--inventory", bad}, 3, "1 of 2 sources could not be read in full"},
	}
	for _, c := range cases {
		code, stdout, stderr := exec(t, append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z"}, c.args...)...)
		if code != c.code || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: exit %d, want %d: %s%s", c.name, code, c.code, stdout, stderr)
		}
	}
	// The partial one wrote a snapshot that says which source failed.
	entries, _ := os.ReadDir(out)
	if len(entries) != 1 {
		t.Fatalf("%d snapshots written", len(entries))
	}
	l := loadSnapshot(t, filepath.Join(out, entries[0].Name()))
	if l.Manifest.Status != snapshot.StatusPartial || len(l.Manifest.Coverage.FailedSources) != 1 ||
		!strings.Contains(l.Manifest.Coverage.FailedSources[0].Reason, "is not infraharvest/inventory/v1") {
		t.Errorf("manifest: %+v", l.Manifest)
	}
}

// TestPlantedSecretsInInventoryNeverReachAnOutputFile builds a snapshot from
// inventories that hold secrets in IDs, names, tags and members of their own,
// and fails if any is in a file the command writes, or on its output.
func TestPlantedSecretsInInventoryNeverReachAnOutputFile(t *testing.T) {
	token := "gh" + "p_" + strings.Repeat("a1", 18)
	url := "https://deploy:PLANTED-URL-PASSWORD@example.com/hook"
	dir := t.TempDir()
	v1 := `{"schema":"infraharvest/inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","generated_at":"2026-11-25T09:30:00Z",
	 "tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws","scopes":["aws/111111111111/eu-west-1"],
	 "attributes":{"master_password":"PLANTED-ATTRIBUTE-1"},
	 "resources":[
	  {"type":"aws_ssm_parameter","id":"` + token + `","account":"111111111111","status":"unmanaged","status_basis":"none"},
	  {"type":"aws_secretsmanager_secret","id":"` + url + `","account":"111111111111","status":"unmanaged","status_basis":"none"},
	  {"type":"aws_db_instance","id":"db-1","account":"111111111111","status":"unmanaged","status_basis":"none","name":"` + token + `",
	   "attributes":{"password":"PLANTED-ATTRIBUTE-2"},
	   "tags":{"env":"prod","db_password":"PLANTED-TAG-1","token":"` + token + `","webhook":"` + url + `"}}],
	 "redaction":{"tag_keys_dropped":[],"ids_hashed":false,"hash_alg":"hmac-sha256"}}`
	ocsf := `{"schema":"infraharvest/ocsf-inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","ocsf_version":"1.9.0",
	 "redaction":{"tag_keys_dropped":[],"ids_hashed":false,"hash_alg":"hmac-sha256","addresses_dropped":false},
	 "events":[{"time":1795600800000,"metadata":{"product":{"name":"infraharvest","version":"0.9.0"}},
	  "cloud":{"provider":"AWS","account":{"uid":"111111111111"},"region":"eu-west-1"},
	  "resources":[{"type":"aws_instance","uid":"i-0bb1","name":"` + url + `","labels":["status:managed","status_basis:state"],
	   "tags":[{"name":"api_key","value":"PLANTED-OCSF-TAG"},{"name":"env","value":"prod"}],
	   "iac":{"address":"aws_instance.` + token + `","module_address":"module.x","path":"` + url + `","state_key":"` + url + `"}}]}]}`
	var args []string
	for name, content := range map[string]string{"v1.json": v1, "ocsf.json": ocsf} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--inventory", p)
	}
	out := t.TempDir()
	code, stdout, stderr := exec(t, append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z"}, args...)...)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, stdout, stderr)
	}
	var files []string
	_ = filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if len(files) != 4 {
		t.Fatalf("%d files written: %v", len(files), files)
	}
	outputs := map[string]string{"stdout": stdout, "stderr": stderr}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		outputs[filepath.Base(f)] = string(b)
	}
	for name, content := range outputs {
		for _, secret := range []string{token, "PLANTED-URL-PASSWORD", "PLANTED-ATTRIBUTE", "PLANTED-TAG", "PLANTED-OCSF", "deploy:"} {
			if strings.Contains(content, secret) {
				t.Errorf("%s holds the planted secret %q", name, secret)
			}
		}
	}
	l := loadSnapshot(t, strings.SplitN(stdout, "\n", 2)[0])
	raw, _ := json.Marshal(l.Tables.Nodes)
	if len(l.Tables.Nodes) != 2 || !strings.Contains(string(raw), `"env":"prod"`) {
		t.Errorf("the snapshot is not what is left: %s", raw)
	}
}
