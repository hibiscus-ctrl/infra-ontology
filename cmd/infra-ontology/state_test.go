// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/ingest"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// statesDir is where the fixture states are, as an absolute path: the tests
// change directory.
var statesDir, _ = filepath.Abs("../../internal/ingest/testdata/states")

// buildState runs `snapshot build --state` in the folder of the fixture
// states, so that their locations are short relative paths.
func buildState(t *testing.T, args ...string) (code int, dir, stdout, stderr string) {
	t.Helper()
	t.Chdir(statesDir)
	out := t.TempDir()
	code, stdout, stderr = exec(t, append([]string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z"}, args...)...)
	if entries, _ := os.ReadDir(out); len(entries) == 1 {
		dir = filepath.Join(out, entries[0].Name())
	}
	return code, dir, stdout, stderr
}

func TestBuildFromState(t *testing.T) {
	code, dir, out, errs := buildState(t, "--label", "prod", "--state", "net.tfstate", "--state", "app.tfstate", "--state", "platform.tfstate")
	if code != 0 || errs != "" || dir == "" || !strings.Contains(out, "snapshot ") {
		t.Fatalf("exit %d: %s%s", code, out, errs)
	}
	if res := snapshot.Verify(dir); !res.OK() {
		t.Fatalf("does not verify: %s", res.Error())
	}
	l, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l.Manifest.Label != "prod" || l.Manifest.Status != snapshot.StatusOK || l.Manifest.SourcesSummary.ByKind["state"] != 3 {
		t.Errorf("manifest: %+v", l.Manifest)
	}
	sources := map[string]snapshot.Source{}
	for _, s := range l.Tables.Sources {
		sources[s.Location] = s
	}
	if s := sources["net.tfstate"]; s.Backend != "local" || s.Serial == nil || *s.Serial != 17 || s.CollectedAt != "2026-11-25T12:00:00Z" {
		t.Errorf("net source: %+v", s)
	}
	// A local state is found by the path a terraform_remote_state names, and
	// the s3 ones, here, are not in the snapshot.
	if !strings.Contains(l.Manifest.Limits, "s3://acme-other/shared.tfstate") {
		t.Errorf("limits: %s", l.Manifest.Limits)
	}
	// The same build twice is the same snapshot.
	_, dir2, _, _ := buildState(t, "--label", "prod", "--state", "net.tfstate", "--state", "app.tfstate", "--state", "platform.tfstate")
	if filepath.Base(dir) != filepath.Base(dir2) {
		t.Errorf("two builds: %s and %s", filepath.Base(dir), filepath.Base(dir2))
	}
}

func TestStateDirectoryAndRemoteStateByPath(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("net/terraform.tfstate", `{"version":4,"serial":1,"lineage":"a","terraform_version":"1.9.0","resources":[
	  {"mode":"managed","type":"aws_vpc","name":"main","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]","instances":[{"attributes":{"id":"vpc-1"}}]}]}`)
	write("app/terraform.tfstate", `{"version":4,"serial":2,"lineage":"b","terraform_version":"1.9.0","resources":[
	  {"mode":"data","type":"terraform_remote_state","name":"net","provider":"provider[\"terraform.io/builtin/terraform\"]","instances":[
	    {"attributes":{"backend":"local","config":{"value":{"path":"../net/terraform.tfstate"},"type":["object",{"path":"string"}]},"workspace":null}}]}]}`)
	// The path is relative to the state's own folder, so it is the one of the
	// producer's file that a consumer in another folder would name.
	write("app2/terraform.tfstate", strings.Replace(mustRead(t, filepath.Join(root, "app/terraform.tfstate")), "../net/", "net/", 1))
	t.Chdir(root)
	out := t.TempDir()
	code, _, errs := exec(t, "snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", ".")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	entries, _ := os.ReadDir(out)
	l, err := snapshot.Load(filepath.Join(out, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Tables.Sources) != 3 {
		t.Fatalf("%d sources", len(l.Tables.Sources))
	}
	reads := 0
	for _, e := range l.Tables.Edges {
		if e.Kind == snapshot.EdgeReadsStateOf {
			reads++
		}
	}
	// app2 names net/terraform.tfstate, which ends the path of the net state.
	// app names ../net/terraform.tfstate, which leaves its own folder and so
	// cannot be placed: it reads an external placeholder.
	if reads != 2 {
		t.Errorf("%d reads_state_of edges, want 2", reads)
	}
	if !strings.Contains(l.Manifest.Limits, "../net/terraform.tfstate") {
		t.Errorf("the limits do not name the path the app state reads: %s", l.Manifest.Limits)
	}
	for _, n := range l.Tables.Nodes {
		if n.Kind == snapshot.KindExternal && !strings.Contains(l.Manifest.Limits, n.Name) {
			t.Errorf("external %s is not in the limits", n.Name)
		}
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPartialWhenOneStateDoesNotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.tfstate"), []byte(`{"version": 4, "resources": [`), 0o644); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(statesDir, "platform.tfstate")
	out := t.TempDir()
	code, stdout, errs := exec(t, "snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", good, "--state", filepath.Join(dir, "bad.tfstate"))
	if code != 3 || !strings.Contains(errs, "1 of 2 states could not be read") {
		t.Fatalf("exit %d: %s%s", code, stdout, errs)
	}
	snap := strings.SplitN(stdout, "\n", 2)[0]
	if res := snapshot.Verify(snap); !res.OK() {
		t.Fatalf("does not verify: %s", res.Error())
	}
	l, _ := snapshot.Load(snap)
	if l.Manifest.Status != snapshot.StatusPartial || len(l.Manifest.Coverage.FailedSources) != 1 ||
		l.Manifest.Coverage.FailedSources[0].Status != snapshot.StatusFailed || l.Manifest.Coverage.FailedSources[0].Reason == "" {
		t.Errorf("manifest: %+v", l.Manifest.Coverage)
	}

	// Nothing read: no snapshot, exit 1.
	out2 := t.TempDir()
	code, stdout, errs = exec(t, "snapshot", "build", "--out", out2, "--state", filepath.Join(dir, "bad.tfstate"))
	if code != 1 || stdout != "" || !strings.Contains(errs, "no state could be read") {
		t.Errorf("exit %d: %s%s", code, stdout, errs)
	}
	if entries, _ := os.ReadDir(out2); len(entries) != 0 {
		t.Errorf("a snapshot was written: %v", entries)
	}
}

func TestStateUsageErrors(t *testing.T) {
	linked := map[string]bool{}
	for _, l := range ingest.Linked() {
		linked[l] = true
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"nothing", nil, "--state LOCATION is required"},
		{"both", []string{"--state", "x", "--from-json", "y"}, "not both"},
		{"missing file", []string{"--state", "no/such/file.tfstate"}, "no/such/file.tfstate"},
		{"azblob without account", []string{"--state", "azblob://"}, "name an account"},
	}
	for _, store := range []struct{ scheme, backend, tag string }{
		{"s3://bucket/prefix", "s3", "s3"}, {"gs://bucket/prefix", "gcs", "gcs"},
		{"azblob://acme/c/p", "azblob", "azblob"}, {"hcp://acme/ws", "hcp", "hcp"},
	} {
		if !linked[store.backend] {
			cases = append(cases, struct {
				name string
				args []string
				want string
			}{store.backend + " not built in", []string{"--state", store.scheme}, "-tags " + store.tag})
		}
	}
	for _, c := range cases {
		out := t.TempDir()
		code, stdout, errs := exec(t, append([]string{"snapshot", "build", "--out", out}, c.args...)...)
		if code != 2 || stdout != "" || !strings.Contains(errs, c.want) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want 2 and %q", c.name, code, stdout, errs, c.want)
		}
		if entries, _ := os.ReadDir(out); len(entries) != 0 {
			t.Errorf("%s: wrote %v", c.name, entries)
		}
	}
}

var planted = regexp.MustCompile(`PLANTED-[A-Z0-9-]+`)

// TestPlantedSecretsNeverReachAnOutputFile builds a snapshot from states that
// hold secrets in attributes, in outputs and in the configuration of a
// terraform_remote_state, and fails if any of them is in any file the command
// writes, or on its stdout and stderr.
func TestPlantedSecretsNeverReachAnOutputFile(t *testing.T) {
	// Credential formats are written out here, so that no file in the
	// repository holds one.
	token := "gh" + "p_" + strings.Repeat("a1", 18)
	generated := t.TempDir()
	runtimeState := `{"version":4,"serial":3,"lineage":"c","terraform_version":"1.9.0",
	  "outputs":{"token":{"value":"` + token + `","type":"string","sensitive":true}},
	  "resources":[
	   {"mode":"managed","type":"github_actions_secret","name":"s","provider":"provider[\"registry.terraform.io/integrations/github\"]",
	    "instances":[{"attributes":{"id":"` + token + `","plaintext_value":"` + token + `","arn":"` + token + `"}}]},
	   {"mode":"data","type":"terraform_remote_state","name":"x","provider":"provider[\"terraform.io/builtin/terraform\"]",
	    "instances":[{"attributes":{"backend":"s3","config":{"value":{"bucket":"b","key":"k.tfstate","access_key":"` + token + `","secret_key":"` + token + `"},"type":["object",{}]},
	      "outputs":{"value":{"p":"` + token + `"},"type":["object",{}]}}}]}]}`
	if err := os.WriteFile(filepath.Join(generated, "runtime.tfstate"), []byte(runtimeState), 0o644); err != nil {
		t.Fatal(err)
	}

	// Every PLANTED- value in the fixtures must be there to be tested.
	want := map[string]bool{}
	_ = filepath.WalkDir(statesDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			for _, m := range planted.FindAllString(string(b), -1) {
				want[m] = true
			}
		}
		return nil
	})
	if len(want) < 12 {
		t.Fatalf("only %d planted secrets in the fixtures", len(want))
	}
	want[token] = true

	abs := statesDir
	out := t.TempDir()
	args := []string{"snapshot", "build", "--out", out, "--created-at", "2026-11-25T12:00:00Z", "--state", filepath.Join(generated, "runtime.tfstate")}
	for _, f := range []string{"net", "app", "platform", "dns", "hub"} {
		args = append(args, "--state", filepath.Join(abs, f+".tfstate"))
	}
	code, stdout, stderr := exec(t, args...)
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
		for secret := range want {
			if strings.Contains(content, secret) {
				t.Errorf("%s holds the planted secret %q", name, secret)
			}
		}
	}

	// And the snapshot is not empty of what it should hold.
	dir := strings.SplitN(stdout, "\n", 2)[0]
	l, err := snapshot.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(l.Tables)
	if len(l.Tables.Nodes) < 30 || len(l.Tables.Edges) < 40 {
		t.Errorf("%d nodes and %d edges: the snapshot is nearly empty: %s", len(l.Tables.Nodes), len(l.Tables.Edges), raw)
	}
}
