// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"errors"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"
)

func TestResolve(t *testing.T) {
	for in, want := range map[string]string{
		"terraform.tfstate":                           "terraform.tfstate",
		"s3://b/p?region=eu-west-1":                   "s3://b/p?region=eu-west-1",
		"gs://b/p":                                    "gs://b/p",
		"azblob://acme/tfstate/prod":                  "https://acme.blob.core.windows.net/tfstate/prod",
		"azblob://acme.blob.core.usgovcloudapi.net/c": "https://acme.blob.core.usgovcloudapi.net/c",
		"hcp://acme/net":                              "tfc://acme/net",
		"hcp://acme/net-*?host=tfe.example.com":       "tfc://acme/net-*?host=tfe.example.com",
		"https://acme.blob.core.windows.net/c":        "https://acme.blob.core.windows.net/c",
	} {
		got, err := Resolve(in)
		if err != nil || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := Resolve("azblob://"); err == nil {
		t.Error("azblob:// without an account resolved")
	}
	// What Resolve returns is what pkg/tfstate reads.
	for _, in := range []string{"azblob://acme/tfstate/prod", "hcp://acme/net", "s3://b/p", "gs://b/p"} {
		r, _ := Resolve(in)
		if err := tfstate.CheckLocations([]string{r}); err != nil {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestBackendAndWorkspace(t *testing.T) {
	for _, c := range []struct{ loc, backend, ws string }{
		{"state/terraform.tfstate", "local", ""},
		{"s3://b/prod/net.tfstate", "s3", "default"},
		{"s3://b/env:/staging/prod/net.tfstate", "s3", "staging"},
		{"gs://b/p/default.tfstate", "gcs", "default"},
		{"gs://b/p/staging.tfstate", "gcs", ""},
		{"https://a.blob.core.windows.net/c/net.tfstate", "azblob", "default"},
		{"https://a.blob.core.windows.net/c/net.tfstateenv:dev", "azblob", "dev"},
		{"tfc://acme/net", "hcp", "net"},
		{"tfc://tfe.example.com/acme/net", "hcp", "net"},
	} {
		if got := BackendOf(c.loc); got != c.backend {
			t.Errorf("BackendOf(%q) = %q, want %q", c.loc, got, c.backend)
		}
		if got := WorkspaceOf(c.loc); got != c.ws {
			t.Errorf("WorkspaceOf(%q) = %q, want %q", c.loc, got, c.ws)
		}
	}
}

func TestSanitise(t *testing.T) {
	pat := "gh" + "p_" + strings.Repeat("a1B2c3", 6)
	for in, want := range map[string]string{
		"terraform.tfstate":                                           "terraform.tfstate",
		"s3://bucket/prod/net.tfstate":                                "s3://bucket/prod/net.tfstate",
		"s3://bucket/net.tfstate?region=eu-west-1&profile=ops":        "s3://bucket/net.tfstate?profile=ops&region=eu-west-1",
		"s3://bucket/net.tfstate?token=PLANTED-TOKEN&sig=PLANTED-SIG": "s3://bucket/net.tfstate",
		"https://user:PLANTED-PASSWORD@acme.blob.core.windows.net/c/k.tfstate?sv=2024&sig=PLANTED-SIG&sp=r": "https://acme.blob.core.windows.net/c/k.tfstate",
		"tfc://tfe.example.com/acme/net":         "tfc://tfe.example.com/acme/net",
		"s3://bucket/" + pat + "/net.tfstate":    "s3://bucket/[redacted]/net.tfstate",
		pat:                                      "[redacted]",
		"s3://bucket/net.tfstate?profile=" + pat: "s3://bucket/net.tfstate?profile=[redacted]",
	} {
		if got := Sanitise(in); got != want {
			t.Errorf("Sanitise(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestScrub(t *testing.T) {
	pat := "gh" + "p_" + strings.Repeat("a1B2c3", 6)
	got := Scrub(`get "https://user:PLANTED-PASSWORD@host/x?sig=PLANTED-SIG": 403 with ` + pat)
	for _, bad := range []string{"PLANTED", pat} {
		if strings.Contains(got, bad) {
			t.Errorf("Scrub kept %q: %s", bad, got)
		}
	}
	if !strings.Contains(got, "403") {
		t.Errorf("Scrub lost the message: %s", got)
	}
}

func TestMatching(t *testing.T) {
	for _, c := range []struct {
		name    string
		source  string
		rs      tfstate.RemoteState
		wantHit bool
	}{
		{"s3", "s3://b/prod/net.tfstate", tfstate.RemoteState{Backend: "s3", Bucket: "b", Key: "prod/net.tfstate"}, true},
		{"s3 other key", "s3://b/prod/net.tfstate", tfstate.RemoteState{Backend: "s3", Bucket: "b", Key: "prod/x.tfstate"}, false},
		{"s3 workspace", "s3://b/env:/dev/prod/net.tfstate", tfstate.RemoteState{Backend: "s3", Bucket: "b", Key: "prod/net.tfstate", Workspace: "dev"}, true},
		{"s3 default workspace is the key", "s3://b/prod/net.tfstate", tfstate.RemoteState{Backend: "s3", Bucket: "b", Key: "prod/net.tfstate", Workspace: "default"}, true},
		{"gcs", "gs://b/dns/default.tfstate", tfstate.RemoteState{Backend: "gcs", Bucket: "b", Key: "dns"}, true},
		{"gcs workspace", "gs://b/dns/dev.tfstate", tfstate.RemoteState{Backend: "gcs", Bucket: "b", Key: "dns", Workspace: "dev"}, true},
		{"gcs no prefix", "gs://b/default.tfstate", tfstate.RemoteState{Backend: "gcs", Bucket: "b"}, true},
		{"azurerm", "https://Acme.blob.core.windows.net/c/hub.tfstate", tfstate.RemoteState{Backend: "azurerm", Account: "acme", Bucket: "c", Key: "hub.tfstate"}, true},
		{"azurerm workspace", "https://acme.blob.core.windows.net/c/hub.tfstateenv:dev", tfstate.RemoteState{Backend: "azurerm", Account: "acme", Bucket: "c", Key: "hub.tfstate", Workspace: "dev"}, true},
		{"remote", "tfc://acme/net", tfstate.RemoteState{Backend: "remote", Organization: "acme", Workspace: "net"}, true},
		{"remote on another host", "tfc://tfe.example.com/acme/net", tfstate.RemoteState{Backend: "remote", Host: "tfe.example.com", Organization: "acme", Workspace: "net"}, true},
		{"remote on another host, not the default", "tfc://tfe.example.com/acme/net", tfstate.RemoteState{Backend: "remote", Organization: "acme", Workspace: "net"}, false},
		{"local", "/work/net/terraform.tfstate", tfstate.RemoteState{Backend: "local", Key: "net/terraform.tfstate"}, true},
		{"local outside", "/work/net/terraform.tfstate", tfstate.RemoteState{Backend: "local", Key: "../net/terraform.tfstate"}, false},
		{"local partial name", "/work/xnet/terraform.tfstate", tfstate.RemoteState{Backend: "local", Key: "net/terraform.tfstate"}, false},
		{"unknown backend", "s3://b/k.tfstate", tfstate.RemoteState{Backend: "kubernetes"}, false},
	} {
		hit := false
		for _, want := range consumerKeys(c.rs) {
			hit = hit || matches(producerKey(c.source), want)
		}
		if hit != c.wantHit {
			t.Errorf("%s: matched = %v, want %v", c.name, hit, c.wantHit)
		}
	}
}

func TestAddresses(t *testing.T) {
	for in, want := range map[string]string{
		"aws_vpc.main":                         "aws_vpc.main",
		"aws_subnet.a[0]":                      "aws_subnet.a",
		`module.a["x.y"].aws_vpc.main["k[1]"]`: "module.a.aws_vpc.main",
		`module.a["q\"]"].module.b[2]`:         "module.a.module.b",
		"data.aws_vpc.main":                    "data.aws_vpc.main",
	} {
		if got := keyless(in); got != want {
			t.Errorf("keyless(%q) = %q, want %q", in, got, want)
		}
	}
	calls := moduleCalls(`module.a["x.y"].module.b[2]`)
	if len(calls) != 2 || calls[0] != `module.a["x.y"]` || calls[1] != `module.a["x.y"].module.b[2]` {
		t.Errorf("moduleCalls = %q", calls)
	}
	if moduleCalls("") != nil || callName(calls[1]) != "b[2]" || callName(calls[0]) != `a["x.y"]` || parentCall(calls[1]) != calls[0] || parentCall(calls[0]) != "" {
		t.Error("callName or parentCall")
	}
}

func TestCheckLocations(t *testing.T) {
	if err := Check("testdata/states/net.tfstate"); err != nil {
		t.Error(err)
	}
	if err := Check("testdata/states/missing.tfstate"); err == nil {
		t.Error("a missing file passed")
	}
	err := Check("s3://bucket/prefix")
	linkedS3 := false
	for _, l := range Linked() {
		linkedS3 = linkedS3 || l == BackendS3
	}
	var nl *NotLinkedError
	switch isNL := errors.As(err, &nl); {
	case linkedS3 && err != nil:
		t.Errorf("s3 is built in, yet: %v", err)
	case !linkedS3 && (!isNL || nl.Tag != "s3" || !strings.Contains(err.Error(), "-tags s3")):
		t.Errorf("s3 is not built in, yet: %v", err)
	}
}
