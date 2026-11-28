// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
)

// query exits as verify, diff and serve-mcp do when the snapshot does not
// verify, so a script can tell a bad snapshot from a bad query (exit 1).
func TestQueryExitsWithTheVerifyCodeOnABadSnapshot(t *testing.T) {
	_, dir := build(t)
	f, err := os.OpenFile(filepath.Join(dir, "nodes.parquet"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{0})
	_ = f.Close()
	code, out, errs := exec(t, "query", dir, "--sql", "SELECT 1")
	if code != exitVerifyFailed || out != "" || !strings.Contains(errs, "does not verify") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if code, _, _ := exec(t, "serve-mcp", dir); code != exitVerifyFailed {
		t.Errorf("serve-mcp exit %d", code)
	}
}

// query takes the signature flags of verify and serve-mcp, with the same
// meaning: a key or an identity to trust requires a signature that verifies.
func TestQueryChecksTheSignatureItIsGiven(t *testing.T) {
	keys := signingtest.NewKeys(t, "p256")
	other := signingtest.NewKeys(t, "p256")
	_, unsigned := build(t)
	_, signed := build(t)
	if code, _, errs := exec(t, "snapshot", "sign", "--key", keys.Private, signed); code != 0 {
		t.Fatalf("sign: %d %s", code, errs)
	}
	_, garbage := build(t)
	if err := os.WriteFile(filepath.Join(garbage, "manifest.sig.json"), []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := func(dir string, flags ...string) (int, string, string) {
		return exec(t, append([]string{"query", dir, "--sql", "SELECT count(*) AS n FROM nodes"}, flags...)...)
	}
	cases := []struct {
		name  string
		dir   string
		flags []string
		want  int
	}{
		{"unsigned, nothing to trust", unsigned, nil, 0},
		{"signed, nothing to trust", signed, nil, 0},
		{"signed, the right key", signed, []string{"--key", keys.Public}, 0},
		{"signed, the right key, required", signed, []string{"--key", keys.Public, "--require-signature"}, 0},
		{"signed, another key", signed, []string{"--key", other.Public}, exitVerifyFailed},
		{"unsigned, a key", unsigned, []string{"--key", keys.Public}, exitVerifyFailed},
		{"unsigned, a key, required", unsigned, []string{"--key", keys.Public, "--require-signature"}, exitVerifyFailed},
		{"unsigned, an identity", unsigned, []string{"--certificate-identity", "me@example.com", "--certificate-oidc-issuer", "https://issuer.example.com"}, exitVerifyFailed},
		{"a file that is no bundle", garbage, nil, exitVerifyFailed},
		{"required with nothing to check with", signed, []string{"--require-signature"}, exitUsage},
		{"a half identity", signed, []string{"--certificate-identity", "me@example.com"}, exitUsage},
	}
	for _, c := range cases {
		code, out, errs := q(c.dir, c.flags...)
		if code == 1 && strings.Contains(errs, "query engine not built in") {
			code = 0 // the build without the engine got past the checks
		}
		if code != c.want {
			t.Errorf("%s: exit %d, want %d\n%s%s", c.name, code, c.want, out, errs)
		}
		if c.want == exitVerifyFailed && out != "" {
			t.Errorf("%s: an answer was printed for a snapshot that failed the check:\n%s", c.name, out)
		}
	}
}
