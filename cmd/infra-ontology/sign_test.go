// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
)

type verifyJSON struct {
	OK        bool     `json:"ok"`
	Problems  []string `json:"problems"`
	Signature struct {
		Status  string `json:"status"`
		Mode    string `json:"mode"`
		Signer  string `json:"signer"`
		Problem string `json:"problem"`
	} `json:"signature"`
}

func verifyJSONOf(t *testing.T, args ...string) (int, verifyJSON) {
	t.Helper()
	code, out, errs := exec(t, append([]string{"snapshot", "verify", "--json"}, args...)...)
	var v verifyJSON
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("exit %d, not JSON: %v\n%s%s", code, err, out, errs)
	}
	return code, v
}

func TestSignThenVerifyWithAKey(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewKeys(t, "p256")

	// Unsigned is reported, and passes.
	code, out, _ := exec(t, "snapshot", "verify", dir)
	if code != 0 || !strings.Contains(out, "signature unsigned") {
		t.Errorf("unsigned: exit %d\n%s", code, out)
	}

	code, out, errs := exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	if code != 0 || !strings.Contains(out, "signed "+dir) || !strings.Contains(out, "manifest.sig.json") {
		t.Fatalf("sign: exit %d\n%s%s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.sig.json")); err != nil {
		t.Fatal(err)
	}

	// Signed, and nothing to check it with: reported, and passes.
	code, out, _ = exec(t, "snapshot", "verify", dir)
	if code != 0 || !strings.Contains(out, "signature signed (unverified)") || !strings.Contains(out, "not checked") {
		t.Errorf("signed, unchecked: exit %d\n%s", code, out)
	}

	// With the public key, offline.
	code, out, _ = exec(t, "snapshot", "verify", "--key", keys.Public, dir)
	if code != 0 || !strings.Contains(out, "signature verified (key: sha256:") {
		t.Errorf("verify --key: exit %d\n%s", code, out)
	}
	code, v := verifyJSONOf(t, "--key", keys.Public, "--require-signature", dir)
	if code != 0 || !v.OK || v.Signature.Status != "verified" || v.Signature.Mode != "key" || v.Signature.Signer == "" {
		t.Errorf("--json: exit %d %+v", code, v)
	}
	// The top-level verify takes the same flags.
	if code, out, errs = exec(t, "verify", "--key", keys.Public, dir); code != 0 || !strings.Contains(out, "verified") {
		t.Errorf("verify: exit %d\n%s%s", code, out, errs)
	}

	// Another key: a failure, with the reason.
	other := signingtest.NewKeys(t, "p256")
	code, out, _ = exec(t, "snapshot", "verify", "--key", other.Public, dir)
	if code != exitVerifyFailed || !strings.Contains(out, "FAILED") || !strings.Contains(out, "manifest.sig.json: the signature does not verify") {
		t.Errorf("another key: exit %d\n%s", code, out)
	}
	if code, v = verifyJSONOf(t, "--key", other.Public, dir); code != exitVerifyFailed || v.OK || v.Signature.Status != "invalid" {
		t.Errorf("another key, --json: exit %d %+v", code, v)
	}
}

func TestATamperedSnapshotFailsVerifyWhateverItsSignature(t *testing.T) {
	keys := signingtest.NewKeys(t, "p256")

	_, dir := build(t)
	exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	f, err := os.OpenFile(filepath.Join(dir, "nodes.parquet"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{0})
	_ = f.Close()
	if code, out, _ := exec(t, "snapshot", "verify", "--key", keys.Public, dir); code != exitVerifyFailed || !strings.Contains(out, "nodes.parquet: sha256") {
		t.Errorf("a changed table: exit %d\n%s", code, out)
	}

	// A new line at the end of the manifest leaves its id and tables as they
	// were, so the hashes pass; the signature, over the file's bytes, fails.
	_, dir = build(t)
	exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	p := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := exec(t, "snapshot", "verify", dir); code != 0 {
		t.Fatalf("a manifest with a new line does not pass the hashes: exit %d\n%s", code, out)
	}
	if code, out, _ := exec(t, "snapshot", "verify", "--key", keys.Public, dir); code != exitVerifyFailed || !strings.Contains(out, "does not verify") {
		t.Errorf("a changed manifest: exit %d\n%s", code, out)
	}
}

func TestRequireSignature(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewKeys(t, "p256")

	// A signature is required, and there is none.
	code, out, _ := exec(t, "snapshot", "verify", "--key", keys.Public, "--require-signature", dir)
	if code != exitVerifyFailed || !strings.Contains(out, "--require-signature") {
		t.Errorf("required, absent: exit %d\n%s", code, out)
	}
	// Required, with nothing to check it with: a usage error, not a pass.
	code, _, errs := exec(t, "snapshot", "verify", "--require-signature", dir)
	if code != exitUsage || !strings.Contains(errs, "--require-signature needs --key") {
		t.Errorf("required, no key: exit %d\n%s", code, errs)
	}
	// Required, signed, and not checked by a verifier that matches: a failure.
	exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	if code, _, _ := exec(t, "snapshot", "verify", "--key", signingtest.NewKeys(t, "p256").Public, "--require-signature", dir); code != exitVerifyFailed {
		t.Errorf("required, wrong key: exit %d", code)
	}
	if code, _, _ := exec(t, "snapshot", "verify", "--key", keys.Public, "--require-signature", dir); code != 0 {
		t.Errorf("required, right key: exit %d", code)
	}
}

func TestAKeylessCheckOfAKeySignatureFails(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewKeys(t, "p256")
	exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	root := filepath.Join(t.TempDir(), "trusted_root.json")
	if err := os.WriteFile(root, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec(t, "snapshot", "verify", "--certificate-identity", "me@example.com", "--certificate-oidc-issuer", "https://issuer.example.com", "--trusted-root", root, dir)
	if code != exitVerifyFailed || !strings.Contains(out, "FAILED") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestAnInvalidSignatureFileFailsVerifyWithNoKey(t *testing.T) {
	_, dir := build(t)
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig.json"), []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := exec(t, "snapshot", "verify", dir)
	if code != exitVerifyFailed || !strings.Contains(out, "manifest.sig.json: manifest.sig.json is not a Sigstore bundle") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestSignUsage(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewKeys(t, "p256")
	for name, args := range map[string][]string{
		"no way to sign":      {"snapshot", "sign", dir},
		"both ways":           {"snapshot", "sign", "--key", keys.Private, "--keyless", dir},
		"no folder":           {"snapshot", "sign", "--key", keys.Private},
		"verify, half a pair": {"snapshot", "verify", "--certificate-identity", "a@b.c", dir},
		"verify, key and id":  {"snapshot", "verify", "--key", keys.Public, "--certificate-identity", "a@b.c", "--certificate-oidc-issuer", "i", dir},
		"serve, half a pair":  {"serve-mcp", "--certificate-oidc-issuer", "i", dir},
		"an answer and a key": {"verify", "--answer", "a.json", "--key", keys.Public},
	} {
		if code, _, errs := exec(t, args...); code != exitUsage {
			t.Errorf("%s: exit %d, %s", name, code, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "manifest.sig.json")); err == nil {
		t.Error("a usage error wrote a signature")
	}
}

func TestSignRefusesToReplaceAndForceDoes(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewKeys(t, "p256")
	if code, _, errs := exec(t, "snapshot", "sign", "--key", keys.Private, dir); code != 0 {
		t.Fatal(errs)
	}
	code, _, errs := exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	if code != exitFailed || !strings.Contains(errs, "--force") {
		t.Errorf("a second signature: exit %d %s", code, errs)
	}
	if code, _, errs = exec(t, "snapshot", "sign", "--force", "--key", keys.Private, dir); code != 0 {
		t.Errorf("--force: exit %d %s", code, errs)
	}
}

func TestSignWithACosignKeyTakesThePasswordFromTheEnvironment(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewEncryptedKeys(t, "s3cret")

	t.Setenv("COSIGN_PASSWORD", "")
	os.Unsetenv("COSIGN_PASSWORD")
	if code, _, errs := exec(t, "snapshot", "sign", "--key", keys.Private, dir); code != exitFailed || !strings.Contains(errs, "COSIGN_PASSWORD") {
		t.Errorf("no password: exit %d %s", code, errs)
	}
	t.Setenv("COSIGN_PASSWORD", "s3cret")
	if code, _, errs := exec(t, "snapshot", "sign", "--key", keys.Private, dir); code != 0 {
		t.Fatalf("exit %d %s", code, errs)
	}
	if code, out, _ := exec(t, "snapshot", "verify", "--key", keys.Public, dir); code != 0 || !strings.Contains(out, "verified") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestSignRefusesASnapshotThatDoesNotVerify(t *testing.T) {
	_, dir := build(t)
	if err := os.Remove(filepath.Join(dir, "edges.parquet")); err != nil {
		t.Fatal(err)
	}
	code, _, errs := exec(t, "snapshot", "sign", "--key", signingtest.NewKeys(t, "p256").Private, dir)
	if code != exitFailed || !strings.Contains(errs, "does not verify") {
		t.Errorf("exit %d %s", code, errs)
	}
}

func TestTheSnapshotIDIgnoresTheSignature(t *testing.T) {
	_, dir := build(t)
	type result struct {
		SnapshotID string `json:"snapshot_id"`
		Tables     []struct {
			File string `json:"file"`
		} `json:"tables"`
	}
	read := func() result {
		_, out, _ := exec(t, "snapshot", "verify", "--json", dir)
		var r result
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := read()
	exec(t, "snapshot", "sign", "--key", signingtest.NewKeys(t, "p256").Private, dir)
	after := read()
	if len(before.SnapshotID) != 64 || after.SnapshotID != before.SnapshotID || len(after.Tables) != 3 {
		t.Errorf("before %+v, after %+v", before, after)
	}
	for _, tb := range after.Tables {
		if strings.Contains(tb.File, "sig") {
			t.Errorf("the signature is in the table list: %+v", after.Tables)
		}
	}
	// Editing the file cannot change the id either.
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if edited := read(); edited.SnapshotID != before.SnapshotID {
		t.Errorf("an edited signature changed the id: %s", edited.SnapshotID)
	}
}

func TestServeMCPRefusesASignatureThatDoesNotCheck(t *testing.T) {
	_, dir := build(t)
	keys := signingtest.NewKeys(t, "p256")
	exec(t, "snapshot", "sign", "--key", keys.Private, dir)
	code, _, errs := exec(t, "serve-mcp", "--key", signingtest.NewKeys(t, "p256").Public, dir)
	if code != exitVerifyFailed || !strings.Contains(errs, "manifest.sig.json") {
		t.Errorf("another key: exit %d\n%s", code, errs)
	}
	_, unsigned := build(t)
	code, _, errs = exec(t, "serve-mcp", "--key", keys.Public, "--require-signature", unsigned)
	if code != exitVerifyFailed || !strings.Contains(errs, "one is required") {
		t.Errorf("unsigned, required: exit %d\n%s", code, errs)
	}
}
