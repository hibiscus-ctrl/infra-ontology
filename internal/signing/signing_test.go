// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

func estate(t *testing.T) string {
	t.Helper()
	return signingtest.CopyEstate(t, signingtest.Estate)
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signed(t *testing.T) (dir string, keys signingtest.Keys) {
	t.Helper()
	dir, keys = estate(t), signingtest.NewKeys(t, "p256")
	if err := SignWithKey(dir, keys.Private, nil, false); err != nil {
		t.Fatal(err)
	}
	return dir, keys
}

func TestSignWithKeyThenVerify(t *testing.T) {
	for _, kind := range []string{"p256", "p384", "p521"} {
		t.Run(kind, func(t *testing.T) {
			dir := estate(t)
			keys := signingtest.NewKeys(t, kind)
			if st := Inspect(dir); st.State != Unsigned {
				t.Fatalf("before signing: %+v", st)
			}
			if err := SignWithKey(dir, keys.Private, nil, false); err != nil {
				t.Fatal(err)
			}
			if st := Inspect(dir); st.State != SignedUnverified || st.Mode != ModeKey {
				t.Errorf("after signing, unchecked: %+v", st)
			}
			st := Check(dir, Verifier{KeyFile: keys.Public})
			if st.State != Verified || st.Mode != ModeKey || !strings.HasPrefix(st.Signer, "sha256:") {
				t.Errorf("verify with the key: %+v", st)
			}
			if res := snapshot.Verify(dir); !res.OK() {
				t.Errorf("the snapshot no longer verifies once signed: %v", res.Problems)
			}
		})
	}
}

func TestTheBundleIsAKeyModeMessageSignature(t *testing.T) {
	// A message signature over manifest.json, with the key's hint and no
	// certificate: the shape `cosign verify-blob --bundle manifest.sig.json
	// --key cosign.pub manifest.json` reads.
	dir, _ := signed(t)
	b := read(t, filepath.Join(dir, File))
	for _, want := range []string{`"messageSignature"`, `"publicKey"`, `"messageDigest"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("the bundle lacks %s: %s", want, b)
		}
	}
	if bytes.Contains(b, []byte(`"certificate"`)) {
		t.Errorf("a key bundle holds a certificate: %s", b)
	}
}

func TestATamperedManifestFails(t *testing.T) {
	dir, keys := signed(t)
	p := filepath.Join(dir, snapshot.ManifestFile)
	if err := os.WriteFile(p, bytes.Replace(read(t, p), []byte("A fixture"), []byte("Not a fixture"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Invalid {
		t.Errorf("a changed manifest verified: %+v", st)
	}

	// A new line is a change too: the signature is over the file's bytes.
	dir, keys = signed(t)
	p = filepath.Join(dir, snapshot.ManifestFile)
	if err := os.WriteFile(p, append(read(t, p), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Invalid {
		t.Errorf("a manifest with a new line verified: %+v", st)
	}
}

func TestATamperedTableFailsThroughTheDigestChain(t *testing.T) {
	// The signature covers the manifest, and the manifest holds each table's
	// hash: a changed table fails snapshot.Verify, and the signature, which
	// is over the untouched manifest, still holds.
	dir, keys := signed(t)
	f, err := os.OpenFile(filepath.Join(dir, snapshot.NodesFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Verified {
		t.Errorf("the manifest is untouched, so its signature holds: %+v", st)
	}
	if res := snapshot.Verify(dir); res.OK() || !strings.Contains(res.Error(), "nodes.parquet: sha256") {
		t.Errorf("a changed table verified: %+v", res)
	}
}

func TestTheWrongKeyFails(t *testing.T) {
	dir, keys := signed(t)
	if st := Check(dir, Verifier{KeyFile: signingtest.NewKeys(t, "p256").Public}); st.State != Invalid {
		t.Errorf("another key verified: %+v", st)
	}
	if st := Check(dir, Verifier{KeyFile: signingtest.NewKeys(t, "p384").Public}); st.State != Invalid {
		t.Errorf("a P-384 key verified a P-256 signature: %+v", st)
	}
	if st := Check(dir, Verifier{KeyFile: filepath.Join(t.TempDir(), "nope.pub")}); st.State != Invalid {
		t.Errorf("a key file that is not there: %+v", st)
	}
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Verified {
		t.Errorf("the right key: %+v", st)
	}
}

func TestAKeylessCheckRefusesAKeySignature(t *testing.T) {
	dir, _ := signed(t)
	v := Verifier{Identity: "me@example.com", Issuer: "https://issuer.example.com", TrustedRoot: filepath.Join(t.TempDir(), "none.json")}
	if st := Check(dir, v); st.State != Invalid {
		t.Errorf("a key signature passed a keyless check: %+v", st)
	}
}

func TestUnsignedIsNotAFailure(t *testing.T) {
	st := Check(estate(t), Verifier{KeyFile: signingtest.NewKeys(t, "p256").Public})
	if st.State != Unsigned {
		t.Errorf("an unsigned snapshot: %+v", st)
	}
}

func TestTheSignatureIsNoPartOfTheSnapshot(t *testing.T) {
	dir := estate(t)
	before := snapshot.Verify(dir)
	keys := signingtest.NewKeys(t, "p256")
	if err := SignWithKey(dir, keys.Private, nil, false); err != nil {
		t.Fatal(err)
	}
	after := snapshot.Verify(dir)
	if !after.OK() || after.SnapshotID != before.SnapshotID || len(after.Tables) != len(before.Tables) {
		t.Errorf("signing changed the snapshot: %+v then %+v", before, after)
	}
	for _, tb := range after.Tables {
		if strings.Contains(tb.File, "sig") {
			t.Errorf("the signature is listed as a table: %+v", tb)
		}
	}
	// Whatever the file holds, the id and the tables stay what the manifest
	// says; only the signature's own status changes.
	sig := filepath.Join(dir, File)
	for _, content := range []string{"", "not json", `{"mediaType":"x"}`} {
		if err := os.WriteFile(sig, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		res := snapshot.Verify(dir)
		if !res.OK() || res.SnapshotID != before.SnapshotID {
			t.Errorf("a signature file of %q changed the snapshot: %+v", content, res)
		}
		if st := Inspect(dir); st.State != Invalid {
			t.Errorf("a signature file of %q reads as %+v", content, st)
		}
	}
	if err := os.Remove(sig); err != nil {
		t.Fatal(err)
	}
	if res := snapshot.Verify(dir); !res.OK() || res.SnapshotID != before.SnapshotID {
		t.Errorf("removing the signature changed the snapshot: %+v", res)
	}
}

func TestAnEditedBundleFails(t *testing.T) {
	dir, keys := signed(t)
	p := filepath.Join(dir, File)
	b := read(t, p)
	marker := []byte(`"signature":"`)
	i := bytes.Index(b, marker)
	if i < 0 {
		t.Fatalf("no signature in %s", b)
	}
	i += len(marker)
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Invalid {
		t.Errorf("an edited signature verified: %+v", st)
	}
}

func TestSigningRefusesWhatItShouldNot(t *testing.T) {
	keys := signingtest.NewKeys(t, "p256")

	dir := estate(t)
	if err := SignWithKey(dir, keys.Private, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := SignWithKey(dir, keys.Private, nil, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("a second signature without --force: %v", err)
	}
	if err := SignWithKey(dir, keys.Private, nil, true); err != nil {
		t.Errorf("--force: %v", err)
	}

	broken := estate(t)
	if err := os.Remove(filepath.Join(broken, snapshot.EdgesFile)); err != nil {
		t.Fatal(err)
	}
	if err := SignWithKey(broken, keys.Private, nil, false); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("signing a snapshot that does not verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(broken, File)); err == nil {
		t.Error("a signature was written for a snapshot that does not verify")
	}

	for name, key := range map[string]string{
		"a missing": filepath.Join(t.TempDir(), "nope"), "a public": keys.Public, "an Ed25519": signingtest.NewKeys(t, "ed25519").Private,
	} {
		if err := SignWithKey(estate(t), key, nil, false); err == nil {
			t.Errorf("signing with %s key", name)
		}
	}
}

func TestACosignEncryptedKey(t *testing.T) {
	keys := signingtest.NewEncryptedKeys(t, "hunter2")
	dir := estate(t)
	if err := SignWithKey(dir, keys.Private, nil, false); err == nil || !strings.Contains(err.Error(), "COSIGN_PASSWORD") {
		t.Errorf("no password: %v", err)
	}
	if err := SignWithKey(dir, keys.Private, []byte("wrong"), false); err == nil {
		t.Error("the wrong password signed")
	}
	if err := SignWithKey(dir, keys.Private, []byte("hunter2"), false); err != nil {
		t.Fatal(err)
	}
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Verified {
		t.Errorf("%+v", st)
	}
}

func TestVerifierValidate(t *testing.T) {
	for _, v := range []Verifier{
		{},
		{KeyFile: "k.pub"},
		{Identity: "a@b.c", Issuer: "https://i"},
		{IdentityRegexp: "^a@", IssuerRegexp: "^https://"},
		{Identity: "a@b.c", IssuerRegexp: "^https://", TrustedRoot: "root.json"},
	} {
		if err := v.Validate(); err != nil {
			t.Errorf("%+v: %v", v, err)
		}
	}
	for name, v := range map[string]Verifier{
		"key and identity":        {KeyFile: "k", Identity: "a", Issuer: "i"},
		"key with a root":         {KeyFile: "k", TrustedRoot: "r"},
		"identity without issuer": {Identity: "a"},
		"issuer without identity": {Issuer: "i"},
		"both identity forms":     {Identity: "a", IdentityRegexp: "a", Issuer: "i"},
		"both issuer forms":       {Identity: "a", Issuer: "i", IssuerRegexp: "i"},
		"a root alone":            {TrustedRoot: "r"},
		"a bad regexp":            {IdentityRegexp: "(", Issuer: "i"},
	} {
		if err := v.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestAnIncompleteVerifierIsReportedNotRun(t *testing.T) {
	dir, _ := signed(t)
	if st := Check(dir, Verifier{Identity: "a@b.c"}); st.State != Invalid || !strings.Contains(st.Problem, "--certificate-oidc-issuer") {
		t.Errorf("%+v", st)
	}
}

func TestASymbolicLinkIsNoSignature(t *testing.T) {
	dir := estate(t)
	target := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, File)); err != nil {
		t.Skip("no symbolic links here")
	}
	if st := Inspect(dir); st.State != Invalid {
		t.Errorf("%+v", st)
	}
}

func TestTheSignatureIsCheckedOverTheBytesGiven(t *testing.T) {
	// A caller that verified the snapshot passes the manifest bytes it hashed.
	// The check must use those, not read the file again: a manifest swapped on
	// disk after the hash check is then not what the signature is checked over.
	dir, keys := signed(t)
	v := Verifier{KeyFile: keys.Public}
	p := filepath.Join(dir, snapshot.ManifestFile)
	signedBytes := read(t, p)

	// The file now holds other bytes, the verified ones are passed: verified.
	if err := os.WriteFile(p, append(append([]byte{}, signedBytes...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := CheckBytes(dir, signedBytes, v); st.State != Verified {
		t.Errorf("the verified bytes were not what the signature was checked over: %+v", st)
	}
	// The file holds the signed bytes, other bytes are passed (what a caller
	// that loaded a different manifest would hold): invalid.
	if err := os.WriteFile(p, signedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if st := CheckBytes(dir, append(append([]byte{}, signedBytes...), '\n'), v); st.State != Invalid {
		t.Errorf("a signature verified over bytes it does not cover: %+v", st)
	}
	if st := CheckBytes(dir, nil, v); st.State != Invalid {
		t.Errorf("no manifest bytes: %+v", st)
	}
	// Without a verifier the bytes do not matter.
	if st := CheckBytes(dir, nil, Verifier{}); st.State != SignedUnverified {
		t.Errorf("%+v", st)
	}
}

func TestSigningSignsTheVerifiedBytes(t *testing.T) {
	dir := estate(t)
	keys := signingtest.NewKeys(t, "p256")
	if err := SignWithKey(dir, keys.Private, nil, false); err != nil {
		t.Fatal(err)
	}
	_, raw := snapshot.VerifyWithManifest(dir)
	if st := CheckBytes(dir, raw, Verifier{KeyFile: keys.Public}); st.State != Verified {
		t.Errorf("%+v", st)
	}
}
