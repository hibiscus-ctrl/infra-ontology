// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package signing

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// TestCosignVerifiesTheBundle checks what is written with the tool the
// bundle is written for: `cosign verify-blob --bundle` over the manifest,
// with the public key (no transparency log entry, as the bundle has none),
// for each key type. It is skipped without cosign.
func TestCosignVerifiesTheBundle(t *testing.T) {
	cosign, err := exec.LookPath("cosign")
	if err != nil {
		t.Skip("cosign is not on the PATH")
	}
	for _, kind := range []string{"p256", "p384", "p521", "ed25519", "rsa2048", "rsa3072"} {
		t.Run(kind, func(t *testing.T) {
			dir, keys := estate(t), signingtest.NewKeys(t, kind)
			if err := SignWithKey(dir, keys.Private, nil, false); err != nil {
				t.Fatal(err)
			}
			args := []string{"verify-blob", "--key", keys.Public, "--bundle", filepath.Join(dir, File),
				"--insecure-ignore-tlog=true", filepath.Join(dir, snapshot.ManifestFile)}
			if out, err := exec.CommandContext(t.Context(), cosign, args...).CombinedOutput(); err != nil {
				t.Fatalf("cosign %v: %v\n%s", args, err, out)
			}

			// A manifest that was changed after signing must not verify.
			if err := os.WriteFile(filepath.Join(dir, snapshot.ManifestFile), append(read(t, filepath.Join(dir, snapshot.ManifestFile)), '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.CommandContext(t.Context(), cosign, args...).CombinedOutput(); err == nil {
				t.Fatalf("cosign verified an edited manifest:\n%s", out)
			}
		})
	}
}

// TestAnRSAKeyInPKCS1Form is the traditional OpenSSL form of an RSA key.
func TestAnRSAKeyInPKCS1Form(t *testing.T) {
	keys := signingtest.NewKeys(t, "rsa2048")
	priv, err := cryptoutils.UnmarshalPEMToPrivateKey(read(t, keys.Private), nil)
	if err != nil {
		t.Fatal(err)
	}
	rk, ok := priv.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("%T", priv)
	}
	pk1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	path := filepath.Join(t.TempDir(), "rsa.key")
	if err := os.WriteFile(path, pk1, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := estate(t)
	if err := SignWithKey(dir, path, nil, false); err != nil {
		t.Fatal(err)
	}
	if st := Check(dir, Verifier{KeyFile: keys.Public}); st.State != Verified {
		t.Errorf("%+v", st)
	}
}
