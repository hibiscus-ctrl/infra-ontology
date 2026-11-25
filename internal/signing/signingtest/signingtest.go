// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package signingtest makes keys and snapshot folders for tests of signing.
package signingtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Estate is the fixture snapshot folder, relative to a package one level
// below internal/ (internal/mcpserver, internal/signing).
var Estate = filepath.Join("..", "snapshot", "testdata", "golden", "estate")

// CopyEstate copies the snapshot folder at src into a new temporary folder
// and returns it.
func CopyEstate(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil { //nolint:gosec // a name read from a fixture folder
			t.Fatal(err)
		}
	}
	return dst
}

// Keys is a key pair on disk: the PEM files of the private and public key.
type Keys struct {
	Private, Public string
}

// NewKeys writes a new key pair of the kind named: "p256", "p384", "p521" or
// "ed25519". The private key is PKCS #8, unencrypted.
func NewKeys(t *testing.T, kind string) Keys {
	t.Helper()
	var priv crypto.Signer
	var err error
	switch kind {
	case "p256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("no key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return files(t, "key.pem", privPEM, "key.pub", pubPEM)
}

// NewEncryptedKeys writes a key pair whose private key is encrypted the way
// `cosign generate-key-pair` does, under the password.
func NewEncryptedKeys(t *testing.T, password string) Keys {
	t.Helper()
	priv, pub, err := cryptoutils.GeneratePEMEncodedECDSAKeyPair(elliptic.P256(), cryptoutils.StaticPasswordFunc([]byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	return files(t, "cosign.key", priv, "cosign.pub", pub)
}

func files(t *testing.T, privName string, priv []byte, pubName string, pub []byte) Keys {
	t.Helper()
	dir := t.TempDir()
	k := Keys{Private: filepath.Join(dir, privName), Public: filepath.Join(dir, pubName)}
	if err := os.WriteFile(k.Private, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k.Public, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return k
}
