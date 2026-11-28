// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
)

// A key or a certificate identity is something to trust: a snapshot with no
// signature that checks against it fails, with or without --require-signature.
func TestATrustAnchorRequiresASignature(t *testing.T) {
	// A server that is wrongly let through reads an empty input and stops.
	old := stdin
	stdin = io.Reader(strings.NewReader(""))
	t.Cleanup(func() { stdin = old })
	keys := signingtest.NewKeys(t, "p256")
	_, unsigned := build(t)
	_, signed := build(t)
	if code, _, errs := exec(t, "snapshot", "sign", "--key", keys.Private, signed); code != 0 {
		t.Fatalf("sign: %d %s", code, errs)
	}
	identity := []string{"--certificate-identity", "me@example.com", "--certificate-oidc-issuer", "https://issuer.example.com"}
	cases := map[string][]string{
		"key":                 {"--key", keys.Public},
		"identity and issuer": identity,
		"identity regexp":     {"--certificate-identity-regexp", "me@.*", "--certificate-oidc-issuer-regexp", "https://issuer.*"},
	}
	for name, flags := range cases {
		for _, cmd := range [][]string{{"snapshot", "verify"}, {"verify"}, {"serve-mcp"}} {
			args := append(append(append([]string{}, cmd...), flags...), unsigned)
			code, out, errs := exec(t, args...)
			if code != exitVerifyFailed {
				t.Errorf("%s %s on an unsigned snapshot: exit %d, want %d\n%s%s", strings.Join(cmd, " "), name, code, exitVerifyFailed, out, errs)
			}
			if !strings.Contains(out+errs, "signature") {
				t.Errorf("%s %s: no word about the signature\n%s%s", strings.Join(cmd, " "), name, out, errs)
			}
		}
	}
	// A signature that checks passes, and with no anchor an unsigned snapshot
	// still passes: the check is opt-in by giving something to trust.
	if code, out, errs := exec(t, "snapshot", "verify", "--key", keys.Public, signed); code != 0 {
		t.Errorf("signed, right key: exit %d\n%s%s", code, out, errs)
	}
	if code, out, errs := exec(t, "snapshot", "verify", unsigned); code != 0 {
		t.Errorf("unsigned, no anchor: exit %d\n%s%s", code, out, errs)
	}
	// --require-signature still works on its own terms.
	if code, _, _ := exec(t, "snapshot", "verify", "--key", keys.Public, "--require-signature", unsigned); code != exitVerifyFailed {
		t.Errorf("--require-signature on an unsigned snapshot: exit %d", code)
	}
}
