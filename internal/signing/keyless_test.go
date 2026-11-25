// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package signing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing/signingtest"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A keyless signature is checked here against sigstore-go's virtual Sigstore (a
// Fulcio, a Rekor and a timestamp authority made in the test), so the policy
// is the real one: a certificate chain, a log entry, a trusted time and the
// identity. The virtual Fulcio issues certificates without a signed
// certificate timestamp, so the cases that expect a pass ask for none, and one
// case checks that the policy the command runs refuses such a certificate. What no test here does is sign against the public-good Fulcio and
// Rekor, which needs an OIDC token and the network.

const (
	workflow = "https://github.com/acme/infra/.github/workflows/snapshot.yml@refs/heads/main"
	issuer   = "https://token.actions.githubusercontent.com"
)

func keylessEntity(t *testing.T) (*ca.VirtualSigstore, *ca.TestEntity, []byte) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	manifest := read(t, filepath.Join(estate(t), snapshot.ManifestFile))
	entity, err := vs.Sign(workflow, issuer, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return vs, entity, manifest
}

func TestKeylessVerificationPolicy(t *testing.T) {
	vs, entity, manifest := keylessEntity(t)

	good := map[string]Verifier{
		"exact":   {Identity: workflow, Issuer: issuer},
		"regexp":  {IdentityRegexp: `^https://github\.com/acme/infra/\.github/workflows/.*@refs/heads/main$`, IssuerRegexp: `^https://token\.actions\.`},
		"mixed":   {Identity: workflow, IssuerRegexp: `githubusercontent\.com$`},
		"another": {IdentityRegexp: `acme/infra`, Issuer: issuer},
	}
	for name, v := range good {
		t.Run(name, func(t *testing.T) {
			signer, err := v.verifyKeyless(entity, manifest, vs, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(signer, workflow) || !strings.Contains(signer, issuer) {
				t.Errorf("signer %q does not name the identity and the issuer", signer)
			}
		})
	}

	bad := map[string]Verifier{
		"another identity":      {Identity: "https://github.com/evil/infra/.github/workflows/snapshot.yml@refs/heads/main", Issuer: issuer},
		"a prefix of it":        {Identity: "https://github.com/acme/infra", Issuer: issuer},
		"another issuer":        {Identity: workflow, Issuer: "https://accounts.google.com"},
		"an unanchored issuer":  {Identity: workflow, IssuerRegexp: `^https://accounts\.`},
		"an identity regexp":    {IdentityRegexp: `^https://github\.com/evil/`, Issuer: issuer},
		"identity, wrong issue": {IdentityRegexp: `acme`, Issuer: issuer + "/x"},
	}
	for name, v := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := v.verifyKeyless(entity, manifest, vs, 0); err == nil {
				t.Error("verified")
			}
		})
	}

	t.Run("a changed manifest", func(t *testing.T) {
		v := Verifier{Identity: workflow, Issuer: issuer}
		if _, err := v.verifyKeyless(entity, append(append([]byte{}, manifest...), '\n'), vs, 0); err == nil {
			t.Error("a changed manifest verified")
		}
	})
	t.Run("no signed certificate timestamp", func(t *testing.T) {
		// The virtual Fulcio issues certificates without one, so the policy
		// the command line runs (requiredSCTs) refuses them.
		v := Verifier{Identity: workflow, Issuer: issuer}
		if _, err := v.verifyKeyless(entity, manifest, vs, requiredSCTs); err == nil || !strings.Contains(err.Error(), "SCT") {
			t.Errorf("a certificate with no SCT verified: %v", err)
		}
	})
	t.Run("another root of trust", func(t *testing.T) {
		other, err := ca.NewVirtualSigstore()
		if err != nil {
			t.Fatal(err)
		}
		v := Verifier{Identity: workflow, Issuer: issuer}
		if _, err := v.verifyKeyless(entity, manifest, other, 0); err == nil {
			t.Error("a signature from another Sigstore verified")
		}
	})
}

func TestACertificateIsNoKeySignature(t *testing.T) {
	_, entity, manifest := keylessEntity(t)
	v := Verifier{KeyFile: signingtest.NewKeys(t, "p256").Public}
	if _, err := v.verifyKey(entity, manifest); err == nil {
		t.Error("a certificate signature passed a --key check")
	}
}

func TestTheAmbientGitHubActionsToken(t *testing.T) {
	var gotAuth, gotAudience string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAudience = r.Header.Get("Authorization"), r.URL.Query().Get("audience")
		if r.URL.Query().Get("existing") != "1" {
			http.Error(w, "the request URL's own query was dropped", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"count":1,"value":"the-oidc-token"}`))
	}))
	defer srv.Close()

	env := map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_URL":   srv.URL + "/token?existing=1",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret",
	}
	k := Keyless{HTTPClient: srv.Client()}
	tok, err := k.idToken(context.Background(), func(n string) string { return env[n] })
	if err != nil || tok != "the-oidc-token" {
		t.Fatalf("token %q, %v", tok, err)
	}
	if gotAuth != "Bearer runner-secret" || gotAudience != "sigstore" {
		t.Errorf("the request had %q and audience %q", gotAuth, gotAudience)
	}

	// SIGSTORE_ID_TOKEN wins, and no request goes out.
	env["SIGSTORE_ID_TOKEN"] = "given"
	gotAuth = ""
	if tok, err := k.idToken(context.Background(), func(n string) string { return env[n] }); err != nil || tok != "given" || gotAuth != "" {
		t.Errorf("token %q, %v, auth %q", tok, err, gotAuth)
	}
}

func TestTheTokenFailsClearly(t *testing.T) {
	none := func(string) string { return "" }
	if _, err := (Keyless{}).idToken(context.Background(), none); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("no token: %v", err)
	}

	denied := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusForbidden) }))
	defer denied.Close()
	env := func(n string) string {
		return map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": denied.URL + "/t", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret"}[n]
	}
	_, err := (Keyless{HTTPClient: denied.Client()}).idToken(context.Background(), env)
	if err == nil || strings.Contains(err.Error(), "runner-secret") {
		t.Errorf("a refused request: %v", err)
	}

	plain := func(n string) string {
		return map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "http://example.com/t", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x"}[n]
	}
	if _, err := (Keyless{}).idToken(context.Background(), plain); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("a plain http token URL: %v", err)
	}
}

func TestKeylessSigningNeedsAToken(t *testing.T) {
	dir := estate(t)
	t.Setenv("SIGSTORE_ID_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	err := SignKeyless(context.Background(), dir, Keyless{}, false)
	if err == nil || !strings.Contains(err.Error(), "OIDC token") {
		t.Errorf("%v", err)
	}
	if st := Inspect(dir); st.State != Unsigned {
		t.Errorf("a failed keyless signature left %+v", st)
	}
}
