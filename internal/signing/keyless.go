// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package signing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// audience is what Fulcio expects of the OIDC token.
const audience = "sigstore"

// Keyless is how a keyless signature gets its token and where it goes. The
// zero value is the public-good Sigstore (Fulcio, Rekor and the timestamp
// authority of its signing configuration) and the ambient token of a GitHub
// Actions job.
type Keyless struct {
	// Getenv reads the environment; nil is os.Getenv. It names the token: a
	// GitHub Actions job (ACTIONS_ID_TOKEN_REQUEST_URL and _TOKEN, which
	// need `permissions: id-token: write`), or SIGSTORE_ID_TOKEN, as cosign
	// reads it.
	Getenv func(string) string
	// HTTPClient fetches the ambient token; nil is a client with a timeout.
	HTTPClient *http.Client
	// SigningConfig and TrustedRoot replace the public-good ones that are
	// fetched with TUF (tests, and a private Sigstore later).
	SigningConfig *root.SigningConfig
	TrustedRoot   root.TrustedMaterial
}

// SignKeyless signs the snapshot in dir with a short-lived certificate from
// Fulcio, issued to the identity of the OIDC token, and records the signature
// in Rekor. The key is made here, signs once and is dropped; nobody holds a
// key. It needs the network.
func SignKeyless(ctx context.Context, dir string, k Keyless, force bool) error {
	getenv := k.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	token, err := k.idToken(ctx, getenv)
	if err != nil {
		return err
	}
	return signManifest(dir, force, func(manifest []byte) (*protobundle.Bundle, error) {
		opts, err := k.bundleOptions(ctx, token)
		if err != nil {
			return nil, err
		}
		kp, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, err
		}
		pb, err := sign.Bundle(&sign.PlainData{Data: manifest}, kp, opts)
		if err != nil {
			return nil, fmt.Errorf("keyless signing: %w", err)
		}
		return pb, nil
	})
}

// bundleOptions selects the services of the signing configuration and checks
// the result against the trusted root when the bundle is made.
func (k Keyless) bundleOptions(ctx context.Context, token string) (sign.BundleOptions, error) {
	cfg, tr := k.SigningConfig, k.TrustedRoot
	if cfg == nil || tr == nil {
		client, err := tuf.New(tuf.DefaultOptions())
		if err != nil {
			return sign.BundleOptions{}, fmt.Errorf("starting the TUF client for the Sigstore root of trust: %w", err)
		}
		if cfg == nil {
			if cfg, err = root.GetSigningConfig(client); err != nil {
				return sign.BundleOptions{}, fmt.Errorf("fetching the Sigstore signing configuration: %w", err)
			}
		}
		if tr == nil {
			if tr, err = root.GetTrustedRoot(client); err != nil {
				return sign.BundleOptions{}, fmt.Errorf("fetching the Sigstore trusted root: %w", err)
			}
		}
	}
	now := time.Now()
	opts := sign.BundleOptions{Context: ctx, TrustedRoot: tr}

	fulcio, err := root.SelectService(cfg.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, now)
	if err != nil {
		return opts, fmt.Errorf("no Fulcio in the signing configuration: %w", err)
	}
	opts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{BaseURL: fulcio.URL, Timeout: 30 * time.Second, Retries: 1})
	opts.CertificateProviderOptions = &sign.CertificateProviderOptions{IDToken: token}

	tsas, err := root.SelectServices(cfg.TimestampAuthorityURLs(), cfg.TimestampAuthorityURLsConfig(), sign.TimestampAuthorityAPIVersions, now)
	if err != nil {
		return opts, fmt.Errorf("the timestamp authorities of the signing configuration: %w", err)
	}
	for _, s := range tsas {
		opts.TimestampAuthorities = append(opts.TimestampAuthorities, sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{URL: s.URL, Timeout: 30 * time.Second, Retries: 1}))
	}
	logs, err := root.SelectServices(cfg.RekorLogURLs(), cfg.RekorLogURLsConfig(), sign.RekorAPIVersions, now)
	if err != nil {
		return opts, fmt.Errorf("the transparency logs of the signing configuration: %w", err)
	}
	for _, s := range logs {
		opts.TransparencyLogs = append(opts.TransparencyLogs, sign.NewRekor(&sign.RekorOptions{BaseURL: s.URL, Timeout: 90 * time.Second, Retries: 1, Version: s.MajorAPIVersion}))
	}
	return opts, nil
}

// idToken returns the OIDC token: SIGSTORE_ID_TOKEN if set, else the ambient
// token of a GitHub Actions job.
func (k Keyless) idToken(ctx context.Context, getenv func(string) string) (string, error) {
	if t := getenv("SIGSTORE_ID_TOKEN"); t != "" {
		return t, nil
	}
	reqURL, reqToken := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", errors.New("keyless signing needs an OIDC token: run it in a GitHub Actions job with `permissions: id-token: write`, or put a token in SIGSTORE_ID_TOKEN")
	}
	u, err := url.Parse(reqURL)
	if err != nil || u.Scheme != "https" {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not an https URL")
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	req.Header.Set("Accept", "application/json")
	client := k.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("requesting the GitHub Actions OIDC token failed (is `permissions: id-token: write` set?)")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("requesting the GitHub Actions OIDC token: %s", resp.Status)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil || body.Value == "" {
		return "", errors.New("the GitHub Actions OIDC token response has no token")
	}
	return body.Value, nil
}
