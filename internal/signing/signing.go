// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package signing signs a snapshot's manifest and checks the signature. The
// signature is a Sigstore bundle (manifest.sig.json) over the bytes of
// manifest.json, so `cosign verify-blob --bundle manifest.sig.json
// manifest.json` checks it too. The manifest names every table's SHA-256 and
// its snapshot_id covers all of that, so one signature covers the snapshot: a
// changed table fails the hash check and a changed manifest fails the
// signature. The signature file is no part of the snapshot's id.
//
// The customer signs and this package never holds a key: a private key is
// read from the file the caller names, and a keyless signature takes an OIDC
// token the caller's CI provides (Fulcio and Rekor, public good).
package signing

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// File is the signature's file name inside a snapshot folder.
const File = snapshot.SignatureFile

// The states of a snapshot's signature.
const (
	// Unsigned: there is no signature file.
	Unsigned = "unsigned"
	// SignedUnverified: there is a signature file that reads as a Sigstore
	// bundle, and no verifier was given to check it.
	SignedUnverified = "signed_unverified"
	// Verified: the signature checked against the key or identity the caller
	// trusts.
	Verified = "verified"
	// Invalid: there is a signature file that is not a bundle, or a signature
	// that does not check.
	Invalid = "invalid"
)

// Signature modes.
const (
	ModeKey     = "key"
	ModeKeyless = "keyless"
)

// Status is what is known of a snapshot's signature.
type Status struct {
	State string `json:"status"`
	// Mode is how it was signed: "key" or "keyless".
	Mode string `json:"mode,omitempty"`
	// Signer is who signed it, set only when the signature verified: the
	// SHA-256 of the public key (key mode), or the certificate's identity and
	// issuer (keyless).
	Signer string `json:"signer,omitempty"`
	// Problem says why a signature is invalid.
	Problem string `json:"problem,omitempty"`
}

// String is the status as the command line prints it.
func (s Status) String() string {
	switch s.State {
	case Unsigned:
		return "unsigned"
	case SignedUnverified:
		return "signed (unverified)"
	case Verified:
		return fmt.Sprintf("verified (%s: %s)", s.Mode, s.Signer)
	}
	return "INVALID: " + s.Problem
}

// Verifier is what the caller trusts: a public key, or a certificate identity
// and its issuer, with the rules of `cosign verify-blob`. The zero value
// trusts nothing, and a signature is then only read, never checked.
type Verifier struct {
	// KeyFile is a PEM public key. Key mode checks offline.
	KeyFile string
	// Identity and IdentityRegexp match the certificate's subject alternative
	// name (an email address or a URL such as a workflow); give one.
	Identity, IdentityRegexp string
	// Issuer and IssuerRegexp match the certificate's OIDC issuer; give one.
	Issuer, IssuerRegexp string
	// TrustedRoot is a trusted_root.json for keyless checks, so that they
	// run offline. Empty: the public-good root, fetched with TUF.
	TrustedRoot string
}

// Configured reports whether the verifier names anything to trust.
func (v Verifier) Configured() bool {
	return v.KeyFile != "" || v.Identity != "" || v.IdentityRegexp != "" || v.Issuer != "" || v.IssuerRegexp != ""
}

// Validate checks that the verifier is one of the two modes, complete, with
// the pairs `cosign verify-blob` requires.
func (v Verifier) Validate() error {
	keyless := v.Identity != "" || v.IdentityRegexp != "" || v.Issuer != "" || v.IssuerRegexp != ""
	switch {
	case v.KeyFile != "" && keyless:
		return errors.New("give --key, or --certificate-identity with --certificate-oidc-issuer, not both")
	case v.KeyFile != "" && v.TrustedRoot != "":
		return errors.New("--trusted-root is for keyless checks; a key needs none")
	case v.KeyFile != "":
		return nil
	case !keyless:
		if v.TrustedRoot != "" {
			return errors.New("--trusted-root needs --certificate-identity and --certificate-oidc-issuer")
		}
		return nil
	case v.Identity != "" && v.IdentityRegexp != "", v.Issuer != "" && v.IssuerRegexp != "":
		return errors.New("give the identity (or the issuer) exactly or as a regular expression, not both")
	case v.Identity == "" && v.IdentityRegexp == "":
		return errors.New("a keyless check needs --certificate-identity (or --certificate-identity-regexp)")
	case v.Issuer == "" && v.IssuerRegexp == "":
		return errors.New("a keyless check needs --certificate-oidc-issuer (or --certificate-oidc-issuer-regexp)")
	}
	for _, re := range []string{v.IdentityRegexp, v.IssuerRegexp} {
		if re == "" {
			continue
		}
		if _, err := regexp.Compile(anchor(re)); err != nil {
			return fmt.Errorf("regular expression %q: %w", re, err)
		}
	}
	return nil
}

// anchor makes a regular expression match the whole value: sigstore-go's
// matcher finds the expression anywhere in it, so an identity such as
// https://evil/x?github.com/org/repo would match github.com/org/repo. The
// group keeps an alternation (a|b) whole.
func anchor(re string) string { return "^(?:" + re + ")$" }

// Inspect reads the signature file without checking it: unsigned, a bundle
// that reads (signed, unverified), or a file that is not a bundle (invalid).
func Inspect(dir string) Status {
	b, err := readBundle(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Status{State: Unsigned}
	case err != nil:
		return Status{State: Invalid, Problem: err.Error()}
	}
	return Status{State: SignedUnverified, Mode: modeOf(b)}
}

// Check reads manifest.json in dir and checks the signature over it, as
// CheckBytes does. A caller that has verified or loaded the snapshot must not
// use it: that is a second read of the file, which could have changed since.
// Use CheckBytes with the bytes that were verified.
func Check(dir string, v Verifier) Status {
	manifest, err := os.ReadFile(filepath.Join(dir, snapshot.ManifestFile))
	if err != nil {
		if st := Inspect(dir); st.State != SignedUnverified || !v.Configured() {
			return st
		}
		return Status{State: Invalid, Problem: fmt.Sprintf("%s: %v", snapshot.ManifestFile, pathReason(err))}
	}
	return CheckBytes(dir, manifest, v)
}

// CheckBytes reads the signature in dir and, if v trusts something, checks it
// over manifest, which must be the bytes of manifest.json that the caller
// verified and parsed (snapshot.Loaded.ManifestRaw, or the bytes
// snapshot.VerifyWithManifest returns). With a zero Verifier it is Inspect. It
// does not check the tables: snapshot.Verify does, through the manifest's
// hashes.
func CheckBytes(dir string, manifest []byte, v Verifier) Status {
	b, err := readBundle(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return Status{State: Unsigned}
	case err != nil:
		return Status{State: Invalid, Problem: err.Error()}
	}
	mode := modeOf(b)
	if !v.Configured() {
		return Status{State: SignedUnverified, Mode: mode}
	}
	if err := v.Validate(); err != nil {
		return Status{State: Invalid, Mode: mode, Problem: err.Error()}
	}
	if manifest == nil {
		return Status{State: Invalid, Mode: mode, Problem: snapshot.ManifestFile + ": there is no manifest to check the signature over"}
	}
	signer, err := v.verify(b, manifest)
	if err != nil {
		return Status{State: Invalid, Mode: mode, Problem: err.Error()}
	}
	return Status{State: Verified, Mode: mode, Signer: signer}
}

// verify checks a signed entity over the manifest bytes and returns who
// signed it.
func (v Verifier) verify(entity verify.SignedEntity, manifest []byte) (string, error) {
	if v.KeyFile != "" {
		return v.verifyKey(entity, manifest)
	}
	trust, err := v.trustedRoot()
	if err != nil {
		return "", err
	}
	return v.verifyKeyless(entity, manifest, trust, requiredSCTs)
}

func (v Verifier) verifyKey(entity verify.SignedEntity, manifest []byte) (string, error) {
	raw, err := os.ReadFile(v.KeyFile)
	if err != nil {
		return "", fmt.Errorf("--key: %w", pathReason(err))
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(raw)
	if err != nil {
		return "", fmt.Errorf("--key %s: not a PEM public key: %w", filepath.Base(v.KeyFile), err)
	}
	sv, err := sigsig.LoadVerifier(pub, hashFor(pub))
	if err != nil {
		return "", fmt.Errorf("--key %s: %w", filepath.Base(v.KeyFile), err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	// The key is the one the caller trusts, whatever hint the bundle gives.
	trust := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(sv, noTime, noTime), nil
	})
	ver, err := verify.NewVerifier(trust, verify.WithNoObserverTimestamps())
	if err != nil {
		return "", err
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(manifest)), verify.WithKey())
	if _, err := ver.Verify(entity, policy); err != nil {
		return "", fmt.Errorf("the signature does not verify with %s: %w", filepath.Base(v.KeyFile), err)
	}
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// requiredSCTs is how many signed certificate timestamps a keyless signature's
// certificate must carry, as `cosign verify-blob` requires of public-good
// signatures.
const requiredSCTs = 1

func (v Verifier) verifyKeyless(entity verify.SignedEntity, manifest []byte, trust root.TrustedMaterial, scts int) (string, error) {
	// A regular expression is matched against the whole value.
	var identityRe, issuerRe string
	if v.IdentityRegexp != "" {
		identityRe = anchor(v.IdentityRegexp)
	}
	if v.IssuerRegexp != "" {
		issuerRe = anchor(v.IssuerRegexp)
	}
	id, err := verify.NewShortCertificateIdentity(v.Issuer, issuerRe, v.Identity, identityRe)
	if err != nil {
		return "", err
	}
	// What `cosign verify-blob` requires of a public-good signature: a
	// certificate with a signed certificate timestamp, an entry in the
	// transparency log and a trusted time inside the certificate's life.
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if scts > 0 {
		opts = append(opts, verify.WithSignedCertificateTimestamps(scts))
	}
	ver, err := verify.NewVerifier(trust, opts...)
	if err != nil {
		return "", err
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(manifest)), verify.WithCertificateIdentity(id))
	res, err := ver.Verify(entity, policy)
	if err != nil {
		return "", fmt.Errorf("the signature does not verify for that identity and issuer: %w", err)
	}
	if res.Signature != nil && res.Signature.Certificate != nil {
		c := res.Signature.Certificate
		return fmt.Sprintf("%s, issued to %s", c.SubjectAlternativeName, c.Issuer), nil
	}
	return v.Identity + v.IdentityRegexp, nil
}

// trustedRoot is the root of trust for keyless checks: the file the caller
// gave, or the public-good root from TUF.
func (v Verifier) trustedRoot() (root.TrustedMaterial, error) {
	if v.TrustedRoot != "" {
		tr, err := root.NewTrustedRootFromPath(v.TrustedRoot)
		if err != nil {
			return nil, fmt.Errorf("--trusted-root %s: %w", filepath.Base(v.TrustedRoot), err)
		}
		return tr, nil
	}
	tr, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching the Sigstore trusted root (give --trusted-root FILE to check offline): %w", err)
	}
	return tr, nil
}

// SignWithKey signs the snapshot in dir with the private key in keyFile and
// writes manifest.sig.json beside the manifest. The key is a PEM ECDSA
// (P-256, P-384 or P-521), Ed25519 or RSA (2048, 3072 or 4096 bits; PKCS #1
// v1.5 with SHA-256) key, in PKCS #8, SEC 1, PKCS #1 or the encrypted
// form `cosign generate-key-pair` writes; password opens an encrypted key.
// Nothing leaves the machine: the bundle holds the signature and the key's
// hint, with no certificate and no transparency log entry.
func SignWithKey(dir, keyFile string, password []byte, force bool) error {
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("--key: %w", pathReason(err))
	}
	kp, err := loadKeypair(raw, password)
	if err != nil {
		return fmt.Errorf("--key %s: %w", filepath.Base(keyFile), err)
	}
	return signManifest(dir, force, func(manifest []byte) (*protobundle.Bundle, error) {
		return sign.Bundle(&sign.PlainData{Data: manifest}, kp, sign.BundleOptions{})
	})
}

// signManifest checks the snapshot is one that verifies, builds the bundle
// over its manifest and writes it, refusing to replace a signature unless
// force is set.
func signManifest(dir string, force bool, build func(manifest []byte) (*protobundle.Bundle, error)) error {
	// Sign the bytes that were verified, not a second read of the file.
	res, manifest := snapshot.VerifyWithManifest(dir)
	if !res.OK() {
		return fmt.Errorf("%s does not verify, so it is not signed:\n%s", dir, res.Error())
	}
	target := filepath.Join(dir, File)
	if _, err := os.Lstat(target); err == nil && !force {
		return fmt.Errorf("%s already has a signature (%s); --force replaces it", dir, File)
	}
	pb, err := build(manifest)
	if err != nil {
		return err
	}
	out, err := protojson.Marshal(pb)
	if err != nil {
		return err
	}
	return writeFile(target, append(out, '\n'))
}

// writeFile writes through a temporary file, so that a signature is whole or
// not there.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sig-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readBundle(dir string) (*bundle.Bundle, error) {
	path := filepath.Join(dir, File)
	// A symbolic link or a device is no signature, and reading one could hang.
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", File)
	}
	if st.Size() > maxBundleBytes {
		return nil, fmt.Errorf("%s is %d bytes, larger than the %d a bundle takes", File, st.Size(), maxBundleBytes)
	}
	b, err := bundle.LoadJSONFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("%s is not a Sigstore bundle: %w", File, err)
	}
	if _, err := b.SignatureContent(); err != nil {
		return nil, fmt.Errorf("%s: %w", File, err)
	}
	if b.GetMessageSignature() == nil {
		return nil, fmt.Errorf("%s does not hold a signature over a file (a message signature)", File)
	}
	return b, nil
}

// maxBundleBytes bounds a signature file. A keyless bundle with a certificate
// chain, a log entry and a timestamp is a few kilobytes.
const maxBundleBytes = 1 << 20

func modeOf(b *bundle.Bundle) string {
	if b.GetVerificationMaterial().GetPublicKey() != nil {
		return ModeKey
	}
	return ModeKeyless
}

// pathReason is a file error without its path, which the caller names.
func pathReason(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
