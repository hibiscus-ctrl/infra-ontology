// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hibiscus-ctrl/infra-ontology/internal/signing"
)

// verifyFlags are the flags that say what signature to trust. `verify` and
// `serve-mcp` take them.
type verifyFlags struct {
	key, identity, identityRe, issuer, issuerRe, trustedRoot *string
	require                                                  *bool
}

func addVerifyFlags(fs *flag.FlagSet) verifyFlags {
	return verifyFlags{
		key:         fs.String("key", "", "trust this PEM public key: the snapshot must carry a signature that checks with it (offline)"),
		identity:    fs.String("certificate-identity", "", "trust a keyless signature by this certificate identity, an email address or a workflow URL (with --certificate-oidc-issuer); the snapshot must carry one"),
		identityRe:  fs.String("certificate-identity-regexp", "", "the certificate's identity as a regular expression, matched against the whole identity"),
		issuer:      fs.String("certificate-oidc-issuer", "", "the OIDC issuer of the certificate, for example https://token.actions.githubusercontent.com"),
		issuerRe:    fs.String("certificate-oidc-issuer-regexp", "", "the OIDC issuer as a regular expression, matched against the whole issuer"),
		trustedRoot: fs.String("trusted-root", "", "a Sigstore trusted_root.json, to check a keyless signature offline (default: the public-good root, fetched with TUF)"),
		require:     fs.Bool("require-signature", false, "fail if the snapshot has no signature that verified (implied by --key, or --certificate-identity with --certificate-oidc-issuer: what you trust must have signed it)"),
	}
}

func (f verifyFlags) verifier() signing.Verifier {
	return signing.Verifier{
		KeyFile: *f.key, Identity: *f.identity, IdentityRegexp: *f.identityRe,
		Issuer: *f.issuer, IssuerRegexp: *f.issuerRe, TrustedRoot: *f.trustedRoot,
	}
}

// required reports whether a signature that verifies is a must: it was asked
// for with --require-signature, or something to trust was given. A key or an
// identity that an unsigned snapshot passes would be no check at all.
func (f verifyFlags) required() bool {
	return *f.require || f.verifier().Configured()
}

// set reports whether any of the flags was given.
func (f verifyFlags) set() bool {
	return f.verifier().Configured() || *f.trustedRoot != "" || *f.require
}

// check validates the flags as a command line: what to trust is complete, and
// --require-signature has something to check with. It returns the verifier, or
// a message for the user.
func (f verifyFlags) check() (signing.Verifier, error) {
	v := f.verifier()
	if err := v.Validate(); err != nil {
		return v, err
	}
	if *f.require && !v.Configured() {
		return v, fmt.Errorf("--require-signature needs --key, or --certificate-identity and --certificate-oidc-issuer, to check the signature with")
	}
	return v, nil
}

// runSign is `snapshot sign`: write manifest.sig.json, a Sigstore bundle over
// the manifest, signed with a key file or keyless.
func runSign(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("snapshot sign", stderr)
	key := fs.String("key", "", "sign with this private key file: a PEM ECDSA (P-256, P-384, P-521), Ed25519 or RSA (2048, 3072, 4096) key, or a cosign key (its password in COSIGN_PASSWORD)")
	keyless := fs.Bool("keyless", false, "sign without a key: an OIDC token (a GitHub Actions job with id-token: write, or SIGSTORE_ID_TOKEN) buys a short-lived certificate from Fulcio, and Rekor records it")
	force := fs.Bool("force", false, "replace a signature the snapshot already has")
	dirs, ok := parse(fs, args, 1, 1, stderr)
	if !ok {
		return exitUsage
	}
	switch {
	case *key != "" && *keyless:
		fmt.Fprintln(stderr, "infra-ontology snapshot sign: give --key FILE or --keyless, not both")
		return exitUsage
	case *key == "" && !*keyless:
		fmt.Fprintln(stderr, "infra-ontology snapshot sign: say how: --key FILE, or --keyless")
		return exitUsage
	}
	dir := dirs[0]
	var err error
	if *keyless {
		ctx, stop := signalContext()
		defer stop()
		err = signing.SignKeyless(ctx, dir, signing.Keyless{}, *force)
	} else {
		var password []byte
		if p, ok := os.LookupEnv("COSIGN_PASSWORD"); ok {
			password = []byte(p)
		}
		err = signing.SignWithKey(dir, *key, password, *force)
	}
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot sign: %s\n", printable(cleanErr(err)))
		return exitFailed
	}
	how := "with a key"
	if *keyless {
		how = "keyless"
	}
	fmt.Fprintf(stdout, "signed %s %s\n%s/%s\n", dir, how, dir, signing.File)
	return exitOK
}
