// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// noTime is a zero time: a key with no validity period.
var noTime time.Time

// hashFor is the digest a public key's signatures are made over, as
// sigstore-go and cosign choose it.
func hashFor(pub crypto.PublicKey) crypto.Hash {
	if k, ok := pub.(*ecdsa.PublicKey); ok {
		switch k.Curve {
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		}
	}
	return crypto.SHA256
}

// keypair is a signing key read from a file, as sigstore-go's sign.Keypair.
// Only the signature leaves it: the key stays in this process.
type keypair struct {
	signer  crypto.Signer
	details sigsig.AlgorithmDetails
	alg     protocommon.PublicKeyDetails
	hint    []byte
}

// loadKeypair reads a PEM private key. The password, if not nil, opens an
// encrypted key: the form `cosign generate-key-pair` writes (ENCRYPTED
// SIGSTORE PRIVATE KEY) or PKCS #8 encrypted.
func loadKeypair(raw, password []byte) (*keypair, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	var pf cryptoutils.PassFunc
	if password != nil {
		pf = cryptoutils.StaticPasswordFunc(password)
	}
	if password == nil && isEncrypted(block) {
		return nil, errors.New("the key is encrypted: put its password in COSIGN_PASSWORD")
	}
	priv, err := cryptoutils.UnmarshalPEMToPrivateKey(raw, pf)
	if err != nil {
		return nil, fmt.Errorf("reading the key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a %T is not a signing key", priv)
	}
	var alg protocommon.PublicKeyDetails
	switch k := signer.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			alg = protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case elliptic.P384():
			alg = protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		case elliptic.P521():
			alg = protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
		default:
			return nil, fmt.Errorf("the curve %s is not supported: use P-256, P-384 or P-521", k.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		// A bundle over a message with a pure Ed25519 signature has no digest
		// algorithm, and sigstore-go cannot check one; cosign does not check
		// Ed25519ph. So no bundle we write would verify anywhere.
		return nil, errors.New("Ed25519 keys are not supported: a Sigstore message-signature bundle cannot carry one that verifies; use an ECDSA key (P-256, P-384 or P-521)")
	default:
		return nil, fmt.Errorf("a %T key is not supported: use an ECDSA key (P-256, P-384 or P-521)", signer.Public())
	}
	details, err := sigsig.GetAlgorithmDetails(alg)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &keypair{signer: signer, details: details, alg: alg, hint: []byte(base64.StdEncoding.EncodeToString(sum[:]))}, nil
}

func isEncrypted(b *pem.Block) bool {
	switch b.Type {
	case "ENCRYPTED SIGSTORE PRIVATE KEY", "ENCRYPTED COSIGN PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return true
	}
	return x509.IsEncryptedPEMBlock(b) //nolint:staticcheck // legacy keys still exist
}

func (k *keypair) GetHashAlgorithm() protocommon.HashAlgorithm { return k.details.GetProtoHashType() }

func (k *keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails { return k.alg }

func (k *keypair) GetHint() []byte { return k.hint }

func (k *keypair) GetKeyAlgorithm() string {
	if k.details.GetKeyType() == sigsig.ECDSA {
		return "ECDSA"
	}
	return ""
}

func (k *keypair) GetPublicKey() crypto.PublicKey { return k.signer.Public() }

func (k *keypair) GetPublicKeyPem() (string, error) {
	b, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	return string(b), err
}

// SignData returns the signature and the data it is over: a digest, except
// for Ed25519, which hashes inside the signature.
func (k *keypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.details.GetHashType()
	toSign := data
	if hf != crypto.Hash(0) {
		h := hf.New()
		h.Write(data)
		toSign = h.Sum(nil)
	}
	sig, err := k.signer.Sign(rand.Reader, toSign, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, toSign, nil
}
