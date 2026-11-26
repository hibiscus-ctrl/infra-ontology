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
	"crypto/rsa"
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
		alg = protocommon.PublicKeyDetails_PKIX_ED25519
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			alg = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
		case 3072:
			alg = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256
		case 4096:
			alg = protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256
		default:
			return nil, fmt.Errorf("a %d-bit RSA key is not supported: use 2048, 3072 or 4096 bits", k.N.BitLen())
		}
	default:
		return nil, fmt.Errorf("a %T key is not supported: use an ECDSA (P-256, P-384 or P-521), Ed25519 or RSA (2048, 3072 or 4096 bits) key", signer.Public())
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

// GetHashAlgorithm is the algorithm of the digest the bundle records. A pure
// Ed25519 signature is over the message itself, but the bundle still names
// the digest of the message, and SHA-256 is the one sigstore-go and cosign
// read it with.
func (k *keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	if k.details.GetKeyType() == sigsig.ED25519 {
		return protocommon.HashAlgorithm_SHA2_256
	}
	return k.details.GetProtoHashType()
}

func (k *keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails { return k.alg }

func (k *keypair) GetHint() []byte { return k.hint }

func (k *keypair) GetKeyAlgorithm() string {
	switch k.details.GetKeyType() {
	case sigsig.ECDSA:
		return "ECDSA"
	case sigsig.RSA:
		return "RSA"
	case sigsig.ED25519:
		return "ED25519"
	}
	return ""
}

func (k *keypair) GetPublicKey() crypto.PublicKey { return k.signer.Public() }

func (k *keypair) GetPublicKeyPem() (string, error) {
	b, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	return string(b), err
}

// SignData returns the signature and the digest of the data that the bundle
// records. ECDSA and RSA (PKCS #1 v1.5) sign the digest; Ed25519 signs the
// data itself, which is what `cosign verify-blob` checks it against.
func (k *keypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.details.GetHashType()
	if hf == crypto.Hash(0) {
		sig, err := k.signer.Sign(rand.Reader, data, hf)
		if err != nil {
			return nil, nil, err
		}
		sum := sha256.Sum256(data)
		return sig, sum[:], nil
	}
	h := hf.New()
	h.Write(data)
	digest := h.Sum(nil)
	sig, err := k.signer.Sign(rand.Reader, digest, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, digest, nil
}
