# Signing a snapshot

A snapshot already proves it is whole: the manifest holds the SHA-256 of every table, and the snapshot id is the hash of the manifest, so `snapshot verify` catches a changed byte anywhere. It cannot say who made the snapshot. A signature does: `snapshot sign` writes `manifest.sig.json`, a [Sigstore bundle](https://docs.sigstore.dev/about/bundle/) over `manifest.json`, and `verify` checks it against a key or an identity you trust. You sign; the tool never holds a key and never calls home.

```sh
infra-ontology snapshot sign --key cosign.key <snapshot-dir>          # with a private key file
infra-ontology snapshot sign --keyless <snapshot-dir>                 # in a GitHub Actions job

infra-ontology snapshot verify --key cosign.pub <snapshot-dir>        # offline
infra-ontology snapshot verify <snapshot-dir> \
  --certificate-identity https://github.com/acme/infra/.github/workflows/snapshot.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## What is signed

The bundle holds a signature over the bytes of `manifest.json`. Because the manifest names every table's hash, one signature covers the whole snapshot:

- change a table, and its hash no longer matches the manifest (`verify` fails);
- change the manifest, even by a new line, and the signature no longer matches (`verify` fails).

The bundle is a standard Sigstore message-signature bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`) over the manifest file, the shape `cosign verify-blob --bundle manifest.sig.json ... manifest.json` reads, and `verify` applies the rules of that command. The tests check it with sigstore-go, and with `cosign verify-blob` for each key type when `cosign` is on the path.

**The signature file is not part of the snapshot.** It is not in the manifest's table list and not in the snapshot id, so adding, replacing or editing it cannot change the id, and `snapshot build` of the same rows still gives the same snapshot. A snapshot that is signed later is the same snapshot.

`snapshot sign` verifies the snapshot first and refuses one that does not verify. It refuses to replace a signature unless you pass `--force`.

## Signing with a key

`--key FILE` takes a private key file: an ECDSA key (P-256, P-384 or P-521), an Ed25519 key or an RSA key (2048, 3072 or 4096 bits) as PEM, in PKCS #8 form (or SEC 1 for ECDSA, PKCS #1 for RSA), or the encrypted key `cosign generate-key-pair` writes. An encrypted key's password is read from the environment variable `COSIGN_PASSWORD` (as cosign reads it); no flag takes a secret. The bundle holds the signature and a hint of the public key, with no certificate and no transparency log entry, and nothing leaves the machine.

```sh
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing.key
openssl pkey -in signing.key -pubout -out signing.pub
infra-ontology snapshot sign --key signing.key <snapshot-dir>
```

Each key type is signed the way `cosign verify-blob` checks it: ECDSA over the SHA-256 (P-256), SHA-384 (P-384) or SHA-512 (P-521) digest, RSA with PKCS #1 v1.5 over SHA-256, and Ed25519 over the manifest itself (the bundle still records the manifest's SHA-256 digest). A key of another size or type is refused, and nothing is written.

## Signing keyless

`--keyless` needs no key. The command takes an OIDC token, makes a key pair that lives in memory for this one signature, asks Fulcio (the public-good Sigstore certificate authority) for a short-lived certificate issued to the token's identity, signs, and records the signature in Rekor. The bundle holds the certificate, the log entry and a signed timestamp. The key is then gone.

The token comes from:

- a GitHub Actions job: give the job `permissions: id-token: write` and the command asks the job's token endpoint (`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which the runner sets) for a token with the audience `sigstore`;
- or the environment variable `SIGSTORE_ID_TOKEN`, as cosign reads it, for another CI system that issues an OIDC token Fulcio accepts.

```yaml
permissions:
  contents: read
  id-token: write
steps:
  - run: infra-ontology snapshot build --state s3://bucket/prefix --out snapshots
  - run: infra-ontology snapshot sign --keyless snapshots/*/
```

Keyless signing needs the network: it fetches the Sigstore signing configuration and trusted root over TUF (cached under `~/.sigstore`), then calls Fulcio, Rekor and the timestamp authority the configuration names. It is the only command that opens a connection other than to a backend you name, and it does so only when you pass `--keyless`. Only the public-good instance is supported.

The certificate carries the job's identity, for example the workflow file and ref of a GitHub Actions run, and the log is public: anyone can see that this identity signed this manifest digest. The snapshot itself is never uploaded; only the manifest's digest is.

## What CI proves

The [Keyless signing](../.github/workflows/keyless-signing.yml) workflow runs the whole keyless path on every push to main and on every pull request from this repository (not from forks or Dependabot, whose tokens cannot ask for an OIDC identity). In a GitHub Actions job with `id-token: write` it builds the `noduckdb` binary and a snapshot from a fixture state, signs it with `snapshot sign --keyless` against the public-good Fulcio and Rekor, and then checks the bundle twice:

- with `snapshot verify --require-signature`, pinning `--certificate-identity` to this repository's workflow file at the ref of the run (`https://github.com/hibiscus-ctrl/infra-ontology/.github/workflows/keyless-signing.yml@refs/heads/main` on a push, `...@refs/pull/N/merge` on a pull request) and `--certificate-oidc-issuer` to `https://token.actions.githubusercontent.com`;
- with `cosign verify-blob --bundle manifest.sig.json` and the same identity and issuer.

A third step checks that the same bundle does not verify against another workflow file as the identity. So CI shows that a bundle this tool writes keyless is accepted by cosign, that the certificate carries the workflow identity and the Actions issuer, and that the tool's own verifier enforces the identity pin. It does not check a signature from a release build or a forked run, and it runs with the live Sigstore services, so an outage of Fulcio or Rekor fails the job.

## Verifying

`verify` (and `snapshot verify`) checks the signature when there is one:

| Snapshot | Result |
| --- | --- |
| No `manifest.sig.json`, and no `--key` or identity given | Reported as `unsigned`. Verification passes. |
| No `manifest.sig.json`, and a `--key` or an identity given | `FAILED`, exit 4: what you trust did not sign it. |
| A signature, and no `--key` or identity given | Reported as `signed (unverified)`. It reads as a Sigstore bundle; it was not checked. Passes. |
| A signature, and it checks against what you gave | Reported as `verified`, with the key's SHA-256 or the certificate's identity and issuer. Passes. |
| A signature that does not check (wrong key or identity, a changed manifest, an edited bundle), or a file that is not a bundle | `FAILED`, exit 4. |
| `--require-signature`, and no signature that verified | `FAILED`, exit 4. It needs `--key` or an identity to check with, or it is a usage error (exit 2). |

**What you give is what you trust.** A `--key` or an identity (`--certificate-identity` or its regexp form, with an issuer) is a statement that this snapshot must be signed by it, so an unsigned snapshot fails on its own, with or without `--require-signature`. The flag is kept, and it adds nothing a key or an identity does not already say; it is the one that turns a missing signature into a failure when you have nothing to check with, and then the command refuses as a usage error rather than pass. Without any of these flags nothing is checked, and an unsigned snapshot passes. The same holds for `query`, `verify --answer` and `serve-mcp`.

**With a key.** `--key PUBKEY` takes the PEM public key (`cosign.pub`). It works offline.

**Keyless.** `--certificate-identity` (or `--certificate-identity-regexp`) and `--certificate-oidc-issuer` (or `--certificate-oidc-issuer-regexp`) are required together, with the rules of `cosign verify-blob`: the certificate's subject alternative name and its OIDC issuer must match, and an exact value must be the whole value. The certificate must chain to the trusted root, carry a signed certificate timestamp, have a Rekor entry, and have been valid at the time it was logged. The trusted root is fetched with TUF; `--trusted-root FILE` takes a `trusted_root.json` instead (for example from `cosign trusted-root create`, or the public-good root saved from a connected machine), so the check runs offline.

A key signature does not pass a keyless check and the reverse: `--key` requires a bundle signed by a key and an identity requires one signed by a certificate.

`--json` adds a `signature` object (`status`, `mode`, `signer`, `problem`) to the result. `status` is `unsigned`, `signed_unverified`, `verified` or `invalid`.

## In the MCP server

`serve-mcp` takes the same flags (`--key`, `--certificate-identity`, `--certificate-oidc-issuer`, `--trusted-root`, `--require-signature`). The `snapshot_info` tool and the server's instructions report the signature status: `unsigned`, `signed_unverified`, or `verified` with its signer when the server was started with something to check it with. A signature that does not check, or a signature file that is not a bundle, stops the server from starting (exit 4), as a snapshot that does not verify does; so does a snapshot with no verified signature when a `--key` or an identity was given, or `--require-signature`. The status is read once, at start-up, with the snapshot.

## What is read once

`verify`, `snapshot sign`, `query` and `serve-mcp` read each file once: the signature is checked, or made, over the very bytes whose id and table hashes were verified, so the manifest cannot be swapped between the two checks. The query engine does not read the snapshot folder again either: the bytes that were hashed are written to a private folder (made by the process, readable by its user alone), the engine loads its tables from there, and the folder is deleted when the session has them. A file swapped into the snapshot folder after the hashing is never served, and the manifest an answer cites is the manifest that was served.

## What a signature does not say

A valid signature says the holder of that key, or that CI identity, signed this exact manifest. It does not say the snapshot is complete or true: a signed snapshot can still be `partial` (read its `status` and `limits`), and it describes the estate at the time it was built. Check the signer against an identity you expect, not only that some signature verified.

## Size of the build

Signing uses [sigstore-go](https://github.com/sigstore/sigstore-go) (Apache-2.0, pure Go, no cgo), so every build has it, including the `_noquery` ones. It adds about 6 MB to the release flavour of those (with the four state stores) and about 12 MB to a build without the stores, and brings in the Sigstore client libraries (about 400 more Go packages). The release workflow builds every platform with it.
