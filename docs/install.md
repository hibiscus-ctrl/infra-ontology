# Install

Download an archive from the [releases page](https://github.com/hibiscus-ctrl/infra-ontology/releases), check it, and put `infra-ontology` (`infra-ontology.exe` on Windows) on your path. There is no installer, and the command makes no network call of its own.

## Which archive

The archives are named `infra-ontology_<version>_<os>_<arch>`, `.tar.gz` on Linux, macOS and the BSDs and `.zip` on Windows.

**With the query engine.** `query`, `verify --answer` and `serve-mcp` need the DuckDB engine, which needs cgo, so these are built natively on a runner of their own platform. DuckDB ships prebuilt libraries for five platforms, and these are those five:

| Platform | Archive ends in |
| --- | --- |
| Linux, x86-64 | `_linux_amd64.tar.gz` |
| Linux, Arm64 | `_linux_arm64.tar.gz` |
| macOS, Intel | `_darwin_amd64.tar.gz` |
| macOS, Apple silicon | `_darwin_arm64.tar.gz` |
| Windows, x86-64 | `_windows_amd64.zip` |

They are about 80 MB unpacked.

**Without the query engine.** Every other platform gets a pure-Go build, built with `-tags noduckdb`, whose name ends in `_noquery` before the extension: for example `_linux_386_noquery.tar.gz`, `_linux_riscv64_noquery.tar.gz`, `_freebsd_amd64_noquery.tar.gz` and `_windows_arm64_noquery.zip`. Linux on x86-64 and Arm64 also have a `_noquery` archive, for images that cannot run the full build (below). A `_noquery` binary is about 9 MB. `snapshot build`, `snapshot verify` and `diff` work as usual; `query`, `verify --answer` and `serve-mcp` say that the build has no query engine and print the SQL to run with DuckDB on the snapshot folder.

## What the full Linux build needs

The full Linux binaries link the C++ runtime dynamically: `libstdc++.so.6` and `libgcc_s.so.1`, next to glibc (`libm`, `libc`). They run on a glibc distribution that has libstdc++ installed, and they do not run on `scratch`, distroless-static or Alpine (musl). On Debian or Ubuntu, `libstdc++6` is almost always there already; if `ldd infra-ontology` says `not found`, install it:

```sh
apt-get install libstdc++6          # Debian, Ubuntu
dnf install libstdc++               # Fedora, RHEL, Amazon Linux
```

For a container that cannot carry glibc and libstdc++, use the `_noquery` archive, or a base image that has them (a Debian or Ubuntu slim image, or distroless `cc`, which carries libstdc++). macOS and Windows binaries link what the system provides and need nothing installed.

## Check the download

Each release holds the archives, a checksums file `infra-ontology_<version>_SHA256SUMS`, and its signature `infra-ontology_<version>_SHA256SUMS.sigstore.json`. The release workflow signs the checksums with [cosign](https://github.com/sigstore/cosign) without a key of ours: GitHub gives the workflow a short-lived identity token, Sigstore issues a certificate for that identity, and the signature is logged in a public transparency log. Each archive also has a GitHub [artifact attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) of its build provenance.

Use `<version>` without the `v` in file names and with it in the tag below. This example is for `v1.2.3`.

**1. The checksums file is signed by our release workflow.** This needs cosign 2 or later:

```sh
cosign verify-blob \
  --bundle infra-ontology_1.2.3_SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/hibiscus-ctrl/infra-ontology/.github/workflows/release.yml@refs/tags/v1.2.3 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  infra-ontology_1.2.3_SHA256SUMS
```

It prints `Verified OK`. The identity names the workflow file and the tag it ran for, so a checksums file signed by anything else, or from another tag, fails.

**2. The archive is the one the checksums file lists.**

```sh
sha256sum --ignore-missing --check infra-ontology_1.2.3_SHA256SUMS     # Linux
grep infra-ontology_1.2.3_darwin_arm64.tar.gz infra-ontology_1.2.3_SHA256SUMS | shasum -a 256 -c   # macOS
```

On Windows, compare `(Get-FileHash .\infra-ontology_1.2.3_windows_amd64.zip).Hash` with the line in the checksums file.

**3. The archive was built by that workflow from this repository (optional).** With the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify infra-ontology_1.2.3_linux_amd64.tar.gz \
  --repo hibiscus-ctrl/infra-ontology \
  --signer-workflow hibiscus-ctrl/infra-ontology/.github/workflows/release.yml
```

Then unpack the archive and run `infra-ontology version`. It prints the release's version.

## How a release is built

Pushing a `v*` tag runs `.github/workflows/release.yml`. It builds each full binary on a runner of its own platform (`ubuntu-latest`, `ubuntu-24.04-arm`, `macos-15-intel`, `macos-latest`, `windows-latest` with MinGW-w64), runs it, builds the `_noquery` binaries in pure Go, packs the archives with `scripts/package-release.sh` (sorted, with the commit's timestamp, so the same binaries give the same archives), signs and attests them, and creates a **draft** release. Nothing is published until a maintainer reviews the draft and publishes it. A pull request that touches the release files runs the same build as a trial (`release-check.yml`) and publishes nothing.

To build it yourself, see the [README](../README.md#build).
