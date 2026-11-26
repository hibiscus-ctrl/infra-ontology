# Contributing

Thank you for helping. The project is at its very start, so this page is short: the process, and the checks a change passes.

## Workflow

- Branch from `main` and open the pull request against it.
- Name the branch after the change's type: `fix/state-parse`, `feat/snapshot-verify`, `docs/architecture`.
- Keep pull requests focused: one logical change each. A bug fix includes a test that fails without the fix.
- Pull requests are squash-merged, so the title becomes the commit on `main`: write it as a [Conventional Commit](https://www.conventionalcommits.org/), for example `feat(snapshot): write a manifest` or `fix(state): read version 4 dependencies`. Types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `ci`, `build`, `chore`, `revert`.
- Say in the description what changes and why, and how you tested it.
- A pull request merges once every check is green, the [CLA](#contributor-license-agreement) check included.

## Contributor License Agreement

Contributions are accepted under the [Contributor License Agreement](CLA.md). infra-ontology is AGPL-3.0-only with a commercial licence offered alongside it, and that only works if every contribution can be relicensed, which is the right the CLA grants.

The `cla` workflow asks on your first pull request: comment

> I have read the CLA Document and I hereby sign the CLA

once, and it covers all your later pull requests.

## Setting up

You need Git and Go (the version in `go.mod`). The query engine (DuckDB) needs cgo, so keep a C and C++ compiler installed; `go test -tags noduckdb ./...` runs everything that does not need it.

```sh
make fast         # formatting, vet, names, licences and workflows
make test         # go test -race
make lint         # golangci-lint, with the repository's config
make golden       # rewrite the golden files (go test -update); review the diff
make schemas      # every schema validates what the code writes
```

`make fast` uses [reuse](https://reuse.software/) and [actionlint](https://github.com/rhysd/actionlint) when they are installed. CI runs every check anyway, on each pull request.

## Checking the cgo build

The query engine links DuckDB through cgo, so a change can pass `go test -tags noduckdb ./...` and still break the build with the engine. `make spike` is the check on your machine:

```sh
make spike
```

It builds `./infra-ontology` with `CGO_ENABLED=1`, runs `go test ./internal/query/...`, and lists the shared libraries the binary links. On Linux that list goes through `scripts/check-ldd.sh`, which fails if a library is missing or not one it expects (libstdc++, libgcc_s and glibc). On other systems it prints `otool -L`.

CI runs the same check across a matrix. In `.github/workflows/test.yml`, the `test` job runs on `ubuntu-latest`, `ubuntu-24.04-arm` and `macos-latest` with `CGO_ENABLED=1`: it builds, vets, runs `go test -race ./...` and, on Linux, runs `scripts/check-ldd.sh`. The `noduckdb` job builds and tests with `-tags noduckdb` and no C toolchain, and cross-builds every release platform. Run `make test TAGS=noduckdb` to try that build locally. Windows is built by the release workflow, not by this matrix.

## Adding a node kind or an edge kind

Kinds are strings in the snapshot tables. Within a major version a change may add kinds, as [docs/snapshot-format.md](docs/snapshot-format.md#versioning) says. A node kind is a closed list that the schema and `Validate` both check. An edge kind is open: `Validate` and the schema only require a lower-case code, so a new edge kind needs no schema edit.

To add a node kind:

1. `internal/snapshot/types.go`: add a `Kind...` constant next to `KindResource`.
2. `internal/snapshot/validate.go`: add it to `nodeKinds`.
3. `schemas/node-v1.schema.json`: add it to the `kind` enum.
4. `internal/ingest`: make the node where it comes from, as `state.go` does for `state_root`, `module_call` and `external`. If the node must change when IDs are hashed, see the kind checks in `hash.go`.
5. `internal/export/graph.go`: decide whether the graph export draws it. Today only `resource` and `module_call` nodes are exported, and the rest are counted as left out. Say which in [docs/export.md](docs/export.md).
6. [docs/snapshot-format.md](docs/snapshot-format.md): add it to the list of kinds in the `nodes` entry, and to the page of the source that makes it ([docs/state.md](docs/state.md) or [docs/inventory.md](docs/inventory.md)).

To add an edge kind:

1. `internal/snapshot/types.go`: add an `Edge...` constant to the edge kinds.
2. `internal/ingest`: call `addEdge` with the kind, a basis code and a confidence. A basis is a constant next to the others, such as `BasisStateDependency` in `state.go` and `BasisResourcePath` in `inventory_build.go`.
3. `internal/export/graph.go`: the export draws `depends_on` and a resource's `contained_in` a module call, and counts every other kind as left out. Change `edges` only if the new kind should be drawn, and update [docs/export.md](docs/export.md).
4. `schemas/edge-v1.schema.json`: update the `kind` description, which lists the kinds written. Do the same for a new `basis` code.
5. Docs: the list of kinds in [docs/snapshot-format.md](docs/snapshot-format.md) and [docs/architecture.md](docs/architecture.md), and the page of the source that writes the edge.

For either kind:

- Add a test that makes the kind from a fixture and checks it, as `hasEdge` does in `internal/ingest/state_test.go`. `internal/snapshot/estate_test.go` builds the sample estate the snapshot golden files come from, so add the kind there if the golden files should hold it.
- Run `make golden` and review the diff. It rewrites the golden files of `internal/snapshot`, `internal/ingest`, `internal/export` and `internal/query`, under each package's `testdata/`, including `internal/snapshot/testdata/estate.json`. Do not edit a golden file by hand.
- Run `make schemas`, which checks every schema compiles and validates what the code writes.
- If the change adds a kind, consider raising `FormatMinor` in `internal/snapshot/types.go`: the format page says `format_minor` counts the additions. The manifest golden files record it, so `make golden` updates them.

## Rules for the code

- Every Go file starts with the licence header:

  ```go
  // Copyright 2026 Gabriel Ignat
  // SPDX-License-Identifier: AGPL-3.0-only
  ```

  Files that can't take a comment are covered by `REUSE.toml`. The JSON Schemas under `schemas/` are Apache-2.0.
- The red lines in [AGENTS.md](AGENTS.md) hold for every change: no secret values stored, read-only, the user's own credentials, no writes to the cloud. A change that breaks one doesn't merge.
- Pin every GitHub Action by its full commit SHA, with the version in a comment, and give a workflow `permissions: contents: read` unless a job needs more.
- Keep the public text of the repository free of the names `scripts/check-names.sh` lists.

## Reporting problems

Open an issue for a bug or an idea. Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) says.
