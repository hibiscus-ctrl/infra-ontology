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
