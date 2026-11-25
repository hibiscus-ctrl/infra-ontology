# Copyright 2026 Gabriel Ignat
# SPDX-License-Identifier: AGPL-3.0-only

# Run `make help` for the targets. PKG narrows go test, go vet and the linter
# to some packages, for example `make test PKG=./cmd/...`.
PKG ?= ./...
GOLANGCI_LINT_VERSION := v2.15.0

.PHONY: help build test vet lint fmt fast
.DEFAULT_GOAL := help

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

build: ## Build the command into ./infra-ontology
	go build -o infra-ontology ./cmd/infra-ontology

test: ## go test with the race detector on PKG
	CGO_ENABLED=1 go test -race $(PKG)

vet: ## go vet on PKG
	go vet $(PKG)

lint: ## golangci-lint on PKG (CI runs $(GOLANGCI_LINT_VERSION))
	golangci-lint run --config .golangci.json $(PKG)

fmt: ## Format the Go code
	gofmt -s -w .

fast: ## Every fast check: formatting, vet, names, licences, workflows
	@test -z "$$(gofmt -s -l .)" || { echo "gofmt: run make fmt"; gofmt -s -l .; exit 1; }
	go vet ./...
	scripts/check-names.sh
	reuse lint -q
	actionlint
