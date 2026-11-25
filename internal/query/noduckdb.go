// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build noduckdb

package query

import "context"

type none struct{}

// New returns the engine of this build: with the noduckdb tag there is none,
// and Open says so.
func New() Engine { return none{} }

func (none) Name() string { return "none" }

func (none) Open(context.Context, string, Options) (Session, error) { return nil, ErrUnavailable }
