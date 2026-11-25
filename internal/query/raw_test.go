// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noduckdb

package query

import "context"

// Raw runs text with no dialect check, so the tests can prove what the engine
// lock refuses on its own. It exists only in test builds.
func (s *session) Raw(ctx context.Context, q string) error {
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
	}
	return rows.Err()
}
