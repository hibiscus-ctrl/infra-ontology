// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

//go:build noduckdb

package query

import (
	"context"
	"errors"
	"testing"
)

func TestTheBuildWithoutTheEngineSaysSo(t *testing.T) {
	s, err := New().Open(context.Background(), "anywhere", Options{})
	if s != nil || !errors.Is(err, ErrUnavailable) {
		t.Errorf("Open = %v, %v; want ErrUnavailable", s, err)
	}
	if New().Name() != "none" {
		t.Errorf("name %q", New().Name())
	}
}
