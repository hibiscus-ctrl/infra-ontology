// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"encoding/json"
	"math"
	"math/big"
	"reflect"
	"testing"
	"time"
)

type stringer struct{}

func (stringer) String() string { return "s" }

func TestNormalise(t *testing.T) {
	when := time.Date(2026, 11, 25, 10, 0, 0, 5, time.FixedZone("x", 3600))
	cases := []struct{ in, want any }{
		{nil, nil},
		{"a", "a"},
		{true, true},
		{int8(-3), int64(-3)},
		{uint8(3), int64(3)},
		{uint64(math.MaxUint64), "18446744073709551615"},
		{float32(1.5), 1.5},
		{math.NaN(), "NaN"},
		{math.Inf(1), "Infinity"},
		{math.Inf(-1), "-Infinity"},
		{big.NewInt(1 << 62), "4611686018427387904"},
		{when, "2026-11-25T09:00:00.000000005Z"},
		{[]byte{0xde, 0xad}, "dead"},
		{[]any{int32(1), "a", nil}, []any{int64(1), "a", nil}},
		{map[string]any{"k": int16(2)}, map[string]any{"k": int64(2)}},
		{map[any]any{"k": int16(2)}, map[string]any{"k": int64(2)}},
		{stringer{}, "s"},
		{struct{ A int }{1}, "{1}"},
	}
	for _, c := range cases {
		got := Normalise(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Normalise(%#v) = %#v, want %#v", c.in, got, c.want)
		}
		if _, err := json.Marshal(got); err != nil {
			t.Errorf("Normalise(%#v) is not JSON: %v", c.in, err)
		}
	}
}

func TestResultHash(t *testing.T) {
	cols := []string{"a", "b"}
	rows := [][]any{{int64(1), "x"}, {int64(2), nil}}
	rev := [][]any{rows[1], rows[0]}
	h := func(c []string, r [][]any, ordered bool) string {
		t.Helper()
		got, err := ResultHash(c, r, ordered)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if h(cols, rows, true) == h(cols, rev, true) {
		t.Error("an ordered result ignores the order")
	}
	if h(cols, rows, false) != h(cols, rev, false) {
		t.Error("an unordered result depends on the order")
	}
	if h(cols, rows, false) == h([]string{"a", "c"}, rows, false) {
		t.Error("the column names are not in the hash")
	}
	if h(cols, rows, true) == h(cols, rows[:1], true) {
		t.Error("the rows are not in the hash")
	}
	if h(cols, [][]any{{"a,b"}}, true) == h(cols, [][]any{{"a", "b"}}, true) {
		t.Error("two rows hash like one")
	}
}

func TestCapsDefaultsAndLimits(t *testing.T) {
	c := Caps{}.WithDefaults()
	if c.MaxRows != 1000 || c.MaxCols != 64 || c.MaxBytes != 4<<20 || c.Timeout != 10*time.Second {
		t.Errorf("defaults %+v", c)
	}
	c = Caps{MaxRows: 1 << 30, MaxCols: 1 << 20, MaxBytes: 1 << 40, Timeout: time.Hour}.WithDefaults()
	if c.MaxRows != 10000 || c.MaxCols != 64 || c.MaxBytes != 64<<20 || c.Timeout != 5*time.Minute {
		t.Errorf("limits %+v", c)
	}
	if c = (Caps{MaxRows: 5, MaxCols: 3}).WithDefaults(); c.MaxRows != 5 || c.MaxCols != 3 {
		t.Errorf("lower caps %+v", c)
	}
}
