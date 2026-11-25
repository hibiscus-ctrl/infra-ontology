// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"slices"
	"sort"
	"time"
)

// Normalise turns a value a database driver returned into a JSON-shaped one:
// nil, bool, int64, float64, string, []any or map[string]any. The same data
// always gives the same value, which is what makes the hash of a result mean
// something.
func Normalise(v any) any {
	switch t := v.(type) {
	case nil, bool, string:
		return t
	case int:
		return int64(t)
	case int8:
		return int64(t)
	case int16:
		return int64(t)
	case int32:
		return int64(t)
	case int64:
		return t
	case uint:
		return unsigned(uint64(t))
	case uint8:
		return int64(t)
	case uint16:
		return int64(t)
	case uint32:
		return int64(t)
	case uint64:
		return unsigned(t)
	case float32:
		return float(float64(t))
	case float64:
		return float(t)
	case *big.Int:
		if t == nil {
			return nil
		}
		return t.String()
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano)
	case []byte:
		return hex.EncodeToString(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Normalise(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = Normalise(e)
		}
		return out
	case map[any]any: // a MAP column
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[fmt.Sprint(Normalise(k))] = Normalise(e)
		}
		return out
	case fmt.Stringer: // decimals, UUIDs, intervals
		return t.String()
	}
	return fmt.Sprint(v)
}

func unsigned(u uint64) any {
	if u > math.MaxInt64 {
		return fmt.Sprint(u)
	}
	return int64(u)
}

// float keeps a finite float as it is and writes NaN and the infinities as
// text, which JSON has no number for.
func float(f float64) any {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return f
}

// ResultHash is the SHA-256 of a result in a canonical form: the column names
// as a JSON array, then each row as a JSON array, one to a line. If the query
// has no ORDER BY of its own the rows are first sorted by their encoding, so
// the order the engine happened to return them in does not change the hash.
func ResultHash(columns []string, rows [][]any, ordered bool) (string, error) {
	lines := make([]string, len(rows))
	for i, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return "", fmt.Errorf("hash the result: %w", err)
		}
		lines[i] = string(b)
	}
	if !ordered {
		sort.Strings(lines)
	}
	cols, err := json.Marshal(slices.Clone(columns))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(cols)
	h.Write([]byte{'\n'})
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// HashQuery is the SHA-256 of a canonical query.
func HashQuery(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}
