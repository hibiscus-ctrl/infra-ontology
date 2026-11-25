// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package query

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/hibiscus-ctrl/infra-ontology/queries"
)

// Param is a parameter of a stored query, from a header line of its file:
//
//	-- param: <name> <string|int|int[lo..hi]> <default|required|-> <description>
//
// A "-" default is the empty string, for an optional filter.
type Param struct {
	Name        string
	Type        string // "string" or "int"
	Min, Max    int    // the range of an int
	Default     string
	Required    bool
	Description string
}

// Stored is a named, versioned SQL file compiled into the binary. Its text has
// {{name}} where a parameter goes; Render fills them in, and the result goes
// through the same dialect check as any other query.
type Stored struct {
	Name        string
	Version     int
	Description string
	Params      []Param
	Hash        string // sha256: of the file
	template    string
}

var placeholder = regexp.MustCompile(`\{\{([a-z][a-z0-9_]*)\}\}`)

// StoredQueries reads the embedded files, sorted by name.
func StoredQueries() ([]Stored, error) { return loadStored(queries.FS) }

// StoredQuery finds a stored query by name.
func StoredQuery(name string) (Stored, error) {
	all, err := StoredQueries()
	if err != nil {
		return Stored{}, err
	}
	for _, s := range all {
		if s.Name == name {
			return s, nil
		}
	}
	names := make([]string, len(all))
	for i, s := range all {
		names[i] = s.Name
	}
	return Stored{}, fmt.Errorf("no stored query %q: there are %s", name, strings.Join(names, ", "))
}

func loadStored(fsys fs.FS) ([]Stored, error) {
	files, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	var out []Stored
	for _, f := range files {
		raw, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		s, err := parseStored(string(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if f != s.Name+".sql" {
			return nil, fmt.Errorf("%s: the file is named for %q", f, s.Name)
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Stored) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func parseStored(text string) (Stored, error) {
	sum := sha256.Sum256([]byte(text))
	s := Stored{Hash: "sha256:" + hex.EncodeToString(sum[:])}
	lines := strings.Split(text, "\n")
	body := 0
	for ; body < len(lines) && strings.HasPrefix(lines[body], "--"); body++ {
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(lines[body], "--")), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "name":
			s.Name = value
		case "version":
			v, err := strconv.Atoi(value)
			if err != nil || v < 1 {
				return s, fmt.Errorf("version %q is not a positive number", value)
			}
			s.Version = v
		case "description":
			s.Description = value
		case "param":
			p, err := parseParam(value)
			if err != nil {
				return s, err
			}
			s.Params = append(s.Params, p)
		}
	}
	s.template = strings.TrimSpace(strings.Join(lines[body:], "\n"))
	switch {
	case s.Name == "" || s.Version == 0 || s.Description == "":
		return s, fmt.Errorf("the header needs a name, a version and a description")
	case s.template == "":
		return s, fmt.Errorf("no query text")
	}
	declared := map[string]bool{}
	for _, p := range s.Params {
		if declared[p.Name] {
			return s, fmt.Errorf("parameter %q is declared twice", p.Name)
		}
		declared[p.Name] = true
	}
	used := map[string]bool{}
	for _, m := range placeholder.FindAllStringSubmatch(s.template, -1) {
		if !declared[m[1]] {
			return s, fmt.Errorf("{{%s}} is not a declared parameter", m[1])
		}
		used[m[1]] = true
	}
	for name := range declared {
		if !used[name] {
			return s, fmt.Errorf("parameter %q is never used", name)
		}
	}
	return s, nil
}

var intType = regexp.MustCompile(`^int(?:\[(\d+)\.\.(\d+)\])?$`)

func parseParam(value string) (Param, error) {
	f := strings.Fields(value)
	if len(f) < 4 {
		return Param{}, fmt.Errorf("param %q: want <name> <type> <default|required|-> <description>", value)
	}
	p := Param{Name: f[0], Type: f[1], Description: strings.Join(f[3:], " ")}
	if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(p.Name) {
		return p, fmt.Errorf("param name %q is not lower-case letters, digits and underscores", p.Name)
	}
	switch m := intType.FindStringSubmatch(f[1]); {
	case f[1] == "string":
	case m != nil:
		p.Type, p.Min, p.Max = "int", 0, 1_000_000
		if m[1] != "" {
			p.Min, _ = strconv.Atoi(m[1])
			p.Max, _ = strconv.Atoi(m[2])
		}
	default:
		return p, fmt.Errorf("param %s: type %q is not string or int", p.Name, f[1])
	}
	switch f[2] {
	case "required":
		p.Required = true
	case "-":
	default:
		p.Default = f[2]
		if p.Type == "int" {
			if _, err := p.render(f[2]); err != nil {
				return p, fmt.Errorf("param %s: default: %w", p.Name, err)
			}
		}
	}
	return p, nil
}

// render turns a parameter's value into SQL text: an integer in its range, or
// a string as a quoted literal.
func (p Param) render(value string) (string, error) {
	if p.Type == "int" {
		n, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(n) != value {
			return "", fmt.Errorf("%s: %q is not a whole number", p.Name, value)
		}
		if n < p.Min || n > p.Max {
			return "", fmt.Errorf("%s: %d is outside %d to %d", p.Name, n, p.Min, p.Max)
		}
		return value, nil
	}
	if len(value) > 1024 {
		return "", fmt.Errorf("%s: longer than 1024 bytes", p.Name)
	}
	if strings.ContainsFunc(value, unicode.IsControl) {
		return "", fmt.Errorf("%s: contains a control character", p.Name)
	}
	return lit(value), nil
}

// Render fills in the parameters: the SQL text, and the values used with
// defaults included, for the citation. An unknown parameter, a missing
// required one, or a value out of range is an error.
func (s Stored) Render(values map[string]string) (sqlText string, used map[string]string, err error) {
	byName := map[string]Param{}
	for _, p := range s.Params {
		byName[p.Name] = p
	}
	for name := range values {
		if _, ok := byName[name]; !ok {
			return "", nil, fmt.Errorf("stored query %s has no parameter %q", s.Name, name)
		}
	}
	used = map[string]string{}
	rendered := map[string]string{}
	for _, p := range s.Params {
		v, given := values[p.Name]
		if !given {
			if p.Required {
				return "", nil, fmt.Errorf("stored query %s needs --param %s=<value>: %s", s.Name, p.Name, p.Description)
			}
			v = p.Default
		}
		r, err := p.render(v)
		if err != nil {
			return "", nil, fmt.Errorf("stored query %s: %w", s.Name, err)
		}
		used[p.Name], rendered[p.Name] = v, r
	}
	text := placeholder.ReplaceAllStringFunc(s.template, func(m string) string {
		return rendered[m[2:len(m)-2]]
	})
	return text, used, nil
}

// lit writes a string as an SQL literal.
func lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
