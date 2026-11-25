// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import "strings"

// splitTop splits an address at the dots that are not inside an index: in
// module.a["x.y"].aws_vpc.main[0] the dot of "x.y" is not a separator.
func splitTop(addr string) []string {
	var parts []string
	depth, start := 0, 0
	inQuote := false
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		switch {
		case inQuote:
			switch c {
			case '\\':
				i++
			case '"':
				inQuote = false
			}
		case c == '"':
			inQuote = true
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '.' && depth == 0:
			parts = append(parts, addr[start:i])
			start = i + 1
		}
	}
	return append(parts, addr[start:])
}

// moduleCalls returns the module calls on a module path, outermost first,
// each as its full address: module.a["x"].module.b gives module.a["x"] and
// module.a["x"].module.b.
func moduleCalls(module string) []string {
	if module == "" {
		return nil
	}
	parts := splitTop(module)
	var calls []string
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] != "module" {
			break
		}
		calls = append(calls, strings.Join(parts[:i+2], "."))
	}
	return calls
}

// callName is the last module call's name, with its index: a["x"].
func callName(call string) string {
	parts := splitTop(call)
	return parts[len(parts)-1]
}

// keyless removes the instance keys from an address: module.a["x"].aws_vpc.b[0]
// becomes module.a.aws_vpc.b, which is how a state records a dependency.
func keyless(addr string) string {
	var b strings.Builder
	depth := 0
	inQuote := false
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		switch {
		case inQuote:
			switch c {
			case '\\':
				i++
			case '"':
				inQuote = false
			}
		case c == '"' && depth > 0:
			inQuote = true
		case c == '[':
			depth++
		case c == ']':
			depth--
		case depth == 0:
			b.WriteByte(c)
		}
	}
	return b.String()
}
