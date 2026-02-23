// Copyright 2026 Jip de Beer (Jip-Hop) and Ojster contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package env

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ojster/ojster/internal/util/file"
)

// KeyNameRegex is the canonical regexp for valid environment key names.
var KeyNameRegex = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// UpdateEnvFile replaces or appends KEY=VALUE in path. VALUE should be the raw value
// (no surrounding quotes). If VALUE contains newlines, it will be written as a
// single-quoted multiline value unless it contains single quotes or ends with a newline,
// in which case a double-quoted escaped form is used. The function preserves comments and other lines.
func UpdateEnvFile(path, key, value string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Read existing file if present
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		// Split into lines preserving trailing newline semantics
		scanner := bufio.NewScanner(bytes.NewReader(b))
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Parser helpers
	keyRe := regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*([:=])\s*(.*)$`)

	// Walk lines and detect existing key (taking multi-line single-quoted values into account)
	outLines := make([]string, 0, len(lines)+2)
	found := false
	i := 0
	for i < len(lines) {
		line := lines[i]

		// If comment or blank, copy as-is
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			outLines = append(outLines, line)
			i++
			continue
		}

		// Try to match key line
		m := keyRe.FindStringSubmatch(line)
		if m == nil {
			// Not a key-value line, copy as-is
			outLines = append(outLines, line)
			i++
			continue
		}

		k := m[1]
		rawVal := m[3]

		// If this key is the one we want to replace, consume the whole value (including multi-line single-quoted)
		if k == key {
			found = true

			rawTrim := strings.TrimLeft(rawVal, " \t")
			// Detect single-quoted multi-line: starts with ' and does not end with ' (after trimming trailing spaces)
			if strings.HasPrefix(rawTrim, "'") && !strings.HasSuffix(strings.TrimRight(rawTrim, " \t"), "'") {
				// multi-line single-quoted: consume until a line that ends with a single quote
				j := i + 1
				for j < len(lines) {
					if strings.HasSuffix(lines[j], "'") {
						j++
						break
					}
					j++
				}
				// skip original key block by advancing i to j
				i = j
			} else {
				// single-line value: just skip this line
				i++
			}

			// Append replacement entry (formatted)
			outLines = append(outLines, FormatEnvEntry(key, value))
			// continue without copying original block
			continue
		}

		// Not the key we want, copy original line (and if it was a multi-line single-quoted value, copy the whole block)
		outLines = append(outLines, line)
		rawTrim := strings.TrimLeft(rawVal, " \t")
		if strings.HasPrefix(rawTrim, "'") && !strings.HasSuffix(strings.TrimRight(rawTrim, " \t"), "'") {
			j := i + 1
			for j < len(lines) {
				outLines = append(outLines, lines[j])
				if strings.HasSuffix(lines[j], "'") {
					j++
					break
				}
				j++
			}
			i = j
		} else {
			i++
		}
	}

	// If not found, append new entry (do not insert an extra blank line)
	if !found {
		outLines = append(outLines, FormatEnvEntry(key, value))
	}

	// Join lines with newline and ensure trailing newline
	var buf bytes.Buffer
	for _, l := range outLines {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}

	// Atomically write file
	return file.WriteFileAtomic(path, buf.Bytes(), 0o644)
}

// FormatEnvEntry formats key and value according to Docker env rules.
// If value contains newline, write as single-quoted multiline block unless the value
// contains single quotes or ends with a newline, in which case use double-quoted escaped form.
// Otherwise, if value contains spaces or # or quotes or control characters, write as double-quoted with escapes.
// For simplicity, prefer single-quote for literal values without interpolation.
func FormatEnvEntry(key, value string) string {
	if strings.Contains(value, "\n") {
		// If value contains single quote or ends with a newline, use double-quoted escaped form
		if strings.Contains(value, "'") || strings.HasSuffix(value, "\n") {
			return fmt.Sprintf("%s=\"%s\"", key, escapeDoubleQuoted(value))
		}
		// single-quoted multiline (closing quote stays on same line)
		return fmt.Sprintf("%s='%s'", key, value)
	}

	// single-line value
	// If value is empty, write as KEY=
	if value == "" {
		return fmt.Sprintf("%s=", key)
	}

	// If value contains spaces, #, quotes, backslash, or control characters like tab/carriage return, use double quotes and escape
	if strings.ContainsAny(value, " #\"'\\\t\r") {
		return fmt.Sprintf("%s=\"%s\"", key, escapeDoubleQuoted(value))
	}

	// safe unquoted
	return fmt.Sprintf("%s=%s", key, value)
}

func escapeDoubleQuoted(s string) string {
	// escape backslash, double quote, and common sequences \n \r \t
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ParseEnvFile reads the env file and returns a map of key -> logical value.
// It understands Docker-style env syntax including single-quoted multiline values.
// The returned values are the logical unquoted/unescaped values.
func ParseEnvFile(path string) (map[string]string, error) {
	out := make(map[string]string)

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return parseLines(lines)
}

// ParseEnvReader parses environment entries from any io.Reader and returns the map.
// This is a full replacement for in-memory parsing helpers used in tests.
func ParseEnvReader(r io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(r)
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return parseLines(lines)
}

// ParseEnvString parses environment entries from a string and returns the map.
func ParseEnvString(s string) (map[string]string, error) {
	scanner := bufio.NewScanner(strings.NewReader(s))
	lines := make([]string, 0)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return parseLines(lines)
}

// parseLines contains the core parsing logic shared by file/reader/string entry points.
func parseLines(lines []string) (map[string]string, error) {
	out := make(map[string]string)
	keyRe := regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*([:=])\s*(.*)$`)

	i := 0
	for i < len(lines) {
		line := lines[i]
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			i++
			continue
		}
		m := keyRe.FindStringSubmatch(line)
		if m == nil {
			i++
			continue
		}
		k := m[1]
		rawVal := m[3]

		rawTrim := strings.TrimLeft(rawVal, " \t")
		// Single-quoted multiline
		if strings.HasPrefix(rawTrim, "'") && !strings.HasSuffix(strings.TrimRight(rawTrim, " \t"), "'") {
			first := rawTrim[1:]
			var parts []string
			parts = append(parts, first)
			j := i + 1
			foundEnd := false
			for j < len(lines) {
				linej := lines[j]
				// If this line looks like a new key, stop consuming — treat the block as malformed but do not swallow the next key.
				if keyRe.MatchString(linej) {
					break
				}
				if before, ok := strings.CutSuffix(linej, "'"); ok {
					parts = append(parts, before)
					foundEnd = true
					j++
					break
				}
				parts = append(parts, linej)
				j++
			}
			if !foundEnd {
				// malformed: take what we have (do not consume the next key line)
				out[k] = strings.Join(parts, "\n")
				i = j
				continue
			}
			out[k] = strings.Join(parts, "\n")
			i = j
			continue
		}

		// Single-line (could be single-quoted, double-quoted, or unquoted)
		trimmed := strings.TrimSpace(rawVal)
		if trimmed == "" {
			out[k] = ""
			i++
			continue
		}
		// Double-quoted
		if strings.HasPrefix(trimmed, "\"") {
			var sb strings.Builder
			escaped := false
			for idx := 1; idx < len(trimmed); idx++ {
				c := trimmed[idx]
				if escaped {
					switch c {
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case 't':
						sb.WriteByte('\t')
					case '\\':
						sb.WriteByte('\\')
					case '"':
						sb.WriteByte('"')
					default:
						sb.WriteByte(c)
					}
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					break
				}
				sb.WriteByte(c)
			}
			out[k] = sb.String()
			i++
			continue
		}
		// Single-quoted single-line
		if strings.HasPrefix(trimmed, "'") && strings.HasSuffix(strings.TrimRight(trimmed, " \t"), "'") {
			inner := strings.TrimSpace(trimmed)
			inner = strings.TrimPrefix(inner, "'")
			inner = strings.TrimSuffix(inner, "'")
			// Unescape escaped quotes and backslashes inside single-quoted single-line values
			inner = strings.ReplaceAll(inner, `\'`, `'`)
			inner = strings.ReplaceAll(inner, `\\`, `\`)
			out[k] = inner
			i++
			continue
		}
		// Unquoted: strip inline comment if preceded by space
		if idx := strings.Index(trimmed, " #"); idx != -1 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		// Value is the rest of the trimmed string
		out[k] = trimmed
		i++
	}

	return out, nil
}
