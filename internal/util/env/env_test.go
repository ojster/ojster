// Copyright 2026 Jip de Beer (Jip-Hop) and ojster contributers
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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// tmpPath returns a path inside a fresh temp dir for the test.
func tmpPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// writeFile creates a file with given content and 0644 perms.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// readMapOrFail parses the file at path and returns the parsed map (or fails the test).
func readMapOrFail(t *testing.T, path string) map[string]string {
	t.Helper()
	m, err := ParseEnvFile(path)
	if err != nil {
		t.Fatalf("ParseEnvFile(%s) error: %v", path, err)
	}
	return m
}

// TestParseEnvFile_Examples covers the documented .env syntax examples in one compact file.
func TestParseEnvFile_Examples(t *testing.T) {
	content := strings.Join([]string{
		"# comment line should be ignored",
		"",
		// delimiters and spacing
		"VAR1=VAL",
		`VAR2="VAL"`,
		"VAR3='VAL'",
		"VAR4: VAL",
		"VAR5 = VAL",
		"",
		// inline comment rules
		"IC1=VAL # comment after space -> comment removed",
		"IC2=VAL#notacomment",
		`IC3="VAL # not a comment"` + " # trailing comment -> comment removed",
		`IC4="VAL" # comment after closing quote -> comment removed`,
		"",
		// single-quoted literal (no interpolation)
		`LIT1='$OTHER'`,
		`LIT2='${OTHER}'`,
		"",
		// escaped quotes
		`ESC1='Let\'s go!'`,
		`ESC2="{\"hello\": \"json\"}"`,
		"",
		// double-quoted escapes vs single/unquoted literal backslashes
		`DQ1="some\tvalue"`,
		`SQ1='some\tvalue'`,
		`UQ1=some\tvalue`,
		"",
		// single-quoted multiline
		"ML='SOME",
		"VALUE'",
	}, "\n") + "\n"

	path := tmpPath(t, "examples.env")
	writeFile(t, path, content)

	got := readMapOrFail(t, path)

	want := map[string]string{
		"VAR1": "VAL",
		"VAR2": "VAL",
		"VAR3": "VAL",
		"VAR4": "VAL",
		"VAR5": "VAL",

		"IC1": "VAL",
		"IC2": "VAL#notacomment",
		"IC3": "VAL # not a comment",
		"IC4": "VAL",

		"LIT1": "$OTHER",
		"LIT2": "${OTHER}",

		"ESC1": "Let's go!",
		"ESC2": `{"hello": "json"}`,

		"DQ1": "some\tvalue",
		"SQ1": `some\tvalue`,
		"UQ1": `some\tvalue`,

		"ML": "SOME\nVALUE",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseEnvFile mismatch\ngot = %#v\nwant= %#v", got, want)
	}
}

// TestUpdateEnvFile_Roundtrip ensures UpdateEnvFile writes entries in a way that ParseEnvFile reads back the logical values.
func TestUpdateEnvFile_Roundtrip(t *testing.T) {
	initial := strings.Join([]string{
		"# header",
		"KEEP=keepme",
	}, "\n") + "\n"

	path := tmpPath(t, "update.env")
	writeFile(t, path, initial)

	// Replace existing key with a value that needs quoting (space)
	if err := UpdateEnvFile(path, "KEEP", "replaced value"); err != nil {
		t.Fatalf("UpdateEnvFile replace failed: %v", err)
	}

	// Add a key that contains a single quote and newline -> should be double-quoted escaped
	valWithQuoteAndNL := "o'clock\nnext"
	if err := UpdateEnvFile(path, "QNL", valWithQuoteAndNL); err != nil {
		t.Fatalf("UpdateEnvFile QNL failed: %v", err)
	}

	// Add a key that is multiline but safe for single-quote (no single quotes and doesn't end with newline)
	multi := "lineA\nlineB"
	if err := UpdateEnvFile(path, "ML", multi); err != nil {
		t.Fatalf("UpdateEnvFile ML failed: %v", err)
	}

	// Add an empty value
	if err := UpdateEnvFile(path, "EMPTY", ""); err != nil {
		t.Fatalf("UpdateEnvFile EMPTY failed: %v", err)
	}

	got := readMapOrFail(t, path)
	want := map[string]string{
		"KEEP":  "replaced value",
		"QNL":   valWithQuoteAndNL,
		"ML":    multi,
		"EMPTY": "",
	}

	for k, v := range want {
		if got[k] != v {
			t.Fatalf("key %s: want %q got %q", k, v, got[k])
		}
	}
}

// TestFormatEnvEntry_CoversEdgeCases asserts textual forms produced by FormatEnvEntry for representative cases.
func TestFormatEnvEntry_CoversEdgeCases(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value string
		want  string
	}{
		{"unquoted safe", "A", "VAL", "A=VAL"},
		{"double-quoted needed (space)", "B", "hello world", `B="hello world"`},
		{"single-quoted multiline", "C", "one\ntwo", "C='one\ntwo'"},
		{"double-quoted because contains single quote or ends with newline", "D", "o'clock\nnext", `D="o'clock\nnext"`},
		{"empty value", "E", "", "E="},
		{"escape sequences in double-quote", "F", "a\tb\rc", `F="a\tb\rc"`},
		{"backslash and quote", "G", `he"llo\there`, `G="he\"llo\\there"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatEnvEntry(tc.key, tc.value)
			if got != tc.want {
				t.Fatalf("FormatEnvEntry(%q,%q) = %q; want %q", tc.key, tc.value, got, tc.want)
			}
		})
	}
}

// TestNonKeyLineAndMNil ensures lines that don't match the key=value/: syntax are ignored/copied
// and that UpdateEnvFile preserves non-key lines.
func TestNonKeyLineAndMNil(t *testing.T) {
	content := strings.Join([]string{
		"# comment",
		"NOT_A_KV_LINE some random text",
		"VAR=ok",
	}, "\n") + "\n"

	path := tmpPath(t, "nonkv.env")
	writeFile(t, path, content)

	m := readMapOrFail(t, path)
	want := map[string]string{"VAR": "ok"}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("unexpected parse result: got=%#v want=%#v", m, want)
	}

	// UpdateEnvFile should preserve the non-kv line when replacing VAR
	if err := UpdateEnvFile(path, "VAR", "new"); err != nil {
		t.Fatalf("UpdateEnvFile failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(string(raw), "NOT_A_KV_LINE some random text") {
		t.Fatalf("expected non-kv line preserved in file; got: %s", string(raw))
	}
}

// TestMultilineSingleQuotedCopyAndConsume covers copying a multi-line single-quoted block
// when it's not the target key, and consuming it when it is the target key.
func TestMultilineSingleQuotedCopyAndConsume(t *testing.T) {
	content := strings.Join([]string{
		"KEEP=keepme",
		"ML='first line",
		"middle line",
		"last line'",
		"OTHER=val",
	}, "\n") + "\n"

	path := tmpPath(t, "multiline.env")
	writeFile(t, path, content)

	// If we update OTHER, ML block should be copied as-is
	if err := UpdateEnvFile(path, "OTHER", "newval"); err != nil {
		t.Fatalf("UpdateEnvFile OTHER failed: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "ML='first line\nmiddle line\nlast line'") {
		t.Fatalf("expected ML block preserved when updating OTHER; got: %s", string(raw))
	}

	// Now replace ML itself; UpdateEnvFile should consume the whole block and replace with formatted entry
	if err := UpdateEnvFile(path, "ML", "replaced\nlines"); err != nil {
		t.Fatalf("UpdateEnvFile ML failed: %v", err)
	}
	m := readMapOrFail(t, path)
	if m["ML"] != "replaced\nlines" {
		t.Fatalf("ML not replaced correctly: got=%q", m["ML"])
	}
}

// TestMalformedMultilineAndPartsAccumulation ensures parser accumulates parts for a multiline block
// and handles the malformed case (no closing quote) by returning what it has and not swallowing the next key.
func TestMalformedMultilineAndPartsAccumulation(t *testing.T) {
	content := strings.Join([]string{
		"GOOD=ok",
		"BADML='start",
		"line2",
		"line3",
		"TAIL=after",
	}, "\n") + "\n"

	path := tmpPath(t, "badml.env")
	writeFile(t, path, content)

	m := readMapOrFail(t, path)

	if got := m["BADML"]; got != "start\nline2\nline3" {
		t.Fatalf("BADML parsed incorrectly: got=%q want=%q", got, "start\nline2\nline3")
	}
	if m["TAIL"] != "after" {
		t.Fatalf("TAIL parsed incorrectly: got=%q want=%q", m["TAIL"], "after")
	}
	if m["GOOD"] != "ok" {
		t.Fatalf("GOOD parsed incorrectly: got=%q want=%q", m["GOOD"], "ok")
	}
}

// TestDoubleQuotedEscapes_DefaultBranch exercises the double-quoted escape handling including the default branch.
func TestDoubleQuotedEscapes_DefaultBranch(t *testing.T) {
	content := strings.Join([]string{
		`DQ1="line1\nline2"`,
		`DQ2="a\tb\rc"`,
		`DQ3="back\\slash"`,
		`DQ4="quote\"here"`,
		`DQX="a\xby"`, // unknown escape -> 'x' should be kept
	}, "\n") + "\n"

	path := tmpPath(t, "dq.env")
	writeFile(t, path, content)

	m := readMapOrFail(t, path)

	want := map[string]string{
		"DQ1": "line1\nline2",
		"DQ2": "a\tb\rc",
		"DQ3": `back\slash`,
		"DQ4": `quote"here`,
		"DQX": "axby",
	}

	if !reflect.DeepEqual(m, want) {
		t.Fatalf("double-quoted escapes parsed incorrectly\ngot = %#v\nwant= %#v", m, want)
	}
}
