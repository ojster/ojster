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

package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// TestSplitDoubleDash covers several positions of the "--" separator.
func TestSplitDoubleDash(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		before []string
		after  []string
		had    bool
	}{
		{"no-dash", []string{"a", "b"}, []string{"a", "b"}, nil, false},
		{"middle", []string{"a", "--", "b", "c"}, []string{"a"}, []string{"b", "c"}, true},
		{"start", []string{"--", "x"}, nil, []string{"x"}, true},
		{"end", []string{"a", "--"}, []string{"a"}, nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, after, had := splitDoubleDash(tc.args)
			if had != tc.had {
				t.Fatalf("had: got %v want %v", had, tc.had)
			}
			if len(before) != len(tc.before) {
				t.Fatalf("before: got %v want %v", before, tc.before)
			}
			if len(after) != len(tc.after) {
				t.Fatalf("after: got %v want %v", after, tc.after)
			}
			for i := range before {
				if before[i] != tc.before[i] {
					t.Fatalf("before[%d]: got %q want %q", i, before[i], tc.before[i])
				}
			}
			for i := range after {
				if after[i] != tc.after[i] {
					t.Fatalf("after[%d]: got %q want %q", i, after[i], tc.after[i])
				}
			}
		})
	}
}

// TestUsageFromFlagSet ensures usageFromFlagSet captures the FlagSet usage output.
func TestUsageFromFlagSet(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	fs.Usage = func() {
		// write to fs.Output() so usageFromFlagSet captures it
		fs.SetOutput(fs.Output())
		fs.Output().Write([]byte("MY USAGE\n"))
	}
	got := usageFromFlagSet(fs)
	if !strings.Contains(got, "MY USAGE") {
		t.Fatalf("usageFromFlagSet did not capture usage; got: %q", got)
	}
}

// TestEntrypoint_NoArgs prints header and returns 0.
func TestEntrypoint_NoArgs(t *testing.T) {
	var out, errb bytes.Buffer
	code := Entrypoint("ojster", []string{}, "v1.2.3", "HEADER\n", &out, &errb)
	if code != 0 {
		t.Fatalf("Entrypoint returned code %d; want 0", code)
	}
	if out.String() != "HEADER\n" {
		t.Fatalf("Entrypoint output mismatch; got %q", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("expected no stderr; got %q", errb.String())
	}
}

// TestEntrypoint_Help prints header and returns 0.
func TestEntrypoint_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := Entrypoint("ojster", []string{"help"}, "v", "HDR\n", &out, &errb)
	if code != 0 {
		t.Fatalf("Entrypoint(help) returned %d; want 0", code)
	}
	if out.String() != "HDR\n" {
		t.Fatalf("help output mismatch; got %q", out.String())
	}
}

// TestEntrypoint_Version prints version and returns 0.
func TestEntrypoint_Version(t *testing.T) {
	var out, errb bytes.Buffer
	code := Entrypoint("ojster", []string{"version"}, "VER-XYZ", "HDR\n", &out, &errb)
	if code != 0 {
		t.Fatalf("Entrypoint(version) returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "VER-XYZ") {
		t.Fatalf("version output missing; got %q", out.String())
	}
}

// TestEntrypoint_Unknown prints header, writes error and returns 1.
func TestEntrypoint_Unknown(t *testing.T) {
	var out, errb bytes.Buffer
	code := Entrypoint("ojster", []string{"nope"}, "v", "HDR\n", &out, &errb)
	if code != 1 {
		t.Fatalf("Entrypoint(unknown) returned %d; want 1", code)
	}
	if out.String() != "HDR\n" {
		t.Fatalf("expected header on stdout; got %q", out.String())
	}
	if !strings.Contains(errb.String(), "unknown subcommand: nope") {
		t.Fatalf("expected unknown subcommand error; got %q", errb.String())
	}
}

// TestHandleKeypair_Help ensures -h triggers usage printing and returns 0 without calling pqc.
func TestHandleKeypair_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := handleKeypair([]string{"-h"}, &out, &errb)
	if code != 0 {
		t.Fatalf("handleKeypair -h returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "Usage: ojster keypair") {
		t.Fatalf("expected keypair usage; got %q", out.String())
	}
}

// TestHandleSeal_MissingArg ensures seal without positional KEY returns error 1 and message.
func TestHandleSeal_MissingArg(t *testing.T) {
	var out, errb bytes.Buffer
	code := handleSeal([]string{}, &out, &errb)
	if code != 1 {
		t.Fatalf("handleSeal with no args returned %d; want 1", code)
	}
	if !strings.Contains(errb.String(), "seal requires exactly one positional argument: KEY") {
		t.Fatalf("expected seal missing-arg message; got %q", errb.String())
	}
}

// TestHandleUnseal_Help ensures -h prints usage and returns 0.
func TestHandleUnseal_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := handleUnseal([]string{"-h"}, &out, &errb)
	if code != 0 {
		t.Fatalf("handleUnseal -h returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "Usage: ojster unseal") {
		t.Fatalf("expected unseal usage; got %q", out.String())
	}
}

// TestHandleRun_Help ensures run -h prints usage and returns 0.
func TestHandleRun_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := handleRun([]string{"-h"}, &out, &errb)
	if code != 0 {
		t.Fatalf("handleRun -h returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "Usage: ojster run") {
		t.Fatalf("expected run usage; got %q", out.String())
	}
}

// TestHandleServe_Help ensures serve -h prints usage and returns 0.
func TestHandleServe_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := handleServe([]string{"-h"}, &out, &errb)
	if code != 0 {
		t.Fatalf("handleServe -h returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "Usage: ojster serve") {
		t.Fatalf("expected serve usage; got %q", out.String())
	}
}
