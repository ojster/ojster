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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ----------------------------- small utilities for tests -----------------------------

// simple helper to create a temp file path
func tmpFilePath(t *testing.T, name string) string {
	t.Helper()
	td := t.TempDir()
	return filepath.Join(td, name)
}

// ----------------------------- entrypoint basic behavior -----------------------------

// TestEntrypoint_NoArgs prints header and returns 0.
func TestEntrypoint_NoArgs(t *testing.T) {
	var out, errb bytes.Buffer
	code := entrypoint("ojster", []string{}, "v1.2.3", &out, &errb)
	if code != 0 {
		t.Fatalf("entrypoint returned code %d; want 0", code)
	}
	// top-level help now composes header + commands; assert header is present
	if !strings.Contains(out.String(), header) {
		t.Fatalf("entrypoint output missing header; got %q", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("expected no stderr; got %q", errb.String())
	}
}

// TestEntrypoint_Help prints header and returns 0.
func TestEntrypoint_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := entrypoint("ojster", []string{"help"}, "v", &out, &errb)
	if code != 0 {
		t.Fatalf("entrypoint(help) returned %d; want 0", code)
	}
	// top-level help now composes header + commands; assert header is present
	if !strings.Contains(out.String(), header) {
		t.Fatalf("help output missing header; got %q", out.String())
	}
}

// TestEntrypoint_Version prints version and returns 0.
func TestEntrypoint_Version(t *testing.T) {
	var out, errb bytes.Buffer
	code := entrypoint("ojster", []string{"version"}, "VER-XYZ", &out, &errb)
	if code != 0 {
		t.Fatalf("entrypoint(version) returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "VER-XYZ") {
		t.Fatalf("version output missing; got %q", out.String())
	}
}

// TestEntrypoint_Unknown prints header, writes error and returns 1.
func TestEntrypoint_Unknown(t *testing.T) {
	var out, errb bytes.Buffer
	code := entrypoint("ojster", []string{"nope"}, "v", &out, &errb)
	if code != 1 {
		t.Fatalf("entrypoint(unknown) returned %d; want 1", code)
	}
	// top-level help should be printed on stdout
	if !strings.Contains(out.String(), header) {
		t.Fatalf("expected header on stdout; got %q", out.String())
	}
	if !strings.Contains(errb.String(), "unknown subcommand: nope") {
		t.Fatalf("expected unknown subcommand error; got %q", errb.String())
	}
}

// ----------------------------- handler help behavior -----------------------------

// TestHandleKeypair_Help ensures -h triggers usage printing and returns 0 without calling pqc.
func TestHandleKeypair_Help(t *testing.T) {
	var out, errb bytes.Buffer
	code := handleKeypair([]string{"-h"}, &out, &errb)
	if code != 0 {
		t.Fatalf("handleKeypair -h returned %d; want 0", code)
	}
	if !strings.Contains(out.String(), "ojster keypair") {
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
	if !strings.Contains(out.String(), "ojster unseal") {
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
	if !strings.Contains(out.String(), "ojster run") {
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
	if !strings.Contains(out.String(), "ojster serve") {
		t.Fatalf("expected serve usage; got %q", out.String())
	}
}

// ----------------------------- entrypoint dispatch tests -----------------------------

// TestEntrypoint_SubcommandDispatch verifies entrypoint dispatches to the correct handlers.
// For most handlers we use the -h help flag so the handler returns quickly without side effects.
func TestEntrypoint_SubcommandDispatch(t *testing.T) {
	cases := []struct {
		name            string
		prog            string
		args            []string
		wantCode        int
		wantOutContains string // substring expected on stdout (if any)
		wantErrContains string // substring expected on stderr (if any)
	}{
		{
			name:            "help",
			prog:            "ojster",
			args:            []string{"help"},
			wantCode:        0,
			wantOutContains: header,
		},
		{
			name:            "version",
			prog:            "ojster",
			args:            []string{"version"},
			wantCode:        0,
			wantOutContains: "v1.2.3", // entrypoint prints the version string
		},
		{
			name:            "keypair help",
			prog:            "ojster",
			args:            []string{"keypair", "-h"},
			wantCode:        0,
			wantOutContains: "ojster keypair",
		},
		{
			name:            "run help",
			prog:            "ojster",
			args:            []string{"run", "-h"},
			wantCode:        0,
			wantOutContains: "ojster run",
		},
		{
			name:            "seal help",
			prog:            "ojster",
			args:            []string{"seal", "-h"},
			wantCode:        0,
			wantOutContains: "ojster seal",
		},
		{
			name:            "serve help",
			prog:            "ojster",
			args:            []string{"serve", "-h"},
			wantCode:        0,
			wantOutContains: "ojster serve",
		},
		{
			name:            "unseal help",
			prog:            "ojster",
			args:            []string{"unseal", "-h"},
			wantCode:        0,
			wantOutContains: "ojster unseal",
		},
		{
			name:            "docker-init behaves like run (help)",
			prog:            "docker-init",
			args:            []string{"-h"},
			wantCode:        0,
			wantOutContains: "ojster run",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := entrypoint(c.prog, c.args, "v1.2.3", &out, &errb)
			if code != c.wantCode {
				t.Fatalf("entrypoint(%s %v) returned code %d; want %d; stderr=%q", c.prog, c.args, code, c.wantCode, errb.String())
			}
			if c.wantOutContains != "" && !strings.Contains(out.String(), c.wantOutContains) {
				t.Fatalf("stdout did not contain %q; got stdout=%q stderr=%q", c.wantOutContains, out.String(), errb.String())
			}
			if c.wantErrContains != "" && !strings.Contains(errb.String(), c.wantErrContains) {
				t.Fatalf("stderr did not contain %q; got stderr=%q stdout=%q", c.wantErrContains, errb.String(), out.String())
			}
		})
	}
}

// ----------------------------- parse-error coverage for subcommands -----------------------------

func TestEntrypoint_SubcommandFlagParseErrors(t *testing.T) {

	cases := []struct {
		name       string
		subcommand string
		args       []string
		wantCode   int
		wantSubstr string
	}{
		{"keypair parse error", "keypair", []string{"keypair", "--no-such-flag"}, 2, "failed to parse keypair flags"},
		{"seal parse error", "seal", []string{"seal", "--no-such-flag"}, 2, "failed to parse seal flags"},
		{"unseal parse error", "unseal", []string{"unseal", "--no-such-flag"}, 2, "failed to parse unseal flags"},
		{"run parse error", "run", []string{"run", "--no-such-flag"}, 2, "failed to parse run flags"},
		{"serve parse error", "serve", []string{"serve", "--no-such-flag"}, 2, "failed to parse serve flags"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			// entrypoint expects args without the program name; pass as-is so subcommand is first arg.
			code := entrypoint("ojster", c.args, "v", &out, &errb)
			if code != c.wantCode {
				t.Fatalf("entrypoint(%v) returned %d; want %d; stderr=%q", c.args, code, c.wantCode, errb.String())
			}
			if !strings.Contains(errb.String(), c.wantSubstr) {
				t.Fatalf("stderr did not contain %q; got: %q", c.wantSubstr, errb.String())
			}
		})
	}
}

// ----------------------------- delegation coverage for keypair -----------------------------

// TestEntrypoint_Keypair_Delegation ensures entrypoint delegates to handleKeypair which calls pqc.KeypairWithPaths.
// This test uses explicit --priv-file and --pub-file flags to avoid writing to default locations.
func TestEntrypoint_Keypair_Delegation(t *testing.T) {

	priv := tmpFilePath(t, "priv.b64")
	pub := tmpFilePath(t, "pub.b64")

	var out, errb bytes.Buffer
	// pass flags to set output paths
	args := []string{"keypair", "--priv-file", priv, "--pub-file", pub}
	code := entrypoint("ojster", args, "v", &out, &errb)
	if code != 0 {
		t.Fatalf("entrypoint(keypair) returned %d; want 0; stderr=%q", code, errb.String())
	}

	// private and public files should exist
	if _, err := os.Stat(priv); err != nil {
		t.Fatalf("expected private key file %s to exist; stat error: %v; stderr=%q", priv, err, errb.String())
	}
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("expected public key file %s to exist; stat error: %v; stderr=%q", pub, err, errb.String())
	}

	// output should include the public key base64 (KeypairWithPaths prints it)
	pubB64, err := os.ReadFile(pub)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	if !strings.Contains(out.String(), strings.TrimSpace(string(pubB64))) {
		t.Fatalf("expected entrypoint output to include public key base64; got stdout=%q stderr=%q", out.String(), errb.String())
	}
}

// ----------------------------- seal/unseal/run delegation smoke checks -----------------------------

// TestEntrypoint_Seal_MissingPositional ensures entrypoint dispatches to handleSeal and that
// handleSeal returns the expected error when the required positional KEY is missing.
func TestEntrypoint_Seal_MissingPositional(t *testing.T) {
	var out, errb bytes.Buffer
	code := entrypoint("ojster", []string{"seal"}, "v", &out, &errb)
	if code != 1 {
		t.Fatalf("entrypoint(seal missing arg) returned %d; want 1; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "seal requires exactly one positional argument: KEY") {
		t.Fatalf("expected seal missing-arg message; got stderr=%q stdout=%q", errb.String(), out.String())
	}
}

// TestEntrypoint_Unseal_Delegation ensures entrypoint delegates to handleUnseal (help path).
func TestEntrypoint_Unseal_Delegation(t *testing.T) {
	var out, errb bytes.Buffer
	code := entrypoint("ojster", []string{"unseal", "-h"}, "v", &out, &errb)
	if code != 0 {
		t.Fatalf("entrypoint(unseal -h) returned %d; want 0; stdout=%q stderr=%q", code, out.String(), errb.String())
	}
	// The handler prints the synopsis line (e.g., "ojster unseal ..."), so assert on that.
	if !strings.Contains(out.String(), unsealSynopsis) {
		t.Fatalf("expected unseal synopsis; got stdout=%q stderr=%q", out.String(), errb.String())
	}
}

// TestHandleSeal_DelegatesToPQC_InvalidPub ensures handleSeal delegates to pqc.SealWithPlaintext.
// We provide stdin and an invalid pub file so pqc.SealWithPlaintext fails with a predictable message.
func TestHandleSeal_DelegatesToPQC_InvalidPub(t *testing.T) {
	td := t.TempDir()
	pub := filepath.Join(td, "badpub.b64")
	outPath := filepath.Join(td, "out.env")
	if err := os.WriteFile(pub, []byte("not-base64!!!\n"), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}

	// Create a pipe and write plaintext into the write end so tty.ReadSecretFromStdin can read it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	_, _ = w.WriteString("plaintext\n")
	_ = w.Close()

	origStdin := os.Stdin
	os.Stdin = r
	defer func() {
		_ = r.Close()
		os.Stdin = origStdin
	}()

	var out, errb bytes.Buffer
	args := []string{"--pub-file", pub, "--out", outPath, "MYKEY"}
	code := handleSeal(args, &out, &errb)
	if code == 0 {
		t.Fatalf("expected non-zero exit code from handleSeal with invalid pub file; stdout=%q stderr=%q", out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "invalid base64 public key") {
		t.Fatalf("expected invalid base64 public key error; got stderr=%q stdout=%q", errb.String(), out.String())
	}
}

// TestHandleUnseal_DelegatesToPQC_InvalidPriv ensures handleUnseal delegates to pqc.UnsealFromFiles.
// We create an invalid base64 private key file so UnsealFromFiles fails with a predictable message.
func TestHandleUnseal_DelegatesToPQC_InvalidPriv(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	envFile := filepath.Join(td, "env.env")

	// write invalid base64 priv
	if err := os.WriteFile(priv, []byte("not-base64!!!\n"), 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
	// minimal env file
	if err := os.WriteFile(envFile, []byte("A=1\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	var out, errb bytes.Buffer
	args := []string{"--in", envFile, "--priv-file", priv}
	code := handleUnseal(args, &out, &errb)
	if code == 0 {
		t.Fatalf("expected non-zero exit code from handleUnseal with invalid priv file; stdout=%q stderr=%q", out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "invalid base64 private key") {
		t.Fatalf("expected invalid base64 private key error; got stderr=%q stdout=%q", errb.String(), out.String())
	}
}

// TestHandleRun_DelegatesToClient_RunNonexistentCommand ensures handleRun delegates to client.Run.
// Passing a non-existent command should produce a non-zero exit code (smoke test).
func TestHandleRun_DelegatesToClient_NonexistentCommand(t *testing.T) {
	var out, errb bytes.Buffer
	// use -- to pass positional command args through; choose a command name that almost certainly doesn't exist
	args := []string{"--", "no-such-command-hopefully-unique-12345"}
	code := handleRun(args, &out, &errb)
	if code == 0 {
		t.Fatalf("expected non-zero exit code from handleRun for nonexistent command; stdout=%q stderr=%q", out.String(), errb.String())
	}
	// stderr content is implementation-dependent; assert we got some stderr text
	if errb.Len() == 0 {
		t.Fatalf("expected some stderr output from handleRun for nonexistent command; got stdout=%q", out.String())
	}
}

// ----------------------------- env reading -----------------------------

func TestReadServeEnv_Defaults(t *testing.T) {
	// Ensure no env vars are set so readServeEnv returns defaults.
	t.Setenv("OJSTER_PRIVATE_KEY_FILE", "")
	t.Setenv("OJSTER_SOCKET_PATH", "")

	got := readServeEnv()

	wantSocket := "/mnt/ojster/ipc.sock"
	if got.SocketPath != wantSocket {
		t.Fatalf("unexpected SocketPath: want=%q got=%q", wantSocket, got.SocketPath)
	}

	wantPriv := "/run/secrets/private_key"
	if got.PrivateKeyFile != wantPriv {
		t.Fatalf("unexpected PrivateKeyFile: want=%q got=%q", wantPriv, got.PrivateKeyFile)
	}
}

func TestReadServeEnv_CustomValues(t *testing.T) {
	tmpSocket := filepath.Join(t.TempDir(), "ojster.sock")
	tmpPriv := filepath.Join(t.TempDir(), "mypriv.key")

	t.Setenv("OJSTER_SOCKET_PATH", tmpSocket)
	t.Setenv("OJSTER_PRIVATE_KEY_FILE", tmpPriv)

	got := readServeEnv()

	if got.SocketPath != tmpSocket {
		t.Fatalf("unexpected SocketPath: want=%q got=%q", tmpSocket, got.SocketPath)
	}
	if got.PrivateKeyFile != tmpPriv {
		t.Fatalf("unexpected PrivateKeyFile: want=%q got=%q", tmpPriv, got.PrivateKeyFile)
	}
}

// TestGetenvDefaultAndUnset verifies getenvDefaultAndUnset returns the env value and unsets it,
// and returns the default when the env var is not set.
func TestGetenvDefaultAndUnset(t *testing.T) {
	// Case 1: env var set -> value returned and var unset
	const key1 = "OJSTER_TEST_KEY"
	_ = os.Setenv(key1, "value1")
	got := getenvDefaultAndUnset(key1, "def1")
	if got != "value1" {
		t.Fatalf("getenvDefaultAndUnset(%q) = %q; want %q", key1, got, "value1")
	}
	if v := os.Getenv(key1); v != "" {
		t.Fatalf("expected %q to be unset after getenvDefaultAndUnset, but got %q", key1, v)
	}

	// Case 2: env var not set -> default returned
	const key2 = "OJSTER_TEST_KEY2"
	_ = os.Unsetenv(key2)
	got2 := getenvDefaultAndUnset(key2, "def2")
	if got2 != "def2" {
		t.Fatalf("getenvDefaultAndUnset(%q) = %q; want default %q", key2, got2, "def2")
	}
}
