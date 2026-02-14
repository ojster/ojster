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

//go:build linux

package tty

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestReadSecretFromStdin_NonTTY verifies that when stdin is not a TTY
// ReadSecretFromStdin simply reads all bytes from stdin.
func TestReadSecretFromStdin_NonTTY(t *testing.T) {
	// Create a pipe and make the read end act as os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	// Write some secret data and close writer so ReadSecretFromStdin sees EOF
	secret := []byte("super-secret\nline2\n")
	_, _ = w.Write(secret)
	_ = w.Close()

	os.Stdin = r

	out, err := ReadSecretFromStdin("prompt: ")
	if err != nil {
		t.Fatalf("ReadSecretFromStdin returned error: %v", err)
	}
	if !bytes.Equal(out, secret) {
		t.Fatalf("unexpected secret read: want=%q got=%q", secret, out)
	}
}

// TestReadWithTermios_Fallback verifies readWithTermios falls back to plain read
// when ioctl/termios operations are not available (e.g., on a pipe).
func TestReadWithTermios_Fallback(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	// Write data and close writer to simulate EOF
	payload := []byte("fallback-secret")
	_, _ = w.Write(payload)
	_ = w.Close()

	// Use a buffer file for out to capture any newline printed by deferred restore.
	// os.Stdout is fine as well, but avoid polluting test output.
	tmpOut, err := os.CreateTemp("", "tty-test-out")
	if err != nil {
		t.Fatalf("failed to create temp out file: %v", err)
	}
	defer func() {
		tmpOut.Close()
		_ = os.Remove(tmpOut.Name())
	}()

	got, err := readWithTermios(r, tmpOut)
	if err != nil {
		t.Fatalf("readWithTermios returned error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected payload: want=%q got=%q", payload, got)
	}

	// ensure deferred newline was written to out if termios path was used.
	// On non-tty (pipe) the ioctl path fails early and no deferred newline is written,
	// so accept either an empty out file or one that contains at least a newline.
	_, _ = tmpOut.Seek(0, io.SeekStart)
	outBytes, _ := io.ReadAll(tmpOut)

	if len(outBytes) == 0 {
		// Acceptable: ioctl failed and no deferred newline was printed.
		t.Logf("no deferred newline written (expected on non-tty fallback)")
		return
	}

	// If something was written, ensure it contains a newline (the deferred restore prints one).
	if !bytes.Contains(outBytes, []byte("\n")) {
		t.Fatalf("expected deferred newline in out, got: %q", outBytes)
	}
}
