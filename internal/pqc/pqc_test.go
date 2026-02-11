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

package pqc

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ojster/ojster/internal/testutil"
)

// captureOutput runs f while capturing stdout and stderr and returns the combined output.
func captureOutput(t *testing.T, f func()) string {
	t.Helper()
	origOut := os.Stdout
	origErr := os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		_ = rOut.Close()
		_ = wOut.Close()
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stdout = wOut
	os.Stderr = wErr

	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		_, _ = io.Copy(&buf, rErr)
		done <- buf.String()
	}()

	f()

	// close writers to let goroutine finish
	_ = wOut.Close()
	_ = wErr.Close()
	out := <-done

	// restore
	_ = rOut.Close()
	_ = rErr.Close()
	os.Stdout = origOut
	os.Stderr = origErr
	return out
}

func TestKeypair_SuccessAndPublicWriteFailure(t *testing.T) {
	t.Run("success_writes_files_and_prints", func(t *testing.T) {
		td := t.TempDir()
		priv := filepath.Join(td, "priv.b64")
		pub := filepath.Join(td, "pub.b64")

		out := captureOutput(t, func() {
			Keypair([]string{"-priv-file", priv, "-pub-file", pub})
		})

		// Check private key file exists and has mode 0600
		st, err := os.Stat(priv)
		if err != nil {
			t.Fatalf("private key file missing: %v", err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("private key file mode: want 0600 got %o", st.Mode().Perm())
		}

		// Check public key file exists and has mode 0644
		st2, err := os.Stat(pub)
		if err != nil {
			t.Fatalf("public key file missing: %v", err)
		}
		if st2.Mode().Perm() != 0o644 {
			t.Fatalf("public key file mode: want 0644 got %o", st2.Mode().Perm())
		}

		// Read and base64-decode both files
		privB, err := os.ReadFile(priv)
		if err != nil {
			t.Fatalf("read priv: %v", err)
		}
		pubB, err := os.ReadFile(pub)
		if err != nil {
			t.Fatalf("read pub: %v", err)
		}

		privStr := strings.TrimSpace(string(privB))
		pubStr := strings.TrimSpace(string(pubB))

		if _, err := base64.StdEncoding.DecodeString(privStr); err != nil {
			t.Fatalf("private key not valid base64: %v", err)
		}
		if _, err := base64.StdEncoding.DecodeString(pubStr); err != nil {
			t.Fatalf("public key not valid base64: %v", err)
		}

		// Output should mention written files and include the public key base64
		if !strings.Contains(out, "Wrote private key to") {
			t.Fatalf("expected stdout to mention private key path; got: %q", out)
		}
		if !strings.Contains(out, "Wrote public key to") {
			t.Fatalf("expected stdout to mention public key path; got: %q", out)
		}
		if !strings.Contains(out, strings.TrimSpace(pubStr)) {
			t.Fatalf("expected stdout to include public key base64; got: %q", out)
		}
	})

	t.Run("failure_public_write_removes_private_and_exits", func(t *testing.T) {
		td := t.TempDir()
		priv := filepath.Join(td, "priv.b64")
		// create a directory at the pub path so the public write will fail
		pubDir := filepath.Join(td, "pubdir")
		if err := os.Mkdir(pubDir, 0o755); err != nil {
			t.Fatalf("mkdir pubdir: %v", err)
		}
		// use the directory path as the pub-file argument to force a write error
		pub := pubDir

		// Stub exit so we can assert it was called and continue the test
		code := testutil.StubExit(t, &exitFunc)

		// Run Keypair; it should attempt to write private then fail writing public and call exitFunc(1)
		defer testutil.ExpectExitPanic(t, code, 1)

		_ = captureOutput(t, func() {
			Keypair([]string{"-priv-file", priv, "-pub-file", pub})
		})

		// After exit, private file should have been removed by the error path
		if _, err := os.Stat(priv); !os.IsNotExist(err) {
			t.Fatalf("expected private key to be removed after public write failure; stat err=%v", err)
		}
	})
}

// AES

func genKey32() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestEncryptDecrypt_RoundtripsAndVariations(t *testing.T) {
	key := genKey32()

	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte("")},
		{"short", []byte("x")},
		{"hello", []byte("hello world")},
		{"long", bytes.Repeat([]byte("A"), 10_000)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := encryptAESGCM(key, tc.plaintext)
			if err != nil {
				t.Fatalf("encryptAESGCM error: %v", err)
			}
			if bytes.Equal(ct, tc.plaintext) {
				t.Fatalf("ciphertext equals plaintext")
			}

			pt, err := decryptAESGCM(key, ct)
			if err != nil {
				t.Fatalf("decryptAESGCM error: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("roundtrip mismatch: want=%q got=%q", tc.plaintext, pt)
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := genKey32()
	plaintext := []byte("same-plaintext")

	ct1, err := encryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}
	ct2, err := encryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatalf("expected different ciphertexts for same plaintext (nonce/randomness), got identical")
	}
}

func TestEncrypt_BadKeySizes(t *testing.T) {
	badKeys := [][]byte{
		[]byte("short"),
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
	}
	for i, k := range badKeys {
		t.Run(fmt.Sprintf("badkey-%d", i), func(t *testing.T) {
			if _, err := encryptAESGCM(k, []byte("x")); err == nil {
				t.Fatalf("expected error for bad key length %d", len(k))
			}
		})
	}
}

func TestDecrypt_BadKeySizes(t *testing.T) {
	// Create a valid ciphertext to use as blob
	key := genKey32()
	ct, err := encryptAESGCM(key, []byte("p"))
	if err != nil {
		t.Fatalf("setup encrypt failed: %v", err)
	}

	badKeys := [][]byte{
		[]byte("short"),
		make([]byte, 16),
		make([]byte, 31),
		make([]byte, 33),
	}
	for i, k := range badKeys {
		t.Run(fmt.Sprintf("badkey-%d", i), func(t *testing.T) {
			if _, err := decryptAESGCM(k, ct); err == nil {
				t.Fatalf("expected error for bad key length %d", len(k))
			}
		})
	}
}

func TestDecrypt_ShortBlob(t *testing.T) {
	key := genKey32()
	// Provide a blob shorter than any reasonable nonce (e.g., 1 byte)
	short := []byte{0x01, 0x02, 0x03}
	if _, err := decryptAESGCM(key, short); err == nil {
		t.Fatalf("expected error for short blob")
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := genKey32()
	plaintext := []byte("sensitive-data")
	ct, err := encryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with a byte in the ciphertext portion (after nonce)
	if len(ct) <= 12 {
		t.Fatalf("ciphertext unexpectedly too short for tamper test")
	}
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	// flip a bit in the last byte
	tampered[len(tampered)-1] ^= 0xFF

	if _, err := decryptAESGCM(key, tampered); err == nil {
		t.Fatalf("expected decryption to fail for tampered ciphertext")
	}
}
