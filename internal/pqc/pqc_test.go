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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ojster/ojster/internal/util/env"
)

// helper: read file and trim
func readTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}

// TestSealAndUnseal_HappyPath generates a keypair, seals a plaintext into an env file,
// then unseals it and verifies the original plaintext is recovered (both json and env output).
func TestSealAndUnseal_HappyPath(t *testing.T) {
	td := t.TempDir()

	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "secrets.env")

	// generate keys
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// Seal a value
	keyName := "MY_SECRET"
	plaintext := []byte("super-secret-value")
	if code := SealWithPlaintext(pub, envFile, keyName, plaintext, &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: code=%d stderr=%q", code, errBuf.String())
	}

	// Ensure env file contains the key and value looks sealed (prefix)
	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	val, ok := envMap[keyName]
	if !ok {
		t.Fatalf("env file missing key %s", keyName)
	}
	if !strings.HasPrefix(val, prefix) {
		t.Fatalf("sealed value missing prefix: %q", val)
	}

	// Unseal to JSON
	var jsonOut bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, []string{keyName}, true, &jsonOut, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles(json) failed: code=%d stderr=%q", code, errBuf.String())
	}
	var got map[string]string
	if err := json.Unmarshal(jsonOut.Bytes(), &got); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if got[keyName] != string(plaintext) {
		t.Fatalf("unsealed mismatch json: want=%q got=%q", string(plaintext), got[keyName])
	}

	// Unseal to env format (non-json)
	var envOut bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, []string{keyName}, false, &envOut, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles(env) failed: code=%d stderr=%q", code, errBuf.String())
	}
	// parse the returned env text
	parsed, err := env.ParseEnvReader(strings.NewReader(envOut.String()))
	if err != nil {
		t.Fatalf("ParseEnvReader failed: %v", err)
	}
	if parsed[keyName] != string(plaintext) {
		t.Fatalf("unsealed mismatch env: want=%q got=%q", string(plaintext), parsed[keyName])
	}
}

// TestSealWithPlaintext_BadPubFile ensures SealWithPlaintext fails when the public key file is invalid.
func TestSealWithPlaintext_BadPubFile(t *testing.T) {
	td := t.TempDir()
	pub := filepath.Join(td, "badpub.b64")
	envFile := filepath.Join(td, "out.env")

	// write invalid base64 to pub file
	if err := os.WriteFile(pub, []byte("not-base64!!!\n"), 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	code := SealWithPlaintext(pub, envFile, "K", []byte("x"), &outBuf, &errBuf)
	if code == 0 {
		t.Fatalf("expected SealWithPlaintext to fail with bad pub file")
	}
}

// TestUnsealFromFiles_MissingKey ensures UnsealFromFiles returns exit code 2 for missing keys.
func TestUnsealFromFiles_MissingKey(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "secrets.env")

	// generate keys
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// create env file with no sealed entries
	if err := os.WriteFile(envFile, []byte("A=1\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	// request a missing key
	code := UnsealFromFiles(envFile, priv, []string{"MISSING"}, false, &outBuf, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing keys, got %d stderr=%q", code, errBuf.String())
	}
}

// TestUnsealFromFiles_MalformedSealedValue ensures malformed sealed values are rejected.
func TestUnsealFromFiles_MalformedSealedValue(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")

	// generate keys (we only need a private key file to exercise parsing errors)
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, filepath.Join(td, "pub.b64"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// write env file with a malformed sealed value (missing sep)
	envFile := filepath.Join(td, "bad.env")
	if err := os.WriteFile(envFile, []byte("BAD=OJSTER-1:onlyonepart\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	code := UnsealFromFiles(envFile, priv, []string{"BAD"}, false, &outBuf, &errBuf)
	if code == 0 {
		t.Fatalf("expected UnsealFromFiles to fail for malformed sealed value")
	}
}

// TestUnsealFromFiles_NoSealedEntries returns success and no output when no sealed entries exist and no keys requested.
func TestUnsealFromFiles_NoSealedEntries(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "plain.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// Reset buffers so subsequent checks only observe UnsealFromFiles output.
	outBuf.Reset()
	errBuf.Reset()

	if err := os.WriteFile(envFile, []byte("A=1\nB=2\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	// request all sealed entries (none exist) by passing empty keys slice
	code := UnsealFromFiles(envFile, priv, nil, false, &outBuf, &errBuf)
	if code != 0 {
		t.Fatalf("expected success when no sealed entries exist, got code=%d stderr=%q", code, errBuf.String())
	}
	if outBuf.Len() != 0 {
		t.Fatalf("expected no output, got %q", outBuf.String())
	}
}

// TestRoundtripMultipleKeys ensures multiple keys are sealed and unsealed and ordering is stable.
func TestRoundtripMultipleKeys(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "multi.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// create env file with several sealed entries by calling SealWithPlaintext repeatedly
	keys := []string{"A", "B", "C"}
	values := map[string][]byte{
		"A": []byte("va"),
		"B": []byte("vb"),
		"C": []byte("vc"),
	}
	// start with empty env file
	if err := os.WriteFile(envFile, []byte(""), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	for _, k := range keys {
		if code := SealWithPlaintext(pub, envFile, k, values[k], &outBuf, &errBuf); code != 0 {
			t.Fatalf("SealWithPlaintext failed for %s: code=%d stderr=%q", k, code, errBuf.String())
		}
	}

	// Unseal all (no keys provided)
	var outJSON bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, nil, true, &outJSON, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles failed: code=%d stderr=%q", code, errBuf.String())
	}
	var got map[string]string
	if err := json.Unmarshal(outJSON.Bytes(), &got); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	// ensure all keys present and values match
	for k, v := range values {
		if got[k] != string(v) {
			t.Fatalf("value mismatch for %s: want=%q got=%q", k, string(v), got[k])
		}
	}

	// ensure deterministic ordering when requesting keys explicitly
	sort.Strings(keys)
	var envOut bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, keys, false, &envOut, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles failed: code=%d stderr=%q", code, errBuf.String())
	}
	// parse envOut and verify entries
	parsed, err := env.ParseEnvReader(strings.NewReader(envOut.String()))
	if err != nil {
		t.Fatalf("ParseEnvReader failed: %v", err)
	}
	for k, v := range values {
		if parsed[k] != string(v) {
			t.Fatalf("env output mismatch for %s: want=%q got=%q", k, string(v), parsed[k])
		}
	}
}

// TestKeypairWithPaths_OutputFormat ensures KeypairWithPaths prints the public key base64 in its output.
func TestKeypairWithPaths_OutputFormat(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}
	out := outBuf.String()
	pubB64 := readTrim(t, pub)
	// output should contain the public key base64
	if !strings.Contains(out, strings.TrimSpace(pubB64)) {
		t.Fatalf("expected output to include public key base64; got: %q", out)
	}
}

// TestEncryptDecrypt_Errors ensures AES helpers return errors for bad inputs (delegated from earlier tests).
func TestEncryptDecrypt_Errors(t *testing.T) {
	// bad key sizes for encrypt
	if _, err := encryptAESGCM([]byte("short"), []byte("x")); err == nil {
		t.Fatalf("expected error for short key")
	}
	// bad key sizes for decrypt
	key := make([]byte, 32)
	ct, err := encryptAESGCM(key, []byte("p"))
	if err != nil {
		t.Fatalf("setup encrypt failed: %v", err)
	}
	if _, err := decryptAESGCM([]byte("short"), ct); err == nil {
		t.Fatalf("expected error for short key on decrypt")
	}
	// short blob
	if _, err := decryptAESGCM(key, []byte{1, 2}); err == nil {
		t.Fatalf("expected error for short blob")
	}
}

// helper: write a file with given content and perms
func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// runUnseal calls UnsealFromFiles with fresh buffers and returns (code, stderr).
// It keeps tests concise and avoids repeated buffer setup.
func runUnseal(t *testing.T, envPath, privPath string, keys []string, jsonOut bool) (int, string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code := UnsealFromFiles(envPath, privPath, keys, jsonOut, &outBuf, &errBuf)
	return code, errBuf.String()
}

// createMinimalEnv writes a minimal env file at path.
func createMinimalEnv(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, []byte("A=1\n"), 0o600)
}

// createInvalidBase64Priv writes an invalid base64 string to privPath.
func createInvalidBase64Priv(t *testing.T, privPath string) {
	t.Helper()
	writeFile(t, privPath, []byte("not-base64!!!\n"), 0o600)
}

// createShortPriv writes base64 of a short byte slice to privPath (to provoke NewDecapsulationKey768 failure).
func createShortPriv(t *testing.T, privPath string) {
	t.Helper()
	short := []byte{0x01, 0x02, 0x03}
	writeFile(t, privPath, []byte(base64.StdEncoding.EncodeToString(short)+"\n"), 0o600)
}

// TestUnsealFromFiles_PrivFileMissing verifies the branch when the private key file cannot be read.
func TestUnsealFromFiles_PrivFileMissing(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "no-such-priv.b64")
	envFile := filepath.Join(td, "env.env")

	createMinimalEnv(t, envFile)

	code, stderr := runUnseal(t, envFile, priv, nil, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when private key file missing")
	}
	if !strings.Contains(stderr, "failed to read private key file") {
		t.Fatalf("expected error about reading private key file; got: %q", stderr)
	}
}

// TestUnsealFromFiles_PrivFileInvalidBase64 verifies the branch when the private key file contains invalid base64.
func TestUnsealFromFiles_PrivFileInvalidBase64(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	envFile := filepath.Join(td, "env.env")

	createInvalidBase64Priv(t, priv)
	createMinimalEnv(t, envFile)

	code, stderr := runUnseal(t, envFile, priv, nil, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid base64 private key")
	}
	if !strings.Contains(stderr, "invalid base64 private key") {
		t.Fatalf("expected error about invalid base64 private key; got: %q", stderr)
	}
}

// TestUnsealFromFiles_PrivFileInvalidKey verifies the branch when the private key decapsulation constructor fails.
func TestUnsealFromFiles_PrivFileInvalidKey(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	envFile := filepath.Join(td, "env.env")

	createShortPriv(t, priv)
	createMinimalEnv(t, envFile)

	code, stderr := runUnseal(t, envFile, priv, nil, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid private key material")
	}
	if !strings.Contains(stderr, "invalid private key") {
		t.Fatalf("expected error about invalid private key; got: %q", stderr)
	}
}

// TestUnsealFromFiles_ParseEnvFileError forces ParseEnvFile to return an error by using a directory path.
// This test creates a valid private key first so UnsealFromFiles reaches the env parsing branch.
func TestUnsealFromFiles_ParseEnvFileError(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")

	// create a valid keypair so we don't fail earlier
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, filepath.Join(td, "pub.b64"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// create a directory and use its path as the env file path to provoke a read error
	envDir := filepath.Join(td, "envdir")
	if err := os.Mkdir(envDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	code, stderr := runUnseal(t, envDir, priv, nil, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when env path is unreadable as file")
	}
	if !strings.Contains(stderr, "failed to read env file") {
		t.Fatalf("expected error about reading env file; got: %q", stderr)
	}
}

// helper: replace the sealed value for key in envPath with the provided sealed string.
func replaceSealedValue(t *testing.T, envPath, key, sealed string) {
	t.Helper()
	if err := env.UpdateEnvFile(envPath, key, sealed); err != nil {
		t.Fatalf("UpdateEnvFile failed: %v", err)
	}
}

// TestUnseal_InvalidBase64Mlkem triggers the "invalid base64 mlkem ciphertext" branch.
func TestUnseal_InvalidBase64Mlkem(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	// create keypair and a sealed entry
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}
	if code := SealWithPlaintext(pub, envFile, "K", []byte("v"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: %d %q", code, errBuf.String())
	}

	// get existing sealed parts
	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	orig := envMap["K"]
	payload := strings.TrimPrefix(orig, prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}
	// craft invalid mlkem base64
	newSealed := prefix + "!!!" + sep + parts[1]
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid mlkem base64")
	}
	if !strings.Contains(stderr, "invalid base64 mlkem ciphertext") {
		t.Fatalf("expected invalid base64 mlkem ciphertext error; got: %q", stderr)
	}
}

// TestUnseal_InvalidBase64Gcm triggers the "invalid base64 gcm blob" branch.
func TestUnseal_InvalidBase64Gcm(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}
	if code := SealWithPlaintext(pub, envFile, "K", []byte("v"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: %d %q", code, errBuf.String())
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	orig := envMap["K"]
	payload := strings.TrimPrefix(orig, prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}
	// craft invalid gcm base64
	newSealed := prefix + parts[0] + sep + "!!!"
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid gcm base64")
	}
	if !strings.Contains(stderr, "invalid base64 gcm blob") {
		t.Fatalf("expected invalid base64 gcm blob error; got: %q", stderr)
	}
}

// TestUnseal_DecapsulationFailed triggers the decapsulation failure branch by replacing
// the mlkem ciphertext with random bytes (base64-encoded).
func TestUnseal_DecapsulationFailed(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}
	if code := SealWithPlaintext(pub, envFile, "K", []byte("v"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: %d %q", code, errBuf.String())
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	orig := envMap["K"]
	payload := strings.TrimPrefix(orig, prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}

	// generate random bytes for mlkem ciphertext (will not decapsulate)
	rb := make([]byte, 200)
	if _, err := rand.Read(rb); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	mlkemB64 := base64.StdEncoding.EncodeToString(rb)
	newSealed := prefix + mlkemB64 + sep + parts[1]
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for decapsulation failure")
	}
	if !strings.Contains(stderr, "decapsulation failed") {
		t.Fatalf("expected decapsulation failed error; got: %q", stderr)
	}
}

// TestUnseal_DecryptionFailed triggers the decryption failure branch by tampering the GCM blob.
func TestUnseal_DecryptionFailed(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}
	if code := SealWithPlaintext(pub, envFile, "K", []byte("v"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: %d %q", code, errBuf.String())
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	orig := envMap["K"]
	payload := strings.TrimPrefix(orig, prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}

	// decode gcm blob, tamper a byte, re-encode
	gcmBlob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode existing gcm blob: %v", err)
	}
	if len(gcmBlob) == 0 {
		t.Fatalf("gcm blob unexpectedly empty")
	}
	gcmBlob[len(gcmBlob)-1] ^= 0xFF
	gcmB64 := base64.StdEncoding.EncodeToString(gcmBlob)

	newSealed := prefix + parts[0] + sep + gcmB64
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for decryption failure")
	}
	if !strings.Contains(stderr, "decryption failed") {
		t.Fatalf("expected decryption failed error; got: %q", stderr)
	}
}

// TestKeypairWithPaths_PrivateWriteFail ensures KeypairWithPaths returns non-zero and prints an error
// when writing the private key fails (e.g., target path is a directory).
func TestKeypairWithPaths_PrivateWriteFail(t *testing.T) {
	td := t.TempDir()
	// Make priv path a directory to provoke a write error.
	privDir := filepath.Join(td, "privdir")
	if err := os.Mkdir(privDir, 0o755); err != nil {
		t.Fatalf("mkdir privdir: %v", err)
	}
	pub := filepath.Join(td, "pub.b64")

	var outBuf, errBuf bytes.Buffer
	code := KeypairWithPaths(privDir, pub, &outBuf, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when private key write fails")
	}
	if !strings.Contains(errBuf.String(), "failed to write private key") {
		t.Fatalf("expected private key write error; got: %q", errBuf.String())
	}
}

// TestKeypairWithPaths_PublicWriteFail ensures KeypairWithPaths cleans up the private key
// and returns non-zero when writing the public key fails.
func TestKeypairWithPaths_PublicWriteFail(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	// Make pub path a directory to provoke a write error for the public key.
	pubDir := filepath.Join(td, "pubdir")
	if err := os.Mkdir(pubDir, 0o755); err != nil {
		t.Fatalf("mkdir pubdir: %v", err)
	}

	var outBuf, errBuf bytes.Buffer
	code := KeypairWithPaths(priv, pubDir, &outBuf, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit code when public key write fails")
	}
	if !strings.Contains(errBuf.String(), "failed to write public key") {
		t.Fatalf("expected public key write error; got: %q", errBuf.String())
	}

	// private key should have been removed on public write failure
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Fatalf("expected private key to be removed on public write failure; stat err=%v", err)
	}
}

// runSeal calls SealWithPlaintext with fresh buffers and returns (code, stderr).
func runSeal(t *testing.T, pubPath, outPath, key string, plaintext []byte) (int, string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code := SealWithPlaintext(pubPath, outPath, key, plaintext, &outBuf, &errBuf)
	return code, errBuf.String()
}

func createInvalidBase64Pub(t *testing.T, pubPath string) {
	t.Helper()
	writeFile(t, pubPath, []byte("not-base64!!!\n"), 0o644)
}

func createShortPub(t *testing.T, pubPath string) {
	t.Helper()
	// write base64 of a short/invalid public key to provoke NewEncapsulationKey768 error
	short := []byte{0x01, 0x02, 0x03}
	writeFile(t, pubPath, []byte(base64.StdEncoding.EncodeToString(short)+"\n"), 0o644)
}

// TestSealWithPlaintext_PubFileMissing verifies SealWithPlaintext returns non-zero and prints an error
// when the public key file cannot be read.
func TestSealWithPlaintext_PubFileMissing(t *testing.T) {
	td := t.TempDir()
	pub := filepath.Join(td, "no-such-pub.b64")
	outPath := filepath.Join(td, "out.env")

	code, stderr := runSeal(t, pub, outPath, "K", []byte("v"))
	if code == 0 {
		t.Fatalf("expected non-zero exit code when public key file missing")
	}
	if !strings.Contains(stderr, "failed to read public key file") {
		t.Fatalf("expected error about reading public key file; got: %q", stderr)
	}
}

// TestSealWithPlaintext_InvalidBase64Pub verifies SealWithPlaintext returns non-zero for invalid base64 public key.
func TestSealWithPlaintext_InvalidBase64Pub(t *testing.T) {
	td := t.TempDir()
	pub := filepath.Join(td, "pub.b64")
	outPath := filepath.Join(td, "out.env")

	createInvalidBase64Pub(t, pub)

	code, stderr := runSeal(t, pub, outPath, "K", []byte("v"))
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid base64 public key")
	}
	if !strings.Contains(stderr, "invalid base64 public key") {
		t.Fatalf("expected invalid base64 public key error; got: %q", stderr)
	}
}

// TestSealWithPlaintext_InvalidPubKey verifies SealWithPlaintext returns non-zero when the public key bytes are invalid.
func TestSealWithPlaintext_InvalidPubKey(t *testing.T) {
	td := t.TempDir()
	pub := filepath.Join(td, "pub.b64")
	outPath := filepath.Join(td, "out.env")

	createShortPub(t, pub)

	code, stderr := runSeal(t, pub, outPath, "K", []byte("v"))
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid public key material")
	}
	if !strings.Contains(stderr, "invalid public key") {
		t.Fatalf("expected invalid public key error; got: %q", stderr)
	}
}

// TestSealWithPlaintext_UpdateEnvFileFail verifies SealWithPlaintext returns non-zero when updating the env file fails.
// We provoke UpdateEnvFile failure by using a directory path as outPath.
func TestSealWithPlaintext_UpdateEnvFileFail(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	// create a valid keypair so SealWithPlaintext can proceed to env update
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// Make outPath a directory to provoke UpdateEnvFile error
	outDir := filepath.Join(td, "outdir")
	if err := os.Mkdir(outDir, 0o755); err != nil {
		t.Fatalf("mkdir outdir: %v", err)
	}

	code, stderr := runSeal(t, pub, outDir, "K", []byte("v"))
	if code == 0 {
		t.Fatalf("expected non-zero exit code when UpdateEnvFile fails")
	}
	if !strings.Contains(stderr, "failed to update env file") {
		t.Fatalf("expected failed to update env file error; got: %q", stderr)
	}
}

// TestUnseal_ValueNotSealed ensures UnsealFromFiles returns an error when a requested key's value
// does not start with the sealed prefix (covers the "missing prefix" return 1 branch).
func TestUnseal_ValueNotSealed(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	// create keypair so we have a valid private key file
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}

	// create an env file with a non-sealed value for KEY
	if err := os.WriteFile(envFile, []byte("KEY=plainvalue\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	// request KEY explicitly to force the branch
	code, stderr := runUnseal(t, envFile, priv, []string{"KEY"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for non-sealed value")
	}
	if !strings.Contains(stderr, "does not appear to be sealed") {
		t.Fatalf("expected missing-prefix error; got: %q", stderr)
	}
}
