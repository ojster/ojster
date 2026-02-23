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

package pqc

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ojster/ojster/internal/util/env"
)

// ----------------------------- helpers ------------------------------------

func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func tmpPaths(t *testing.T) (priv, pub, envFile string) {
	t.Helper()
	td := t.TempDir()
	return filepath.Join(td, "priv.b64"), filepath.Join(td, "pub.b64"), filepath.Join(td, "secrets.env")
}

func runUnseal(t *testing.T, envPath, privPath string, keys []string, jsonOut bool) (int, string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code := UnsealFromFiles(envPath, privPath, keys, jsonOut, &outBuf, &errBuf)
	return code, errBuf.String()
}

func runSeal(t *testing.T, pubPath, outPath, key string, plaintext []byte) (int, string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code := SealWithPlaintext(pubPath, outPath, key, plaintext, &outBuf, &errBuf)
	return code, errBuf.String()
}

func createMinimalEnv(t *testing.T, path string) {
	t.Helper()
	writeFile(t, path, []byte("A=1\n"), 0o600)
}

func createInvalidBase64Priv(t *testing.T, privPath string) {
	t.Helper()
	writeFile(t, privPath, []byte("not-base64!!!\n"), 0o600)
}

func createShortPriv(t *testing.T, privPath string) {
	t.Helper()
	short := []byte{0x01, 0x02, 0x03}
	writeFile(t, privPath, []byte(base64.StdEncoding.EncodeToString(short)+"\n"), 0o600)
}

func createInvalidBase64Pub(t *testing.T, pubPath string) {
	t.Helper()
	writeFile(t, pubPath, []byte("not-base64!!!\n"), 0o644)
}

func createShortPub(t *testing.T, pubPath string) {
	t.Helper()
	short := []byte{0x01, 0x02, 0x03}
	writeFile(t, pubPath, []byte(base64.StdEncoding.EncodeToString(short)+"\n"), 0o644)
}

func replaceSealedValue(t *testing.T, envPath, key, sealed string) {
	t.Helper()
	if err := env.UpdateEnvFile(envPath, key, sealed); err != nil {
		t.Fatalf("UpdateEnvFile failed: %v", err)
	}
}

func readTrim(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}

// ----------------------------- keypair tests -------------------------------

func TestKeypairWithPaths_OutputFormat(t *testing.T) {
	priv, pub, _ := tmpPaths(t)

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}
	pubB64 := readTrim(t, pub)
	if !strings.Contains(outBuf.String(), strings.TrimSpace(pubB64)) {
		t.Fatalf("expected output to include public key base64; got: %q", outBuf.String())
	}
}

func TestKeypairWithPaths_PrivateWriteFail(t *testing.T) {
	td := t.TempDir()
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

func TestKeypairWithPaths_PublicWriteFail(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
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
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Fatalf("expected private key to be removed on public write failure; stat err=%v", err)
	}
}

// ----------------------------- seal tests ---------------------------------

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

func TestSealWithPlaintext_UpdateEnvFileFail(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

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

// ----------------------------- unseal tests -------------------------------

func TestUnsealMap_HappyPath(t *testing.T) {
	priv, pub, envFile := tmpPaths(t)

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	keyName := "MY_SECRET_MAP"
	plaintext := []byte("map-secret-value")
	if code := SealWithPlaintext(pub, envFile, keyName, plaintext, &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: code=%d stderr=%q", code, errBuf.String())
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}

	// Call UnsealMap and expect a decrypted map directly
	decrypted, err := UnsealMap(envMap, priv, []string{keyName})
	if err != nil {
		t.Fatalf("UnsealMap failed: err=%v", err)
	}
	if got, ok := decrypted[keyName]; !ok {
		t.Fatalf("UnsealMap result missing key %s", keyName)
	} else if got != string(plaintext) {
		t.Fatalf("unsealed mismatch: want=%q got=%q", string(plaintext), got)
	}
}

func TestUnsealMap_PrivFileMissing(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "no-such-priv.b64")
	envFile := filepath.Join(td, "env.env")

	// create an env file with a sealed-looking value so UnsealMap will attempt to read the key
	if err := os.WriteFile(envFile, []byte("A=1\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}

	decrypted, err := UnsealMap(envMap, priv, nil)
	if err == nil {
		t.Fatalf("expected error when private key file missing; got decrypted=%v", decrypted)
	}
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("expected ErrConfig for missing private key, got: %v", err)
	}
}

func TestUnsealMap_MalformedSealedValue(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}
	if code := SealWithPlaintext(pub, envFile, "BAD", []byte("v"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: code=%d stderr=%q", code, errBuf.String())
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	// Replace the sealed value with a malformed payload (no separator)
	envMap["BAD"] = Prefix + "onlyonepart"

	decrypted, err := UnsealMap(envMap, priv, []string{"BAD"})
	if err == nil {
		t.Fatalf("expected error for malformed sealed value; got decrypted=%v", decrypted)
	}
	if !errors.Is(err, ErrUnseal) {
		t.Fatalf("expected ErrUnseal for malformed sealed value, got: %v", err)
	}
}

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

func TestUnsealFromFiles_ParseEnvFileError(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, filepath.Join(td, "pub.b64"), &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

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

func TestUnseal_ValueNotSealed(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}

	if err := os.WriteFile(envFile, []byte("KEY=plainvalue\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	code, stderr := runUnseal(t, envFile, priv, []string{"KEY"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for non-sealed value")
	}
	if !strings.Contains(stderr, "does not appear to be sealed") {
		t.Fatalf("expected missing-prefix error; got: %q", stderr)
	}
}

func TestUnseal_InvalidBase64Mlkem(t *testing.T) {
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
	payload := strings.TrimPrefix(orig, Prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}

	newSealed := Prefix + "!!!" + sep + parts[1]
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid mlkem base64")
	}
	if !strings.Contains(stderr, "invalid base64 mlkem ciphertext") {
		t.Fatalf("expected invalid base64 mlkem ciphertext error; got: %q", stderr)
	}
}

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
	payload := strings.TrimPrefix(orig, Prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}

	newSealed := Prefix + parts[0] + sep + "!!!"
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for invalid gcm base64")
	}
	if !strings.Contains(stderr, "invalid base64 gcm blob") {
		t.Fatalf("expected invalid base64 gcm blob error; got: %q", stderr)
	}
}

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
	payload := strings.TrimPrefix(orig, Prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}

	rb := make([]byte, 200)
	if _, err := rand.Read(rb); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	mlkemB64 := base64.StdEncoding.EncodeToString(rb)
	newSealed := Prefix + mlkemB64 + sep + parts[1]
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for decapsulation failure")
	}
	if !strings.Contains(stderr, "decapsulation failed") {
		t.Fatalf("expected decapsulation failed error; got: %q", stderr)
	}
}

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
	payload := strings.TrimPrefix(orig, Prefix)
	parts := strings.SplitN(payload, sep, 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed format: %q", orig)
	}

	gcmBlob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode existing gcm blob: %v", err)
	}
	if len(gcmBlob) == 0 {
		t.Fatalf("gcm blob unexpectedly empty")
	}
	gcmBlob[len(gcmBlob)-1] ^= 0xFF
	gcmB64 := base64.StdEncoding.EncodeToString(gcmBlob)

	newSealed := Prefix + parts[0] + sep + gcmB64
	replaceSealedValue(t, envFile, "K", newSealed)

	code, stderr := runUnseal(t, envFile, priv, []string{"K"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for decryption failure")
	}
	if !strings.Contains(stderr, "decryption failed") {
		t.Fatalf("expected decryption failed error; got: %q", stderr)
	}
}

func TestUnseal_NoSealedEntries_NoOutput(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "plain.env")

	// create a valid keypair so UnsealFromFiles can run
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// write an env file that has no sealed entries (only plain values)
	if err := os.WriteFile(envFile, []byte("A=1\nB=2\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	// Request all sealed entries (nil keys) — there are none.
	var stdout, stderr bytes.Buffer
	code := UnsealFromFiles(envFile, priv, nil, false, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected success when no sealed entries exist, got code=%d stderr=%q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got: %q", stderr.String())
	}
}

func TestUnsealFromFiles_MissingKey_Message(t *testing.T) {
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

	// Reset buffers to ensure we only observe UnsealFromFiles output.
	outBuf.Reset()
	errBuf.Reset()

	// request a missing key and assert the specific error message and exit code
	code := UnsealFromFiles(envFile, priv, []string{"MISSING"}, false, &outBuf, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing keys, got %d stderr=%q", code, errBuf.String())
	}
	stderr := errBuf.String()
	if !strings.Contains(stderr, "missing keys in") || !strings.Contains(stderr, envFile) || !strings.Contains(stderr, "MISSING") {
		t.Fatalf("expected missing-keys message to mention env path and key; got stderr=%q", stderr)
	}
}

func TestUnseal_SealedValueMalformedParts(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "env.env")

	// create valid keypair so UnsealFromFiles can run and reach parsing of the stored value
	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: %d %q", code, errBuf.String())
	}

	// Write an env file where the value looks like a sealed value (has Prefix)
	// but the payload does not contain the expected separator, so SplitN yields != 2.
	malformed := Prefix + "onlyonepart" // no sep present
	if err := os.WriteFile(envFile, []byte("BAD="+malformed+"\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	// Request the BAD key explicitly to trigger the malformed-parts branch.
	code, stderr := runUnseal(t, envFile, priv, []string{"BAD"}, false)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for malformed sealed value parts")
	}
	if !strings.Contains(stderr, "sealed value for BAD malformed") {
		t.Fatalf("expected sealed-value-malformed message; got stderr=%q", stderr)
	}
}

// ----------------------------- roundtrip & AES -----------------------------

func TestSealAndUnseal_HappyPath(t *testing.T) {
	priv, pub, envFile := tmpPaths(t)

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	keyName := "MY_SECRET"
	plaintext := []byte("super-secret-value")
	if code := SealWithPlaintext(pub, envFile, keyName, plaintext, &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: code=%d stderr=%q", code, errBuf.String())
	}

	envMap, err := env.ParseEnvFile(envFile)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	val, ok := envMap[keyName]
	if !ok {
		t.Fatalf("env file missing key %s", keyName)
	}
	if !strings.HasPrefix(val, Prefix) {
		t.Fatalf("sealed value missing prefix: %q", val)
	}

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

	var envOut bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, []string{keyName}, false, &envOut, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles(env) failed: code=%d stderr=%q", code, errBuf.String())
	}
	parsed, err := env.ParseEnvReader(strings.NewReader(envOut.String()))
	if err != nil {
		t.Fatalf("ParseEnvReader failed: %v", err)
	}
	if parsed[keyName] != string(plaintext) {
		t.Fatalf("unsealed mismatch env: want=%q got=%q", string(plaintext), parsed[keyName])
	}
}

func TestRoundtripMultipleKeys(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "multi.env")

	var outBuf, errBuf bytes.Buffer
	if code := KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	keys := []string{"A", "B", "C"}
	values := map[string][]byte{
		"A": []byte("va"),
		"B": []byte("vb"),
		"C": []byte("vc"),
	}
	if err := os.WriteFile(envFile, []byte(""), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	for _, k := range keys {
		if code := SealWithPlaintext(pub, envFile, k, values[k], &outBuf, &errBuf); code != 0 {
			t.Fatalf("SealWithPlaintext failed for %s: code=%d stderr=%q", k, code, errBuf.String())
		}
	}

	var outJSON bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, nil, true, &outJSON, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles failed: code=%d stderr=%q", code, errBuf.String())
	}
	var got map[string]string
	if err := json.Unmarshal(outJSON.Bytes(), &got); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	for k, v := range values {
		if got[k] != string(v) {
			t.Fatalf("value mismatch for %s: want=%q got=%q", k, string(v), got[k])
		}
	}

	sort.Strings(keys)
	var envOut bytes.Buffer
	if code := UnsealFromFiles(envFile, priv, keys, false, &envOut, &errBuf); code != 0 {
		t.Fatalf("UnsealFromFiles failed: code=%d stderr=%q", code, errBuf.String())
	}
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

// ----------------------------- AES helpers tests --------------------------

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

// ------------------------------ regex roundtrip ---------------------------

func TestBuildParseRegexRoundtrip(t *testing.T) {
	// create two random-ish byte slices (not cryptographically important for this test)
	mlkem := []byte{0x01, 0x02, 0x03, 0x04}
	gcm := []byte{0x05, 0x06, 0x07}

	// Build sealed value
	sealed := BuildSealed(mlkem, gcm)

	// IsSealed should accept it (unquoted)
	if !IsSealed(sealed) {
		t.Fatalf("BuildSealed produced value that IsSealed rejects: %q", sealed)
	}

	// ParseSealed should return the two base64 parts
	mlkemB64, gcmB64, err := ParseSealed(sealed)
	if err != nil {
		t.Fatalf("ParseSealed failed: %v", err)
	}
	// verify base64 roundtrip
	if got := base64.StdEncoding.EncodeToString(mlkem); got != mlkemB64 {
		t.Fatalf("mlkem base64 mismatch: want=%q got=%q", got, mlkemB64)
	}
	if got := base64.StdEncoding.EncodeToString(gcm); got != gcmB64 {
		t.Fatalf("gcm base64 mismatch: want=%q got=%q", got, gcmB64)
	}

	// DefaultValueRegexp should match both unquoted and single-quoted forms
	re, err := DefaultValueRegexp()
	if err != nil {
		t.Fatalf("DefaultValueRegexp compile failed: %v", err)
	}
	if !re.MatchString(sealed) {
		t.Fatalf("DefaultValueRegexp did not match sealed value: %q", sealed)
	}
	quoted := "'" + sealed + "'"
	if !re.MatchString(quoted) {
		t.Fatalf("DefaultValueRegexp did not match quoted sealed value: %q", quoted)
	}
}
