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
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ojster/ojster/internal/util/env"
	"github.com/ojster/ojster/internal/util/file"
)

const (
	nonceSizeGCM    = 12 // TODO: decide if this size is sufficient
	defaultPrivFile = "ojster_priv.key"
	defaultPubFile  = "ojster_pub.key"
	prefix          = "OJSTER-1:"
	sep             = ":" // separator between mlkem ciphertext and gcm blob
)

func DefaultPrivFile() string { return defaultPrivFile }
func DefaultPubFile() string  { return defaultPubFile }

//
// AES helpers (internal)
//

// encryptAESGCM encrypts plaintext with key (32 bytes) using AES-256-GCM.
// Returns nonce||ciphertext (nonce first).
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256-GCM")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSizeGCM)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// decryptAESGCM expects blob = nonce||ciphertext
func decryptAESGCM(key, blob []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256-GCM")
	}
	if len(blob) < nonceSizeGCM {
		return nil, errors.New("gcm blob too short")
	}
	nonce := blob[:nonceSizeGCM]
	ct := blob[nonceSizeGCM:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

//
// Public, testable functions that write to io.Writer and return an exit code.
// These functions do NOT call os.Exit. The caller (main/cli) should call os.Exit
// with the returned code and may print additional context if desired.
//

// KeypairWithPaths generates a keypair and writes the private and public files.
// On success it writes a short summary to outw and returns 0.
// On failure it writes an error message to errw and returns a non-zero exit code.
func KeypairWithPaths(privPath, pubPath string, outw io.Writer, errw io.Writer) int {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to generate key: %w", err))
		return 1
	}
	priv := dk.Bytes() // 64 bytes seed form (private)
	ek := dk.EncapsulationKey()
	pub := ek.Bytes() // public encapsulation key bytes

	// Encode to base64 text
	privB64 := []byte(base64.StdEncoding.EncodeToString(priv) + "\n")
	pubB64Bytes := []byte(base64.StdEncoding.EncodeToString(pub) + "\n")

	// Write private key atomically with 0600 permissions
	if err := file.WriteFileAtomic(privPath, privB64, 0o600); err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to write private key: %w", err))
		return 1
	}

	// Write public key atomically with 0644 permissions
	if err := file.WriteFileAtomic(pubPath, pubB64Bytes, 0o644); err != nil {
		_ = os.Remove(privPath)
		fmt.Fprintln(errw, fmt.Errorf("failed to write public key: %w", err))
		return 1
	}

	absPriv, _ := filepath.Abs(privPath)
	absPub, _ := filepath.Abs(pubPath)

	outMsg := fmt.Sprintf(
		"Wrote private key to %s (mode 0600)\nWrote public key to %s (mode 0644)\n\nPUBLIC (base64):\n%s\n",
		absPriv, absPub, strings.TrimSpace(string(pubB64Bytes)),
	)

	if outw != nil {
		_, _ = io.WriteString(outw, outMsg)
	}

	// avoid unused var warnings in some build contexts
	_ = ek
	_ = pub

	return 0
}

// SealWithPlaintext seals the provided plaintext using the public key file at pubPath,
// writes the sealed value into outPath under keyName (via env.UpdateEnvFile), and
// writes a short success message to outw. Returns an exit code and writes errors to errw.
func SealWithPlaintext(pubPath, outPath, keyName string, plaintext []byte, outw io.Writer, errw io.Writer) int {
	pubBytesRaw, err := os.ReadFile(pubPath)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to read public key file %s: %w", pubPath, err))
		return 1
	}

	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubBytesRaw)))
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("invalid base64 public key in %s: %w", pubPath, err))
		return 1
	}

	ek, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("invalid public key in %s: %w", pubPath, err))
		return 1
	}

	pt := make([]byte, len(plaintext))
	copy(pt, plaintext)

	sharedKey, mlkemCiphertext := ek.Encapsulate()
	if len(sharedKey) != mlkem.SharedKeySize {
		fmt.Fprintln(errw, fmt.Errorf("unexpected shared key size: %d", len(sharedKey)))
		return 1
	}

	gcmBlob, err := encryptAESGCM(sharedKey, pt)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("encryption failed: %w", err))
		return 1
	}

	mlkemB64 := base64.StdEncoding.EncodeToString(mlkemCiphertext)
	gcmB64 := base64.StdEncoding.EncodeToString(gcmBlob)
	sealed := prefix + mlkemB64 + sep + gcmB64

	if err := env.UpdateEnvFile(outPath, keyName, sealed); err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to update env file %s: %w", outPath, err))
		return 1
	}

	if outw != nil {
		_, _ = io.WriteString(outw, fmt.Sprintf("Wrote %s to %s\n", keyName, outPath))
	}
	_ = ek
	return 0
}

// loadDecapsulationKey reads privPath, base64-decodes it and returns a DecapsulationKey.
// On error it writes the same error messages as before to errw and returns a non-zero exit code.
func loadDecapsulationKey(privPath string, errw io.Writer) (*mlkem.DecapsulationKey768, int) {
	privFileBytes, err := os.ReadFile(privPath)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to read private key file %s: %w", privPath, err))
		return nil, 1
	}
	privText := strings.TrimSpace(string(privFileBytes))
	privBytes, err := base64.StdEncoding.DecodeString(privText)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("invalid base64 private key in %s: %w", privPath, err))
		return nil, 1
	}

	dk, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("invalid private key in %s: %w", privPath, err))
		return nil, 1
	}
	return dk, 0
}

// UnsealMap decrypts the provided envMap using the private key at privPath.
// It returns the decrypted map (only keys that were successfully decrypted), an exit code,
// and a textual error message (stderr) if non-zero code. Exit codes match UnsealFromFiles:
// 0 success, 1 error, 2 missing keys.
func UnsealMap(envMap map[string]string, privPath string, keys []string) (map[string]string, int, string) {
	// capture stderr from loadDecapsulationKey
	var errBuf bytes.Buffer
	dk, code := loadDecapsulationKey(privPath, &errBuf)
	if code != 0 {
		return nil, code, strings.TrimSpace(errBuf.String())
	}

	decrypted, _, code, msg := decryptCore(envMap, dk, keys, "<map input>")
	if code != 0 {
		// return the message so callers can decide HTTP status mapping
		return nil, code, msg
	}
	return decrypted, 0, ""
}

// UnsealFromFiles reads the env file at inPath and the private key at privPath,
// decapsulates and decrypts the requested keys (if keys is empty, all sealed keys).
// On success it writes either JSON (if jsonOut) or newline-separated env entries to outw.
// Returns an exit code and writes errors to errw.
func UnsealFromFiles(inPath, privPath string, keys []string, jsonOut bool, outw io.Writer, errw io.Writer) int {
	dk, code := loadDecapsulationKey(privPath, errw)
	if code != 0 {
		return code
	}

	// Parse env file into map of key->rawValue (logical unquoted value)
	envMap, err := env.ParseEnvFile(inPath)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to read env file %s: %w", inPath, err))
		return 1
	}

	return unsealCore(envMap, dk, keys, jsonOut, outw, errw, inPath)
}

// decryptCore performs the core selection/validation/decapsulation/decryption.
// It returns the decrypted map, the resolved keys slice (in deterministic order),
// an exit code, and an error message string (if non-zero code).
func decryptCore(envMap map[string]string, dk *mlkem.DecapsulationKey768, keys []string, sourceDesc string) (map[string]string, []string, int, string) {
	// If no keys provided, select all keys whose stored value starts with the sealed prefix
	if len(keys) == 0 {
		for k, v := range envMap {
			if strings.HasPrefix(v, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			// No sealed entries is not an error; return empty map and success.
			return map[string]string{}, keys, 0, ""
		}
	}

	// Validate requested keys exist
	missing := make([]string, 0)
	for _, k := range keys {
		if _, ok := envMap[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		msg := fmt.Sprintf("missing keys in %s: %s", sourceDesc, strings.Join(missing, ", "))
		return nil, nil, 2, msg
	}

	// Collect decrypted values
	decrypted := make(map[string]string, len(keys))

	for _, k := range keys {
		stored := envMap[k]
		if !strings.HasPrefix(stored, prefix) {
			msg := fmt.Sprintf("value for %s does not appear to be sealed (missing prefix)", k)
			return nil, nil, 1, msg
		}
		payload := strings.TrimPrefix(stored, prefix)
		parts := strings.SplitN(payload, sep, 2)
		if len(parts) != 2 {
			msg := fmt.Sprintf("sealed value for %s malformed", k)
			return nil, nil, 1, msg
		}
		mlkemB64 := parts[0]
		gcmB64 := parts[1]

		mlkemCiphertext, err := base64.StdEncoding.DecodeString(mlkemB64)
		if err != nil {
			msg := fmt.Sprintf("invalid base64 mlkem ciphertext for %s: %v", k, err)
			return nil, nil, 1, msg
		}
		gcmBlob, err := base64.StdEncoding.DecodeString(gcmB64)
		if err != nil {
			msg := fmt.Sprintf("invalid base64 gcm blob for %s: %v", k, err)
			return nil, nil, 1, msg
		}

		sharedKey, err := dk.Decapsulate(mlkemCiphertext)
		if err != nil {
			msg := fmt.Sprintf("decapsulation failed for %s: %v", k, err)
			return nil, nil, 1, msg
		}
		if len(sharedKey) != mlkem.SharedKeySize {
			msg := fmt.Sprintf("unexpected shared key size for %s: %d", k, len(sharedKey))
			return nil, nil, 1, msg
		}

		plaintext, err := decryptAESGCM(sharedKey, gcmBlob)
		if err != nil {
			msg := fmt.Sprintf("decryption failed for %s: %v", k, err)
			return nil, nil, 1, msg
		}

		decrypted[k] = string(plaintext)
	}

	// Return decrypted map and the resolved keys (in the order we processed them)
	return decrypted, keys, 0, ""
}

func unsealCore(envMap map[string]string, dk *mlkem.DecapsulationKey768, keys []string, jsonOut bool, outw io.Writer, errw io.Writer, sourceDesc string) int {
	decrypted, resolvedKeys, code, msg := decryptCore(envMap, dk, keys, sourceDesc)
	if code != 0 {
		fmt.Fprintln(errw, msg)
		return code
	}

	// Build output
	if jsonOut {
		js, _ := json.Marshal(decrypted)
		if outw != nil {
			_, _ = outw.Write(js)
		}
		return 0
	}

	// .env-safe lines: preserve the resolvedKeys ordering (matches original behavior)
	var b strings.Builder
	for _, k := range resolvedKeys {
		b.WriteString(env.FormatEnvEntry(k, decrypted[k]))
		b.WriteByte('\n')
	}
	result := strings.TrimRight(b.String(), "\n")
	if outw != nil && result != "" {
		_, _ = io.WriteString(outw, result)
	}
	return 0
}
