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

// TODO: use https://pkg.go.dev/runtime/secret to clean up secrets from memory

import (
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

// ExitError is returned by command functions to indicate the desired exit code.
// The caller (typically main) is responsible for printing the error message
// and calling os.Exit with the provided code.
type ExitError struct {
	Code int
	Err  error
}

func (e ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

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
// Public, testable functions that return printable strings and errors.
// These functions do NOT call os.Exit or print error messages themselves.
// The caller (main/cli) should print returned strings and handle ExitError codes.
//

// KeypairWithPaths generates a keypair and writes the private and public files.
// On success it returns a printable string describing the result (caller may print it).
// On failure it returns an ExitError (with Code) or a plain error.
func KeypairWithPaths(privPath, pubPath string) (string, error) {
	// Generate decapsulation (private) key
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to generate key: %w", err)}
	}
	priv := dk.Bytes() // 64 bytes seed form (private)
	ek := dk.EncapsulationKey()
	pub := ek.Bytes() // public encapsulation key bytes

	// Encode to base64 text
	privB64 := []byte(base64.StdEncoding.EncodeToString(priv) + "\n")
	pubB64Bytes := []byte(base64.StdEncoding.EncodeToString(pub) + "\n")

	// Write private key atomically with 0600 permissions
	if err := file.WriteFileAtomic(privPath, privB64, 0o600); err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to write private key: %w", err)}
	}

	// Write public key atomically with 0644 permissions
	if err := file.WriteFileAtomic(pubPath, pubB64Bytes, 0o644); err != nil {
		// attempt to remove private key if public write fails
		_ = os.Remove(privPath)
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to write public key: %w", err)}
	}

	absPriv, _ := filepath.Abs(privPath)
	absPub, _ := filepath.Abs(pubPath)

	out := fmt.Sprintf(
		"Wrote private key to %s (mode 0600)\nWrote public key to %s (mode 0644)\n\nPUBLIC (base64):\n%s\n",
		absPriv, absPub, strings.TrimSpace(string(pubB64Bytes)),
	)

	// avoid unused var warnings in some build contexts
	_ = ek
	_ = pub

	return out, nil
}

// SealWithPlaintext seals the provided plaintext using the public key file at pubPath,
// writes the sealed value into outPath under keyName (via env.UpdateEnvFile), and
// returns a printable success string on success. No printing is performed here.
func SealWithPlaintext(pubPath, outPath, keyName string, plaintext []byte) (string, error) {
	pubBytesRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to read public key file %s: %w", pubPath, err)}
	}

	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubBytesRaw)))
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("invalid base64 public key in %s: %w", pubPath, err)}
	}

	ek, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("invalid public key in %s: %w", pubPath, err)}
	}

	pt := make([]byte, len(plaintext))
	copy(pt, plaintext)

	sharedKey, mlkemCiphertext := ek.Encapsulate()
	if len(sharedKey) != mlkem.SharedKeySize {
		return "", ExitError{Code: 1, Err: fmt.Errorf("unexpected shared key size: %d", len(sharedKey))}
	}

	gcmBlob, err := encryptAESGCM(sharedKey, pt)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("encryption failed: %w", err)}
	}

	mlkemB64 := base64.StdEncoding.EncodeToString(mlkemCiphertext)
	gcmB64 := base64.StdEncoding.EncodeToString(gcmBlob)
	sealed := prefix + mlkemB64 + sep + gcmB64

	if err := env.UpdateEnvFile(outPath, keyName, sealed); err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to update env file %s: %w", outPath, err)}
	}

	out := fmt.Sprintf("Wrote %s to %s\n", keyName, outPath)
	return out, nil
}

// UnsealFromFiles reads the env file at inPath and the private key at privPath,
// decapsulates and decrypts the requested keys (if keys is empty, all sealed keys).
// On success it returns either a JSON string (if jsonOut) or newline-separated env entries.
func UnsealFromFiles(inPath, privPath string, keys []string, jsonOut bool) (string, error) {
	// Read private key file
	privFileBytes, err := os.ReadFile(privPath)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to read private key file %s: %w", privPath, err)}
	}
	privText := strings.TrimSpace(string(privFileBytes))
	privBytes, err := base64.StdEncoding.DecodeString(privText)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("invalid base64 private key in %s: %w", privPath, err)}
	}

	dk, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("invalid private key in %s: %w", privPath, err)}
	}

	// Parse env file into map of key->rawValue (logical unquoted value)
	envMap, err := env.ParseEnvFile(inPath)
	if err != nil {
		return "", ExitError{Code: 1, Err: fmt.Errorf("failed to read env file %s: %w", inPath, err)}
	}

	// If no keys provided, select all keys whose stored value starts with the sealed prefix
	if len(keys) == 0 {
		for k, v := range envMap {
			if strings.HasPrefix(v, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			// No sealed entries is not an error; return empty output.
			return "", nil
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
		return "", ExitError{Code: 2, Err: fmt.Errorf("missing keys in %s: %s", inPath, strings.Join(missing, ", "))}
	}

	// Collect decrypted values
	decrypted := make(map[string]string, len(keys))

	for _, k := range keys {
		stored := envMap[k]
		if !strings.HasPrefix(stored, prefix) {
			return "", ExitError{Code: 1, Err: fmt.Errorf("value for %s does not appear to be sealed (missing prefix)", k)}
		}
		payload := strings.TrimPrefix(stored, prefix)
		parts := strings.SplitN(payload, sep, 2)
		if len(parts) != 2 {
			return "", ExitError{Code: 1, Err: fmt.Errorf("sealed value for %s malformed", k)}
		}
		mlkemB64 := parts[0]
		gcmB64 := parts[1]

		mlkemCiphertext, err := base64.StdEncoding.DecodeString(mlkemB64)
		if err != nil {
			return "", ExitError{Code: 1, Err: fmt.Errorf("invalid base64 mlkem ciphertext for %s: %w", k, err)}
		}
		gcmBlob, err := base64.StdEncoding.DecodeString(gcmB64)
		if err != nil {
			return "", ExitError{Code: 1, Err: fmt.Errorf("invalid base64 gcm blob for %s: %w", k, err)}
		}

		sharedKey, err := dk.Decapsulate(mlkemCiphertext)
		if err != nil {
			return "", ExitError{Code: 1, Err: fmt.Errorf("decapsulation failed for %s: %w", k, err)}
		}
		if len(sharedKey) != mlkem.SharedKeySize {
			return "", ExitError{Code: 1, Err: fmt.Errorf("unexpected shared key size for %s: %d", k, len(sharedKey))}
		}

		plaintext, err := decryptAESGCM(sharedKey, gcmBlob)
		if err != nil {
			return "", ExitError{Code: 1, Err: fmt.Errorf("decryption failed for %s: %w", k, err)}
		}

		decrypted[k] = string(plaintext)
	}

	// Build output
	if jsonOut {
		js, err := json.Marshal(decrypted)
		if err != nil {
			return "", ExitError{Code: 1, Err: fmt.Errorf("failed to marshal JSON: %w", err)}
		}
		return string(js), nil
	}

	// .env-safe lines
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(env.FormatEnvEntry(k, decrypted[k]))
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n"), nil
}
