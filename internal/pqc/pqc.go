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
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/util/env"
	"github.com/ojster/ojster/internal/util/file"
	"github.com/ojster/ojster/internal/util/tty"
)

const nonceSizeGCM = 12 // TODO: decide if this size is sufficient

// TODO: don't print anything here, not even JSON or stdout,
// but return strings which the caller should print on success
// Even abstract away the all cli args (flag.NewFlagSet) logic,
// should be handled by caller

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

// Keypair generates a keypair and writes files. It returns an error value
// describing the failure; callers should print the error and exit as needed.
func Keypair(args []string) error {
	fs := flag.NewFlagSet("keypair", flag.ContinueOnError)
	privPath := fs.String("priv-file", common.DefaultPrivFile, "private key filename to write (default ./"+common.DefaultPrivFile+")")
	pubPath := fs.String("pub-file", common.DefaultPubFile, "public key filename to write (default ./"+common.DefaultPubFile+")")
	if err := fs.Parse(args); err != nil {
		return ExitError{Code: 2, Err: err}
	}

	// Generate decapsulation (private) key
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to generate key: %w", err)}
	}
	priv := dk.Bytes() // 64 bytes seed form (private)
	ek := dk.EncapsulationKey()
	pub := ek.Bytes() // public encapsulation key bytes

	// Encode to base64 text
	privB64 := []byte(base64.StdEncoding.EncodeToString(priv) + "\n")
	pubB64 := []byte(base64.StdEncoding.EncodeToString(pub) + "\n")

	// Write private key atomically with 0600 permissions
	if err := file.WriteFileAtomic(*privPath, privB64, 0o600); err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to write private key: %w", err)}
	}

	// Write public key atomically with 0644 permissions
	if err := file.WriteFileAtomic(*pubPath, pubB64, 0o644); err != nil {
		// attempt to remove private key if public write fails
		_ = os.Remove(*privPath)
		return ExitError{Code: 1, Err: fmt.Errorf("failed to write public key: %w", err)}
	}

	// Print helpful info (do not print private key)
	absPriv, _ := filepath.Abs(*privPath)
	absPub, _ := filepath.Abs(*pubPath)
	fmt.Fprintf(os.Stdout, "Wrote private key to %s (mode 0600)\n", absPriv)
	fmt.Fprintf(os.Stdout, "Wrote public key to %s (mode 0644)\n", absPub)

	// Also print public key base64 for convenience (same as file content)
	fmt.Fprintln(os.Stdout, "\nPUBLIC (base64):")
	fmt.Fprintln(os.Stdout, strings.TrimSpace(string(pubB64)))

	return nil
}

// Seal reads a public key, plaintext from stdin, seals it and updates the env file.
// It returns an ExitError on failure; callers should print the error and exit.
func Seal(args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	pubPath := fs.String("pub-file", common.DefaultPubFile, "public key filename to read (default ./"+common.DefaultPubFile+")")
	outPath := fs.String("out", ".env", "env file path to write (default ./.env)")
	if err := fs.Parse(args); err != nil {
		return ExitError{Code: 2, Err: err}
	}

	if fs.NArg() != 1 {
		return ExitError{Code: 1, Err: fmt.Errorf("seal requires exactly one positional argument: KEY")}
	}
	keyName := fs.Arg(0)

	pubBytesRaw, err := os.ReadFile(*pubPath)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to read public key file %s: %w", *pubPath, err)}
	}

	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubBytesRaw)))
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("invalid base64 public key in %s: %w", *pubPath, err)}
	}

	ek, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("invalid public key in %s: %w", *pubPath, err)}
	}

	plaintext, err := tty.ReadSecretFromStdin(
		"Reading plaintext input from stdin (input will be hidden). Press Ctrl-D when done.\n",
	)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to read plaintext: %w", err)}
	}

	pt := make([]byte, len(plaintext))
	copy(pt, plaintext)

	sharedKey, mlkemCiphertext := ek.Encapsulate()
	if len(sharedKey) != mlkem.SharedKeySize {
		return ExitError{Code: 1, Err: fmt.Errorf("unexpected shared key size: %d", len(sharedKey))}
	}

	gcmBlob, err := encryptAESGCM(sharedKey, pt)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("encryption failed: %w", err)}
	}

	mlkemB64 := base64.StdEncoding.EncodeToString(mlkemCiphertext)
	gcmB64 := base64.StdEncoding.EncodeToString(gcmBlob)
	sealed := common.Prefix + mlkemB64 + common.Sep + gcmB64

	if err := env.UpdateEnvFile(*outPath, keyName, sealed); err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to update env file %s: %w", *outPath, err)}
	}

	fmt.Fprintf(os.Stderr, "Wrote %s to %s\n", keyName, *outPath)

	return nil
}

// Unseal reads an env file and a private key, decapsulates and decrypts values.
// It returns an ExitError on failure; callers should print the error and exit.
func Unseal(args []string) error {
	fs := flag.NewFlagSet("unseal", flag.ContinueOnError)
	inPath := fs.String("in", ".env", "env file path to read (default ./.env)")
	privPath := fs.String("priv-file", common.DefaultPrivFile, "private key filename to read (default ./"+common.DefaultPrivFile+")")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	if err := fs.Parse(args); err != nil {
		return ExitError{Code: 2, Err: err}
	}

	// Keys provided on command line (may be zero)
	keys := fs.Args()

	// Read private key file
	privFileBytes, err := os.ReadFile(*privPath)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to read private key file %s: %w", *privPath, err)}
	}
	privText := strings.TrimSpace(string(privFileBytes))
	privBytes, err := base64.StdEncoding.DecodeString(privText)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("invalid base64 private key in %s: %w", *privPath, err)}
	}

	dk, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("invalid private key in %s: %w", *privPath, err)}
	}

	// Parse env file into map of key->rawValue (logical unquoted value)
	envMap, err := env.ParseEnvFile(*inPath)
	if err != nil {
		return ExitError{Code: 1, Err: fmt.Errorf("failed to read env file %s: %w", *inPath, err)}
	}

	// If no keys provided, select all keys whose stored value starts with the sealed common.Prefix
	if len(keys) == 0 {
		for k, v := range envMap {
			if strings.HasPrefix(v, common.Prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			// No sealed entries is not an error; caller may print a message.
			return nil
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
		return ExitError{Code: 2, Err: fmt.Errorf("missing keys in %s: %s", *inPath, strings.Join(missing, ", "))}
	}

	// Collect decrypted values
	decrypted := make(map[string]string, len(keys))

	for _, k := range keys {
		stored := envMap[k]
		if !strings.HasPrefix(stored, common.Prefix) {
			return ExitError{Code: 1, Err: fmt.Errorf("value for %s does not appear to be sealed (missing common.Prefix)", k)}
		}
		payload := strings.TrimPrefix(stored, common.Prefix)
		parts := strings.SplitN(payload, common.Sep, 2)
		if len(parts) != 2 {
			return ExitError{Code: 1, Err: fmt.Errorf("sealed value for %s malformed", k)}
		}
		mlkemB64 := parts[0]
		gcmB64 := parts[1]

		mlkemCiphertext, err := base64.StdEncoding.DecodeString(mlkemB64)
		if err != nil {
			return ExitError{Code: 1, Err: fmt.Errorf("invalid base64 mlkem ciphertext for %s: %w", k, err)}
		}
		gcmBlob, err := base64.StdEncoding.DecodeString(gcmB64)
		if err != nil {
			return ExitError{Code: 1, Err: fmt.Errorf("invalid base64 gcm blob for %s: %w", k, err)}
		}

		sharedKey, err := dk.Decapsulate(mlkemCiphertext)
		if err != nil {
			return ExitError{Code: 1, Err: fmt.Errorf("decapsulation failed for %s: %w", k, err)}
		}
		if len(sharedKey) != mlkem.SharedKeySize {
			return ExitError{Code: 1, Err: fmt.Errorf("unexpected shared key size for %s: %d", k, len(sharedKey))}
		}

		plaintext, err := decryptAESGCM(sharedKey, gcmBlob)
		if err != nil {
			return ExitError{Code: 1, Err: fmt.Errorf("decryption failed for %s: %w", k, err)}
		}

		decrypted[k] = string(plaintext)
	}

	// Output either JSON or .env-safe lines. Do not print errors here; return them.
	if *jsonOut {
		js, err := json.Marshal(decrypted)
		if err != nil {
			return ExitError{Code: 1, Err: fmt.Errorf("failed to marshal JSON: %w", err)}
		}
		// Print success output; caller may prefer to capture stdout instead of printing here.
		fmt.Println(string(js))
	} else {
		for _, k := range keys {
			fmt.Println(env.FormatEnvEntry(k, decrypted[k]))
		}
	}

	return nil
}
