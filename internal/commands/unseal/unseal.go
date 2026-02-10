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

package unseal

// TODO: use https://pkg.go.dev/runtime/secret to clean up secrets from memory

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/util/aes"
	"github.com/ojster/ojster/internal/util/env"
)

func Unseal(args []string) {
	fs := flag.NewFlagSet("unseal", flag.ExitOnError)
	inPath := fs.String("in", ".env", "env file path to read (default ./.env)")
	privPath := fs.String("priv-file", common.DefaultPrivFile, "private key filename to read (default ./"+common.DefaultPrivFile+")")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	_ = fs.Parse(args)

	// Keys provided on command line (may be zero)
	keys := fs.Args()

	// Read private key file
	privFileBytes, err := os.ReadFile(*privPath)
	if err != nil {
		log.Fatalf("failed to read private key file %s: %v", *privPath, err)
	}
	privText := strings.TrimSpace(string(privFileBytes))
	privBytes, err := base64.StdEncoding.DecodeString(privText)
	if err != nil {
		log.Fatalf("invalid base64 private key in %s: %v", *privPath, err)
	}

	dk, err := mlkem.NewDecapsulationKey768(privBytes)
	if err != nil {
		log.Fatalf("invalid private key in %s: %v", *privPath, err)
	}

	// Parse env file into map of key->rawValue (logical unquoted value)
	envMap, err := env.ParseEnvFile(*inPath)
	if err != nil {
		log.Fatalf("failed to read env file %s: %v", *inPath, err)
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
			fmt.Fprintf(os.Stderr, "no sealed entries found in %s\n", *inPath)
			return
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
		fmt.Fprintf(os.Stderr, "missing keys in %s: %s\n", *inPath, strings.Join(missing, ", "))
		os.Exit(2)
	}

	// Collect decrypted values
	decrypted := make(map[string]string, len(keys))

	for _, k := range keys {
		stored := envMap[k]
		if !strings.HasPrefix(stored, common.Prefix) {
			log.Fatalf("value for %s does not appear to be sealed (missing common.Prefix)", k)
		}
		payload := strings.TrimPrefix(stored, common.Prefix)
		parts := strings.SplitN(payload, common.Sep, 2)
		if len(parts) != 2 {
			log.Fatalf("sealed value for %s malformed", k)
		}
		mlkemB64 := parts[0]
		gcmB64 := parts[1]

		mlkemCiphertext, err := base64.StdEncoding.DecodeString(mlkemB64)
		if err != nil {
			log.Fatalf("invalid base64 mlkem ciphertext for %s: %v", k, err)
		}
		gcmBlob, err := base64.StdEncoding.DecodeString(gcmB64)
		if err != nil {
			log.Fatalf("invalid base64 gcm blob for %s: %v", k, err)
		}

		sharedKey, err := dk.Decapsulate(mlkemCiphertext)
		if err != nil {
			log.Fatalf("decapsulation failed for %s: %v", k, err)
		}
		if len(sharedKey) != mlkem.SharedKeySize {
			log.Fatalf("unexpected shared key size for %s: %d", k, len(sharedKey))
		}

		plaintext, err := aes.DecryptAESGCM(sharedKey, gcmBlob)
		if err != nil {
			log.Fatalf("decryption failed for %s: %v", k, err)
		}

		valStr := string(plaintext)

		decrypted[k] = valStr
	}

	// Output either JSON or .env-safe lines
	if *jsonOut {
		// Marshal compact JSON object
		js, err := json.Marshal(decrypted)
		if err != nil {
			log.Fatalf("failed to marshal JSON: %v", err)
		}
		// Print JSON followed by newline
		fmt.Println(string(js))
	} else {
		for _, k := range keys {
			fmt.Println(env.FormatEnvEntry(k, decrypted[k]))
		}
	}

}
