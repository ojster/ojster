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

package seal

// TODO: use https://pkg.go.dev/runtime/secret to clean up secrets from memory

import (
	"crypto/mlkem"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/util/aes"
	"github.com/ojster/ojster/internal/util/env"
	"github.com/ojster/ojster/internal/util/tty"
)

func Seal(args []string) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	pubPath := fs.String("pub-file", common.DefaultPubFile, "public key filename to read (default ./"+common.DefaultPubFile+")")
	outPath := fs.String("out", ".env", "env file path to write (default ./.env)")
	_ = fs.Parse(args)

	// Require positional KEY argument
	if fs.NArg() != 1 {
		log.Fatalf("seal requires exactly one positional argument: KEY")
	}
	keyName := fs.Arg(0)

	pubFileBytes, err := os.ReadFile(*pubPath)
	if err != nil {
		log.Fatalf("failed to read public key file %s: %v", *pubPath, err)
	}

	pubText := strings.TrimSpace(string(pubFileBytes))

	pubBytes, err := base64.StdEncoding.DecodeString(pubText)
	if err != nil {
		log.Fatalf("invalid base64 public key in %s: %v", *pubPath, err)
	}

	ek, err := mlkem.NewEncapsulationKey768(pubBytes)
	if err != nil {
		log.Fatalf("invalid public key in %s: %v", *pubPath, err)
	}

	// Read secret from stdin (masked if interactive). Supports multiline terminated by EOF (Ctrl-D).
	prompt := "Reading plaintext input from stdin (input will be hidden). Press Ctrl-D when done.\n"
	plaintext, err := tty.ReadSecretFromStdin(prompt)
	if err != nil {
		log.Fatalf("failed to read plaintext: %v", err)
	}

	pt := make([]byte, len(plaintext))
	copy(pt, plaintext)

	sharedKey, mlkemCiphertext := ek.Encapsulate()
	if len(sharedKey) != mlkem.SharedKeySize {
		log.Fatalf("unexpected shared key size: %d", len(sharedKey))
	}

	gcmBlob, err := aes.EncryptAESGCM(sharedKey, pt)
	if err != nil {
		log.Fatalf("encryption failed: %v", err)
	}

	mlkemB64 := base64.StdEncoding.EncodeToString(mlkemCiphertext)
	gcmB64 := base64.StdEncoding.EncodeToString(gcmBlob)
	sealed := common.Prefix + mlkemB64 + common.Sep + gcmB64

	// Update env file atomically (replace or append)
	if err := env.UpdateEnvFile(*outPath, keyName, sealed); err != nil {
		log.Fatalf("failed to update env file %s: %v", *outPath, err)
	}

	// Print a short confirmation to the terminal (to stderr so stdout remains clean)
	fmt.Fprintf(os.Stderr, "Wrote %s to %s\n", keyName, *outPath)

}
