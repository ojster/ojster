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

package keypair

// TODO: use https://pkg.go.dev/runtime/secret to clean up secrets from memory

import (
	"crypto/mlkem"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/util/file"
)

func Keypair(args []string) {
	fs := flag.NewFlagSet("keypair", flag.ExitOnError)
	privPath := fs.String("priv-file", common.DefaultPrivFile, "private key filename to write (default ./"+common.DefaultPrivFile+")")
	pubPath := fs.String("pub-file", common.DefaultPubFile, "public key filename to write (default ./"+common.DefaultPubFile+")")
	_ = fs.Parse(args)

	// Generate decapsulation (private) key
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	priv := dk.Bytes() // 64 bytes seed form (private)
	ek := dk.EncapsulationKey()
	pub := ek.Bytes() // public encapsulation key bytes

	// Encode to base64 text
	privB64 := []byte(base64.StdEncoding.EncodeToString(priv) + "\n")
	pubB64 := []byte(base64.StdEncoding.EncodeToString(pub) + "\n")

	// Write private key atomically with 0600 permissions
	if err := file.WriteFileAtomic(*privPath, privB64, 0o600); err != nil {
		log.Fatalf("failed to write private key: %v", err)
	}

	// Write public key atomically with 0644 permissions
	if err := file.WriteFileAtomic(*pubPath, pubB64, 0o644); err != nil {
		// attempt to remove private key if public write fails
		_ = os.Remove(*privPath)
		log.Fatalf("failed to write public key: %v", err)
	}

	// Print helpful info (do not print private key)
	absPriv, _ := filepath.Abs(*privPath)
	absPub, _ := filepath.Abs(*pubPath)
	fmt.Fprintf(os.Stdout, "Wrote private key to %s (mode 0600)\n", absPriv)
	fmt.Fprintf(os.Stdout, "Wrote public key to %s (mode 0644)\n", absPub)

	// Also print public key base64 for convenience (same as file content)
	fmt.Fprintln(os.Stdout, "\nPUBLIC (base64):")
	fmt.Fprintln(os.Stdout, strings.TrimSpace(string(pubB64)))
}
