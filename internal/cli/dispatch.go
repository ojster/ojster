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

package cli

import (
	"flag"
	"fmt"

	"github.com/ojster/ojster/internal/pqc"
	"github.com/ojster/ojster/internal/util/tty"
)

func Dispatch(prog string, args []string) (mode string, subargs []string) {
	// docker-init behaves like run
	if prog == "docker-init" {
		return "run", normalizeArgsForSubcommand(args)
	}

	if len(args) < 1 {
		return "help", nil
	}

	switch args[0] {
	case "help":
		return "help", nil
	case "version":
		return "version", nil
	case "keypair":
		return "keypair", normalizeArgsForSubcommand(args[1:])
	case "run":
		return "run", normalizeArgsForSubcommand(args[1:])
	case "seal":
		return "seal", normalizeArgsForSubcommand(args[1:])
	case "serve":
		return "serve", normalizeArgsForSubcommand(args[1:])
	case "unseal":
		return "unseal", normalizeArgsForSubcommand(args[1:])
	default:
		return "help", nil
	}
}

func normalizeArgsForSubcommand(raw []string) []string {
	if len(raw) > 0 && raw[0] == "--" {
		return raw[1:]
	}
	return raw
}

// RunKeypairFromArgs parses args and runs KeypairWithPaths.
// Returns the printable output string (from pqc) or an error.
func RunKeypairFromArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("keypair", flag.ContinueOnError)
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to write")
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to write")
	if err := fs.Parse(args); err != nil {
		return "", pqc.ExitError{Code: 2, Err: err}
	}

	out, err := pqc.KeypairWithPaths(*privPath, *pubPath)
	if err != nil {
		return "", err
	}
	return out, nil
}

// RunSealFromArgs parses args, reads plaintext from stdin, calls SealWithPlaintext,
// and returns the printable output string (from pqc) or an error.
func RunSealFromArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to read")
	outPath := fs.String("out", ".env", "env file path to write")
	if err := fs.Parse(args); err != nil {
		return "", pqc.ExitError{Code: 2, Err: err}
	}
	if fs.NArg() != 1 {
		return "", pqc.ExitError{Code: 1, Err: fmt.Errorf("seal requires exactly one positional argument: KEY")}
	}
	keyName := fs.Arg(0)

	plaintext, err := tty.ReadSecretFromStdin(
		"Reading plaintext input from stdin (input will be hidden). Press Ctrl-D when done.\n",
	)
	if err != nil {
		return "", pqc.ExitError{Code: 1, Err: err}
	}

	out, err := pqc.SealWithPlaintext(*pubPath, *outPath, keyName, plaintext)
	if err != nil {
		return "", err
	}
	return out, nil
}

// RunUnsealFromArgs parses args and runs UnsealFromFiles. Returns printable output or error.
func RunUnsealFromArgs(args []string) (string, error) {
	fs := flag.NewFlagSet("unseal", flag.ContinueOnError)
	inPath := fs.String("in", ".env", "env file path to read")
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to read")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	if err := fs.Parse(args); err != nil {
		return "", pqc.ExitError{Code: 2, Err: err}
	}

	keys := fs.Args()
	out, err := pqc.UnsealFromFiles(*inPath, *privPath, keys, *jsonOut)
	if err != nil {
		return "", err
	}
	return out, nil
}
