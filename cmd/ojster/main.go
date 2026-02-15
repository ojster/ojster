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

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ojster/ojster/internal/client"
	"github.com/ojster/ojster/internal/pqc"
	"github.com/ojster/ojster/internal/server"
	"github.com/ojster/ojster/internal/util/tty"
)

const header = `Ojster - GitOps-safe one-way encrypted secrets for Docker Compose

Environment variables:
  OJSTER_SOCKET_PATH
      Path to the Unix domain socket used for IPC between client and server.
      Default: /mnt/ojster/ipc.sock

  OJSTER_PRIVATE_KEY_FILE
      Path to the private key file used by the subprocess (serve mode).
      Default: /run/secrets/private_key

  OJSTER_REGEX
      Regex used by the client (run mode) to select which env values to send.
      Default: ^'?(encrypted:[A-Za-z0-9+/=]+)'?$

Usage:
  ojster help
  ojster version
  ojster run [command...]
      Client/bootstrap mode. Sends selected env values to the server over the
      Unix domain socket, receives decrypted values, merges them into the
      environment and execs [command...] (replacing the current process).

  ojster serve [command...]
      Server mode. Listens on the Unix domain socket for POST requests
      containing a JSON object of key->value pairs. For each request:
        - writes a temporary .env file,
        - symlinks OJSTER_PRIVATE_KEY_FILE to .env.keys,
        - runs the configured subprocess in that tmp dir,
        - expects the subprocess to print a JSON map of key->decrypted-value,
        - validates the subprocess returned only requested keys,
        - returns the filtered map to the client.
`

var version = "0.0.0"

func main() {
	prog := filepath.Base(os.Args[0])
	args := os.Args[1:]

	// Entrypoint writes directly to the provided writers and returns an exit code.
	code := entrypoint(prog, args, version, header, os.Stdout, os.Stderr)

	// Ensure we exit with the code returned by Entrypoint.
	os.Exit(code)
}

// entrypoint is a testable, writer-based entrypoint for the CLI.
// - prog is the program name (e.g., filepath.Base(os.Args[0])).
// - args are os.Args[1:].
// - version and header are printed for version/help.
// - outw and errw are the writers to use for stdout and stderr respectively.
// Entrypoint writes to the provided writers and returns an exit code.
// It does not call os.Exit.
func entrypoint(prog string, args []string, version string, header string, outw io.Writer, errw io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(outw, header)
		return 0
	}

	var sub string
	var rawSubArgs []string
	if prog == "docker-init" {
		sub = "run"
		rawSubArgs = args
	} else {
		sub = args[0]
		rawSubArgs = args[1:]
	}

	switch sub {
	case "help":
		fmt.Fprint(outw, header)
		return 0
	case "version":
		fmt.Fprintln(outw, version)
		return 0
	case "keypair":
		return handleKeypair(rawSubArgs, outw, errw)
	case "run":
		return handleRun(rawSubArgs, outw, errw)
	case "seal":
		return handleSeal(rawSubArgs, outw, errw)
	case "serve":
		return handleServe(rawSubArgs, outw, errw)
	case "unseal":
		return handleUnseal(rawSubArgs, outw, errw)
	default:
		fmt.Fprint(outw, header)
		fmt.Fprintf(errw, "unknown subcommand: %s\n", sub)
		return 1
	}
}

// ----------------------------- utilities --------------------------------

// parseFlags parses args using fs and handles help/errors consistently.
// Returns a non‑zero exit code if parsing should stop, otherwise 0.
func parseFlags(fs *flag.FlagSet, args []string, errw io.Writer, cmdName string) int {
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		fmt.Fprintf(errw, "failed to parse %s flags: %v\n", cmdName, err)
		return 2
	}
	return -1 // means "no error, continue"
}

// ------------------------- subcommand handlers ---------------------------

// handleKeypair uses FlagSet semantics and delegates to pqc.KeypairWithPaths.
func handleKeypair(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "keypair"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(errw)
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to write")
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to write")
	fs.Usage = func() {
		fmt.Fprintf(outw, "Usage: ojster %s [options]\n\nOptions:\n", cmdName)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	// pqc.KeypairWithPaths follows the writer/exit-code pattern.
	return pqc.KeypairWithPaths(*privPath, *pubPath, outw, errw)
}

// handleSeal reads plaintext from tty and calls pqc.SealWithPlaintext.
func handleSeal(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "seal"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(errw)
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to read")
	outPath := fs.String("out", ".env", "env file path to write")
	fs.Usage = func() {
		fmt.Fprintf(outw, "Usage: ojster %s [options] KEY\n\nOptions:\n", cmdName)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	var pos = fs.Args()

	if len(pos) != 1 {
		fmt.Fprintln(errw, "seal requires exactly one positional argument: KEY")
		return 1
	}
	keyName := pos[0]

	plaintext, err := tty.ReadSecretFromStdin("Reading plaintext input from stdin (input will be hidden). Press Ctrl-D when done.\n")
	if err != nil {
		fmt.Fprintln(errw, err.Error())
		return 1
	}

	return pqc.SealWithPlaintext(*pubPath, *outPath, keyName, plaintext, outw, errw)
}

// handleUnseal uses FlagSet semantics and delegates to pqc.UnsealFromFiles.
func handleUnseal(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "unseal"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(errw)
	inPath := fs.String("in", ".env", "env file path to read")
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to read")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	fs.Usage = func() {
		fmt.Fprintf(outw, "Usage: ojster %s [options] [KEY...]\n\nOptions:\n", cmdName)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	return pqc.UnsealFromFiles(*inPath, *privPath, fs.Args(), *jsonOut, outw, errw)
}

// handleRun passes through positional args to client.Run while using FlagSet
// semantics for any run-specific flags and for help handling.
func handleRun(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "run"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(errw)
	// Add run-specific flags here if needed in future.
	fs.Usage = func() {
		fmt.Fprintf(outw, "Usage: ojster %s [--] command [args...]\n\n", cmdName)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	var cmdArgs = fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	return client.Run(cmdArgs, outw, errw)
}

// handleServe starts the server. For testability, server.Serve should return an exit code
// and write any startup errors to errw; if it blocks, that's expected for serve mode.
func handleServe(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "serve"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(errw)
	// Add serve-specific flags here if needed.
	fs.Usage = func() {
		fmt.Fprintf(outw, "Usage: ojster %s [options]\n\n", cmdName)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	var cmdArgs = fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	return server.Serve(context.Background(), cmdArgs, outw, errw)
}
