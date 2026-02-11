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
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/ojster/ojster/internal/client"
	"github.com/ojster/ojster/internal/pqc"
	"github.com/ojster/ojster/internal/server"
	"github.com/ojster/ojster/internal/util/tty"
)

// Entrypoint is a pure, testable entrypoint for the CLI.
// - prog is the program name (e.g., filepath.Base(os.Args[0])).
// - args are os.Args[1:].
// Returns (stdout, stderr, exitCode).
//
// Entrypoint does not print or call os.Exit.
func Entrypoint(prog string, args []string, version string, header string) (string, string, int) {
	// docker-init behaves like run
	if prog == "docker-init" {
		return handleRun(args)
	}

	if len(args) == 0 {
		return header, "", 0
	}

	sub := args[0]
	subargs := args[1:]

	switch sub {
	case "help":
		return header, "", 0
	case "version":
		return version, "", 0
	case "keypair":
		return handleKeypair(subargs)
	case "run":
		return handleRun(subargs)
	case "seal":
		return handleSeal(subargs)
	case "serve":
		return handleServe(subargs)
	case "unseal":
		return handleUnseal(subargs)
	default:
		return header, fmt.Sprintf("unknown subcommand: %s", sub), 1
	}
}

// ----------------------------- utilities --------------------------------

// splitDoubleDash splits args at the first "--" and returns (before, after, had).
func splitDoubleDash(args []string) (before []string, after []string, had bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

// usageFromFlagSet captures fs.Usage output and returns it as a string.
func usageFromFlagSet(fs *flag.FlagSet) string {
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.Usage()
	return buf.String()
}

// exitCodeFromErr extracts an exit code from an error. If the error is a pqc.ExitError
// (value, pointer, or wrapped), its Code is returned; otherwise default 1.
func exitCodeFromErr(err error) int {
	var ee pqc.ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}

// ------------------------- subcommand handlers ---------------------------

// handleKeypair uses FlagSet semantics and delegates to pqc.KeypairWithPaths.
func handleKeypair(rawArgs []string) (string, string, int) {
	before, _, _ := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("keypair", flag.ContinueOnError)
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to write")
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to write")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster keypair [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	// Parse the portion before any "--"
	if err := fs.Parse(before); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageFromFlagSet(fs), "", 0
		}
		return "", fmt.Sprintf("failed to parse keypair flags: %v", err), 2
	}

	out, err := pqc.KeypairWithPaths(*privPath, *pubPath)
	if err != nil {
		return "", err.Error(), exitCodeFromErr(err)
	}
	return out, "", 0
}

// handleSeal reads plaintext from tty and calls pqc.SealWithPlaintext.
func handleSeal(rawArgs []string) (string, string, int) {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to read")
	outPath := fs.String("out", ".env", "env file path to write")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster seal [options] KEY\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageFromFlagSet(fs), "", 0
		}
		return "", fmt.Sprintf("failed to parse seal flags: %v", err), 2
	}

	var pos []string
	if had {
		pos = after
	} else {
		pos = fs.Args()
	}

	if len(pos) != 1 {
		return "", "seal requires exactly one positional argument: KEY", 1
	}
	keyName := pos[0]

	plaintext, err := tty.ReadSecretFromStdin("Reading plaintext input from stdin (input will be hidden). Press Ctrl-D when done.\n")
	if err != nil {
		return "", err.Error(), exitCodeFromErr(err)
	}

	out, err := pqc.SealWithPlaintext(*pubPath, *outPath, keyName, plaintext)
	if err != nil {
		return "", err.Error(), exitCodeFromErr(err)
	}
	return out, "", 0
}

// handleUnseal uses FlagSet semantics and delegates to pqc.UnsealFromFiles.
func handleUnseal(rawArgs []string) (string, string, int) {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("unseal", flag.ContinueOnError)
	inPath := fs.String("in", ".env", "env file path to read")
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to read")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster unseal [options] [KEY...]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageFromFlagSet(fs), "", 0
		}
		return "", fmt.Sprintf("failed to parse unseal flags: %v", err), 2
	}

	var keys []string
	if had {
		keys = after
	} else {
		keys = fs.Args()
	}

	out, err := pqc.UnsealFromFiles(*inPath, *privPath, keys, *jsonOut)
	if err != nil {
		return "", err.Error(), exitCodeFromErr(err)
	}
	return out, "", 0
}

// handleRun passes through positional args to client.Run while using FlagSet
// semantics for any run-specific flags and for help handling.
func handleRun(rawArgs []string) (string, string, int) {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	// Add run-specific flags here if needed in future.
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster run [--] command [args...]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageFromFlagSet(fs), "", 0
		}
		return "", fmt.Sprintf("failed to parse run flags: %v", err), 2
	}

	var cmdArgs []string
	if had {
		cmdArgs = after
	} else {
		cmdArgs = fs.Args()
	}

	// Delegate to client.Run. In production client.Run may exec/replace the process.
	// Entrypoint calls it and does not attempt to capture its stdout/stderr here.
	// client.Run currently manages its own lifecycle; call it and return success.
	client.Run(cmdArgs)
	// If client.Run returns (it may not), we return success.
	return "", "", 0
}

// handleServe starts the server. For testability, server.Serve should return an error
// on startup failure; if it blocks, consider adding a test adapter in server package.
func handleServe(rawArgs []string) (string, string, int) {
	before, after, _ := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	// Add serve-specific flags here if needed.
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster serve [options]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return usageFromFlagSet(fs), "", 0
		}
		return "", fmt.Sprintf("failed to parse serve flags: %v", err), 2
	}

	// server.Serve currently expects a context and args; call it similarly to main.
	// If server.Serve blocks, this will block; that's expected for serve mode.
	server.Serve(context.Background(), after)
	return "", "", 0
}
