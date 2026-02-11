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

	// handle special prog alias
	if prog == "docker-init" {
		// docker-init behaves like run
		return handleRun(args)
	}

	if len(args) == 0 {
		// top-level help
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
		// unknown subcommand -> top-level help and non-zero exit
		return header, fmt.Sprintf("unknown subcommand: %s", sub), 1
	}
}

// ----------------------------- helpers ----------------------------------

// splitDoubleDash splits args at the first "--".
// Returns (before, after, hadDoubleDash).
func splitDoubleDash(args []string) (before []string, after []string, had bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}

// containsHelpFlag reports whether args (the portion before any "--")
// contains "-h" or "--help".
func containsHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// usageFromFlagSet returns the usage text produced by fs. It captures
// the output of fs.Usage into a string.
func usageFromFlagSet(fs *flag.FlagSet) string {
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.Usage()
	return buf.String()
}

// --------------------------- subcommand handlers -------------------------

// handleKeypair uses FlagSet semantics to decide whether to show usage
// or to run the keypair action. It delegates to pqc.KeypairWithPaths.
func handleKeypair(rawArgs []string) (string, string, int) {
	// split at "--" (not typically used for keypair, but consistent)
	before, _, had := splitDoubleDash(rawArgs)

	// build a FlagSet to produce usage text and to follow FlagSet parsing rules
	fs := flag.NewFlagSet("keypair", flag.ContinueOnError)
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to write")
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to write")
	// custom usage
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster keypair [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	// If no double-dash and help flag present, return usage
	if !had && containsHelpFlag(before) {
		return usageFromFlagSet(fs), "", 0
	}

	// Parse only the portion before "--" so FlagSet stops at first non-flag.
	// We ignore parse errors here and return them as ExitError-like behavior.
	if err := fs.Parse(before); err != nil {
		// flag package already wrote an error to fs.Output(); return a clean error message.
		return "", fmt.Sprintf("failed to parse keypair flags: %v", err), 2
	}

	// Now call the underlying implementation with the full rawArgs (so callers
	// that used "--" get the expected behavior). KeypairWithPaths expects explicit paths.
	out, err := pqc.KeypairWithPaths(*privPath, *pubPath)
	if err != nil {
		return "", err.Error(), exitCodeFromErr(err)
	}
	return out, "", 0
}

// handleSeal reads plaintext from tty and calls pqc.SealWithPlaintext.
// It uses FlagSet to implement conventional parsing and help.
func handleSeal(rawArgs []string) (string, string, int) {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to read")
	outPath := fs.String("out", ".env", "env file path to write")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster seal [options] KEY\n\nOptions:\n")
		fs.PrintDefaults()
	}

	// If no double-dash and help requested, return usage
	if !had && containsHelpFlag(before) {
		return usageFromFlagSet(fs), "", 0
	}

	// Parse flags from the portion before "--"
	if err := fs.Parse(before); err != nil {
		return "", fmt.Sprintf("failed to parse seal flags: %v", err), 2
	}

	// Determine positional args: if there was a "--", positional args are 'after',
	// otherwise they are fs.Args() (the remainder after parsing).
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

	// Read plaintext from tty (this is interactive; tests can stub tty.ReadSecretFromStdin)
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

	// If no double-dash and help requested, return usage
	if !had && containsHelpFlag(before) {
		return usageFromFlagSet(fs), "", 0
	}

	if err := fs.Parse(before); err != nil {
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

// handleKeypair, handleSeal, handleUnseal done above.

// handleRun is special: it must pass-through positional args to the inner command.
// We still use FlagSet semantics to support run-specific flags in future and to
// implement the "--" behavior. For now, client.Run is expected to accept the
// final args slice and manage exec semantics.
func handleRun(rawArgs []string) (string, string, int) {
	before, after, had := splitDoubleDash(rawArgs)

	// Create a FlagSet for run so we can produce usage and parse any run-specific flags.
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	// Example run-specific flags could be added here in future.
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster run [--] command [args...]\n\n")
		fs.PrintDefaults()
	}

	// If no double-dash and help requested, return usage
	if !had && containsHelpFlag(before) {
		return usageFromFlagSet(fs), "", 0
	}

	// Parse flags from before; parsing stops at first non-flag.
	if err := fs.Parse(before); err != nil {
		return "", fmt.Sprintf("failed to parse run flags: %v", err), 2
	}

	// Determine the command args to pass to client.Run:
	// - If user provided "--", everything after it is passed verbatim.
	// - Otherwise, pass fs.Args() (the remainder after parsing).
	var cmdArgs []string
	if had {
		cmdArgs = after
	} else {
		cmdArgs = fs.Args()
	}

	// // Delegate to client.Run. client.Run may exec/replace process in production.
	// // For testability, client.Run should return an error instead of calling os.Exit.
	// if err := client.Run(cmdArgs); err != nil {
	// 	return "", err.Error(), exitCodeFromErr(err)
	// }
	client.Run(cmdArgs)
	return "", "", 0
}

// handleServe starts the server. For testability, server.Serve should return an
// error on startup failure; if it blocks, provide a test adapter in server package.
func handleServe(rawArgs []string) (string, string, int) {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	// Add serve-specific flags here if needed.
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster serve [options]\n\n")
		fs.PrintDefaults()
	}

	// If no double-dash and help requested, return usage
	if !had && containsHelpFlag(before) {
		return usageFromFlagSet(fs), "", 0
	}

	if err := fs.Parse(before); err != nil {
		return "", fmt.Sprintf("failed to parse serve flags: %v", err), 2
	}

	// // Delegate to server.Serve. If server.Serve blocks, consider adding a ServeBackground
	// // adapter in the server package for testability. Here we call Serve and return any error.
	// if err := server.Serve(after); err != nil {
	// 	return "", err.Error(), exitCodeFromErr(err)
	// }
	// return "", "", 0

	server.Serve(context.Background(), after)
	return "", "", 0
}

// --------------------------- small utilities -----------------------------

// exitCodeFromErr extracts an exit code from an error. If the error is a pqc.ExitError
// (value, pointer, or wrapped), its Code is returned; otherwise default 1.
func exitCodeFromErr(err error) int {
	var ee pqc.ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 1
}
