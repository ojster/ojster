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
	"flag"
	"fmt"
	"io"

	"github.com/ojster/ojster/internal/client"
	"github.com/ojster/ojster/internal/pqc"
	"github.com/ojster/ojster/internal/server"
	"github.com/ojster/ojster/internal/util/tty"
)

// Entrypoint is a testable, writer-based entrypoint for the CLI.
// - prog is the program name (e.g., filepath.Base(os.Args[0])).
// - args are os.Args[1:].
// - version and header are printed for version/help.
// - outw and errw are the writers to use for stdout and stderr respectively.
// Entrypoint writes to the provided writers and returns an exit code.
// It does not call os.Exit.
func Entrypoint(prog string, args []string, version string, header string, outw io.Writer, errw io.Writer) int {
	// docker-init behaves like run
	if prog == "docker-init" {
		return handleRun(args, outw, errw)
	}

	if len(args) == 0 {
		fmt.Fprint(outw, header)
		return 0
	}

	sub := args[0]
	subargs := args[1:]

	switch sub {
	case "help":
		fmt.Fprint(outw, header)
		return 0
	case "version":
		fmt.Fprintln(outw, version)
		return 0
	case "keypair":
		return handleKeypair(subargs, outw, errw)
	case "run":
		return handleRun(subargs, outw, errw)
	case "seal":
		return handleSeal(subargs, outw, errw)
	case "serve":
		return handleServe(subargs, outw, errw)
	case "unseal":
		return handleUnseal(subargs, outw, errw)
	default:
		fmt.Fprint(outw, header)
		fmt.Fprintf(errw, "unknown subcommand: %s\n", sub)
		return 1
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

// ------------------------- subcommand handlers ---------------------------

// handleKeypair uses FlagSet semantics and delegates to pqc.KeypairWithPaths.
func handleKeypair(rawArgs []string, outw io.Writer, errw io.Writer) int {
	before, _, _ := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("keypair", flag.ContinueOnError)
	// Ensure flag package writes usage/errors to our err writer
	fs.SetOutput(errw)
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to write")
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to write")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster keypair [options]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	// Parse the portion before any "--"
	if err := fs.Parse(before); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(outw, usageFromFlagSet(fs))
			return 0
		}
		fmt.Fprintf(errw, "failed to parse keypair flags: %v\n", err)
		return 2
	}

	// pqc.KeypairWithPaths follows the writer/exit-code pattern.
	return pqc.KeypairWithPaths(*privPath, *pubPath, outw, errw)
}

// handleSeal reads plaintext from tty and calls pqc.SealWithPlaintext.
func handleSeal(rawArgs []string, outw io.Writer, errw io.Writer) int {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(errw)
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to read")
	outPath := fs.String("out", ".env", "env file path to write")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster seal [options] KEY\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(outw, usageFromFlagSet(fs))
			return 0
		}
		fmt.Fprintf(errw, "failed to parse seal flags: %v\n", err)
		return 2
	}

	var pos []string
	if had {
		pos = after
	} else {
		pos = fs.Args()
	}

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
func handleUnseal(rawArgs []string, outw io.Writer, errw io.Writer) int {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("unseal", flag.ContinueOnError)
	fs.SetOutput(errw)
	inPath := fs.String("in", ".env", "env file path to read")
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to read")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster unseal [options] [KEY...]\n\nOptions:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(outw, usageFromFlagSet(fs))
			return 0
		}
		fmt.Fprintf(errw, "failed to parse unseal flags: %v\n", err)
		return 2
	}

	var keys []string
	if had {
		keys = after
	} else {
		keys = fs.Args()
	}

	return pqc.UnsealFromFiles(*inPath, *privPath, keys, *jsonOut, outw, errw)
}

// handleRun passes through positional args to client.Run while using FlagSet
// semantics for any run-specific flags and for help handling.
func handleRun(rawArgs []string, outw io.Writer, errw io.Writer) int {
	before, after, had := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errw)
	// Add run-specific flags here if needed in future.
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster run [--] command [args...]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(outw, usageFromFlagSet(fs))
			return 0
		}
		fmt.Fprintf(errw, "failed to parse run flags: %v\n", err)
		return 2
	}

	var cmdArgs []string
	if had {
		cmdArgs = after
	} else {
		cmdArgs = fs.Args()
	}

	// client.Run follows the writer/exit-code pattern and returns an int exit code.
	return client.Run(cmdArgs, outw, errw)
}

// handleServe starts the server. For testability, server.Serve should return an exit code
// and write any startup errors to errw; if it blocks, that's expected for serve mode.
func handleServe(rawArgs []string, outw io.Writer, errw io.Writer) int {
	before, after, _ := splitDoubleDash(rawArgs)

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(errw)
	// Add serve-specific flags here if needed.
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: ojster serve [options]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(before); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(outw, usageFromFlagSet(fs))
			return 0
		}
		fmt.Fprintf(errw, "failed to parse serve flags: %v\n", err)
		return 2
	}

	// server.Serve is expected to follow the writer/exit-code pattern.
	return server.Serve(context.Background(), after, outw, errw)
}
