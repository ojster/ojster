// Copyright 2026 Jip de Beer (Jip-Hop) and Ojster contributors
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

const header = `Ojster — GitOps-safe one-way encrypted secrets for Docker Compose

Environment variables:
  OJSTER_SOCKET_PATH
      Unix domain socket path used for client ↔ server IPC.
      Default: /mnt/ojster/ipc.sock

  OJSTER_PRIVATE_KEY_FILE
      Path to the private key file used for decryption..
      Default: /run/secrets/private_key

  OJSTER_REGEX
      Regex used by the client (run mode) to select which env values to send.

Usage:
  ojster help
  ojster version
`

const keypairSynopsis = "ojster keypair"
const keypairDesc = "Generate a new keypair. Writes private and public key files."
const keypairArgs = "[--priv-file PATH] [--pub-file PATH]"

const sealSynopsis = "ojster seal"
const sealDesc = "Encrypt KEY in an env file using the public key."
const sealArgs = "[--pub-file PATH] [--out PATH] KEY"

const unsealSynopsis = "ojster unseal"
const unsealDesc = "Decrypt values from an env file using a private key and print results."
const unsealArgs = "[--in PATH] [--priv-file PATH] [--json] [KEY...]"

const runSynopsis = "ojster run"
const runDesc = "Client mode: send selected encrypted env values to the server and exec the command."
const runArgs = "[--] command [args...]"

const serveSynopsis = "ojster serve"
const serveDesc = "Server mode: listen on the Unix socket and return decrypted env values to clients."
const serveArgs = "[--] command [args...]"

var version = "0.0.0"

// ----------------------------- utilities --------------------------------

// RunEnv contains the environment-derived values used by the client/run path.
type RunEnv struct {
	// Regex used to select which env values to send to the server.
	Regex string
	// SocketPath is the Unix domain socket path the client will POST to.
	SocketPath string
}

// ServeEnv contains the environment-derived values used by the server/serve path.
type ServeEnv struct {
	// PrivateKeyFile is the path containing the private key file for decryption.
	PrivateKeyFile string
	// SocketPath is the Unix domain socket path the server will listen on.
	SocketPath string
}

// getenvDefaultAndUnset returns the value of env key if set, otherwise def.
// If the env var was set (non-empty), it unsets it before returning.
func getenvDefaultAndUnset(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	_ = os.Unsetenv(key)
	return v
}

func getSocketPath() string {
	return getenvDefaultAndUnset("OJSTER_SOCKET_PATH", "/mnt/ojster/ipc.sock")
}

// readRunEnv reads only the env vars needed for run mode and clears them.
func readRunEnv() RunEnv {
	re := getenvDefaultAndUnset("OJSTER_REGEX", pqc.DefaultValueRegex())
	return RunEnv{Regex: re, SocketPath: getSocketPath()}
}

// readServeEnv reads only the env vars needed for serve mode and clears them.
func readServeEnv() ServeEnv {
	priv := getenvDefaultAndUnset("OJSTER_PRIVATE_KEY_FILE", "/run/secrets/private_key")
	return ServeEnv{PrivateKeyFile: priv, SocketPath: getSocketPath()}
}

// usage prints the composed help text to the provided writer.
func usage(outw io.Writer) {
	fmt.Fprint(outw, header)
	printCommands(outw)
}

func printCommands(outw io.Writer) {
	pairs := [][2]string{
		{keypairSynopsis, keypairDesc},
		{sealSynopsis, sealDesc},
		{unsealSynopsis, unsealDesc},
		{runSynopsis, runDesc},
		{serveSynopsis, serveDesc},
	}

	// compute max synopsis length for alignment
	max := 0
	for _, p := range pairs {
		if l := len(p[0]); l > max {
			max = l
		}
	}

	for _, p := range pairs {
		fmt.Fprintf(outw, "  %-*s  %s\n", max, p[0], p[1])
	}
}

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

// ----------------------------- main --------------------------------

func main() {
	prog := filepath.Base(os.Args[0])
	args := os.Args[1:]

	// Entrypoint writes directly to the provided writers and returns an exit code.
	code := entrypoint(prog, args, version, os.Stdout, os.Stderr)

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
func entrypoint(prog string, args []string, version string, outw io.Writer, errw io.Writer) int {
	if len(args) == 0 {
		usage(outw)
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
		usage(outw)
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
		usage(outw)
		fmt.Fprintf(errw, "unknown subcommand: %s\n", sub)
		return 1
	}
}

// ------------------------- subcommand handlers ---------------------------

// handleKeypair uses FlagSet semantics and delegates to pqc.KeypairWithPaths.
func handleKeypair(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "keypair"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(outw)
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to write")
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to write")
	fs.Usage = func() {
		fmt.Fprintf(outw, "%s %s\n\n%s\n\nOptions:\n", keypairSynopsis, keypairArgs, keypairDesc)
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
	fs.SetOutput(outw)
	pubPath := fs.String("pub-file", pqc.DefaultPubFile(), "public key filename to read")
	outPath := fs.String("out", ".env", "env file path to write")
	fs.Usage = func() {
		fmt.Fprintf(outw, "%s %s\n\n%s\n\nOptions:\n", sealSynopsis, sealArgs, sealDesc)
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

	plaintext, err := tty.ReadSecretFromStdin("Reading plaintext input from stdin (input will be hidden). Press Ctrl-D twice when done.\n")
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
	fs.SetOutput(outw)
	inPath := fs.String("in", ".env", "env file path to read")
	privPath := fs.String("priv-file", pqc.DefaultPrivFile(), "private key filename to read")
	jsonOut := fs.Bool("json", false, "output decrypted keys/values as JSON object")
	fs.Usage = func() {
		fmt.Fprintf(outw, "%s %s\n\n%s\n\nOptions:\n", unsealSynopsis, unsealArgs, unsealDesc)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	return pqc.UnsealFromFiles(*inPath, *privPath, fs.Args(), *jsonOut, outw, errw)
}

// handleRun passes through positional args to client.Run while using FlagSet
// semantics for the command separator. The command to exec is provided after
// an optional "--" separator: "ojster run [--] command [args...]".
func handleRun(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "run"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(outw)
	// No run-specific flags currently; command follows optional "--".
	fs.Usage = func() {
		fmt.Fprintf(outw, "%s %s\n\n%s\n", runSynopsis, runArgs, runDesc)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	var cmdArgs = fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	runEnv := readRunEnv()
	return client.Run(runEnv.Regex, runEnv.SocketPath, cmdArgs, outw, errw)
}

// handleServe starts the server. The server accepts a command to run after an
// optional "--" separator: "ojster serve [--] command [args...]". There are no
// serve-specific flags at the moment.
func handleServe(args []string, outw io.Writer, errw io.Writer) int {
	const cmdName = "serve"
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	fs.SetOutput(outw)
	// No serve-specific flags currently; command follows optional "--".
	fs.Usage = func() {
		fmt.Fprintf(outw, "%s %s\n\n%s\n", serveSynopsis, serveArgs, serveDesc)
		fs.PrintDefaults()
	}

	if code := parseFlags(fs, args, errw, cmdName); code >= 0 {
		return code
	}

	var cmdArgs = fs.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	serveEnv := readServeEnv()
	return server.Serve(serveEnv.PrivateKeyFile, serveEnv.SocketPath, context.Background(), cmdArgs, outw, errw)
}
