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
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ojster/ojster/internal/cli"
	"github.com/ojster/ojster/internal/ojster/client"
	"github.com/ojster/ojster/internal/ojster/server"
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
	log.SetFlags(0)

	prog := filepath.Base(os.Args[0])
	args := os.Args[1:]

	mode, subargs := cli.Dispatch(prog, args)

	switch mode {
	case "help":
		printHelpAndExit()
	case "version":
		fmt.Println(version)
	case "run":
		client.Run(subargs)
	case "serve":
		server.Serve(context.Background(), subargs)
	}
}

func printHelpAndExit() { fmt.Print(header); os.Exit(0) }
