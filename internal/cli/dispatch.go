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
