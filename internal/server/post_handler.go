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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ojster/ojster/internal/pqc"
	"github.com/ojster/ojster/internal/util/env"
)

// Assign functions to vars so tests can override them
var environFunc = os.Environ

// allow tests to override the unseal implementation used by handlePost
var unsealMapFunc = func(envMap map[string]string, privPath string, keys []string) (map[string]string, error) {
	return pqc.UnsealMap(envMap, privPath, keys)
}

func handlePost(w http.ResponseWriter, r *http.Request, cmdArgs []string, privateKeyFile string) {
	cmd := []string{"/ojster", "unseal", "-json", "-priv-file", "./.env.keys"}
	if len(cmdArgs) > 0 {
		cmd = cmdArgs
	}

	defer r.Body.Close()

	var incoming map[string]string
	{
		const maxBytes = 10 * 1024 * 1024
		data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(data, &incoming); err != nil {
			http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
			return
		}
	}

	requestedKeys := make(map[string]struct{}, len(incoming))
	for k := range incoming {
		if !env.KeyNameRegex.MatchString(k) {
			http.Error(w, "invalid key name in request: "+k, http.StatusBadRequest)
			return
		}
		requestedKeys[k] = struct{}{}
	}

	// Dispatch to the appropriate branch
	if len(cmdArgs) == 0 {
		handlePostDirectUnseal(w, incoming, requestedKeys, privateKeyFile)
		return
	}
	handlePostSubprocessUnseal(w, incoming, requestedKeys, cmd, privateKeyFile)
}

// handlePostDirectUnseal handles the path where the server calls UnsealMap directly.
func handlePostDirectUnseal(w http.ResponseWriter, incoming map[string]string, requestedKeys map[string]struct{}, privateKeyFile string) {
	outMap, err := unsealMapFunc(incoming, privateKeyFile, nil)
	if err != nil {
		switch {
		case errors.Is(err, pqc.ErrConfig):
			http.Error(w, err.Error(), http.StatusInternalServerError) // 500
			return
		default:
			http.Error(w, err.Error(), http.StatusBadGateway) // 502
			return
		}
	}

	// Ensure returned keys are subset of requested keys
	for k := range outMap {
		if _, ok := requestedKeys[k]; !ok {
			http.Error(w, "unseal returned unexpected keys", http.StatusBadGateway)
			return
		}
	}

	finalMap := make(map[string]string, len(outMap))
	for k := range requestedKeys {
		if v, ok := outMap[k]; ok {
			finalMap[k] = v
		}
	}
	if len(finalMap) == 0 {
		http.Error(w, "unseal produced no acceptable env entries", http.StatusBadGateway)
		return
	}

	j, _ := json.Marshal(finalMap)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(j)
}

// handlePostSubprocessUnseal handles the path where the server writes files and runs a subprocess.
func handlePostSubprocessUnseal(w http.ResponseWriter, incoming map[string]string, requestedKeys map[string]struct{}, cmd []string, privateKeyFile string) {
	tmpDir, err := os.MkdirTemp("", "ojster-")
	if err != nil {
		http.Error(w, "failed to create temp dir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Write .env using the formatted lines (ensure trailing newline)
	lines := make([]string, 0, len(incoming))
	for k, v := range incoming {
		lines = append(lines, env.FormatEnvEntry(k, v))
	}
	envPath := filepath.Join(tmpDir, ".env")
	s := strings.Join(lines, "\n")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	if err := os.WriteFile(envPath, []byte(s), 0600); err != nil {
		http.Error(w, "failed to write .env file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := os.Symlink(privateKeyFile, filepath.Join(tmpDir, ".env.keys")); err != nil {
		http.Error(w, "failed to create symlink to private key file: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	execCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	execCmd.Dir = tmpDir
	execCmd.Env = environFunc()

	var stdoutBuf bytes.Buffer
	execCmd.Stdout = &stdoutBuf

	start := time.Now()
	if err := execCmd.Run(); err != nil {
		dur := time.Since(start)
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "subprocess timed out", http.StatusGatewayTimeout)
			return
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			http.Error(w, fmt.Sprintf("subprocess failed (exit %d) after %s", exitErr.ExitCode(), dur), http.StatusBadGateway)
			return
		}
		http.Error(w, "failed to run subprocess: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var outMap map[string]string
	if err := json.Unmarshal(stdoutBuf.Bytes(), &outMap); err != nil {
		http.Error(w, fmt.Sprintf("subprocess produced invalid JSON after %s", time.Since(start)), http.StatusBadGateway)
		return
	}

	for k := range outMap {
		if _, ok := requestedKeys[k]; !ok {
			http.Error(w, "subprocess returned unexpected keys", http.StatusBadGateway)
			return
		}
	}

	finalMap := make(map[string]string, len(outMap))
	for k := range requestedKeys {
		if v, ok := outMap[k]; ok {
			finalMap[k] = v
		}
	}

	if len(finalMap) == 0 {
		http.Error(w, "subprocess produced no acceptable env entries", http.StatusBadGateway)
		return
	}

	j, _ := json.Marshal(finalMap)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(j)
}
