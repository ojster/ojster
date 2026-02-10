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

package serve

// TODO: use https://pkg.go.dev/runtime/secret to clean up secrets from memory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/util"
)

// Assign functions to vars so tests can override them
var environFunc = os.Environ

func handlePost(w http.ResponseWriter, r *http.Request, cmd []string, privateKeyFile string) {
	defer r.Body.Close()

	var incoming map[string]string
	if err := readJSON(r.Body, 10*1024*1024, &incoming); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	requestedKeys := make(map[string]struct{}, len(incoming))
	lines := make([]string, 0, len(incoming))

	for k, v := range incoming {
		if !common.KeyNameRegex.MatchString(k) {
			http.Error(w, "invalid key name in request: "+k, http.StatusBadRequest)
			return
		}
		requestedKeys[k] = struct{}{}
		lines = append(lines, k+"="+dotenvEscape(v))
	}

	tmpDir, err := os.MkdirTemp("", "ojster-")
	if err != nil {
		http.Error(w, "failed to create temp dir: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := os.WriteFile(filepath.Join(tmpDir, ".env"), joinLines(lines), 0600); err != nil {
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

func readJSON(r io.Reader, maxBytes int64, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes))
	if err != nil {
		return util.Errf("failed to read body: %v", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return util.Errf("invalid JSON: %v", err)
	}
	return nil
}

func joinLines(lines []string) []byte {
	s := strings.Join(lines, "\n")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return []byte(s)
}

func dotenvEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return "'" + s + "'"
}
