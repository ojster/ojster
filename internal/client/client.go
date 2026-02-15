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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/pqc"
	"github.com/ojster/ojster/internal/util/file"
)

// Assign functions to vars so tests can override them
var (
	environFunc             = os.Environ
	execFunc                = syscall.Exec
	postMapToServerJSONFunc = postMapToServerJSON
	sleepFunc               = time.Sleep
	lookPathFunc            = exec.LookPath
)

// retryWithBackoff logs a formatted message to errw, sleeps for the current backoff,
// and updates backoff to the next value (capped by maxBackoff).
func retryWithBackoff(errw io.Writer, backoff *time.Duration, maxBackoff time.Duration, format string, a ...any) {
	// append the backoff placeholder to the format and the current backoff to args
	fullFmt := format + " Retrying in %s\n"
	args := append(a, *backoff)
	fmt.Fprintf(errw, fullFmt, args...)
	sleepFunc(*backoff)
	*backoff = min(*backoff*2, maxBackoff)
}

// Run performs the client "run" flow and follows the writer/exit-code pattern:
// - nextArgs are the command and args to exec
// - outw and errw are writers for stdout/stderr
// Returns an exit code suitable for os.Exit.
func Run(nextArgs []string, outw io.Writer, errw io.Writer) int {
	if len(nextArgs) < 1 {
		fmt.Fprintln(errw, "run requires a next-binary to execute. Usage: ojster run <next-binary> [args...]")
		return 2
	}

	fmt.Fprintln(outw, "ojster run")

	socketPath := file.GetSocketPath()

	allEnv := environFunc()
	requestMap, err := filterEnvByValue(allEnv)
	if err != nil {
		fmt.Fprintln(errw, "failed to filter environment:", err)
		return 2
	}
	if len(requestMap) == 0 {
		fmt.Fprintln(errw, "no environment variables have values matching OJSTER_REGEX; nothing to send")
		return 2
	}

	requestedKeys := make(map[string]struct{}, len(requestMap))
	for k := range requestMap {
		requestedKeys[k] = struct{}{}
	}

	backoff := 1 * time.Second
	const maxBackoff = 30 * time.Second
	var newEnv map[string]string

	for {
		respBody, statusCode, err := postMapToServerJSONFunc(socketPath, requestMap)

		// default: we will retry unless we set accept=true
		accept := false
		var replyMap map[string]string
		var retryFormat string
		var retryArgs []any

		// transport-level error -> retry
		if err != nil {
			retryFormat = "request failed: %v"
			retryArgs = []any{err}
		} else if statusCode < 200 || statusCode >= 300 {
			// non-2xx -> retry without attempting JSON decode
			retryFormat = "server returned status=%d body=%q"
			retryArgs = []any{statusCode, respBody}
		} else {
			// 2xx -> attempt JSON decode
			decodeErr := json.Unmarshal(respBody, &replyMap)
			if decodeErr != nil {
				retryFormat = "failed to decode JSON response (status=%d decodeErr=%v)"
				retryArgs = []any{statusCode, decodeErr}
			} else {
				unexpected := false
				for k := range replyMap {
					if _, ok := requestedKeys[k]; !ok {
						unexpected = true
						break
					}
				}
				if unexpected {
					retryFormat = "reply contains unexpected keys (status=%d)"
					retryArgs = []any{statusCode}
				} else {
					// success
					accept = true
				}
			}
		}

		if accept {
			newEnv = replyMap
			break
		}

		// retry path
		retryWithBackoff(errw, &backoff, maxBackoff, retryFormat, retryArgs...)
	}

	mergedEnv := buildExecEnv(newEnv)
	nextBin := nextArgs[0]
	nextBinPath, err := lookPathFunc(nextBin)
	if err != nil {
		fmt.Fprintf(errw, "executable not found %q: %v\n", nextBin, err)
		return 2
	}
	argv := append([]string{nextBin}, nextArgs[1:]...)
	if err := execFunc(nextBinPath, argv, mergedEnv); err != nil {
		fmt.Fprintf(errw, "failed to exec %s: %v\n", nextBinPath, err)
		return 1
	}

	// If execFunc succeeds the process is replaced and this is not reached.
	// For test stubs that return nil, return success.
	return 0
}

// filterEnvByValue returns a map of env key->value for entries whose value matches OJSTER_REGEX.
// Returns an error if the regex from OJSTER_REGEX is invalid.
func filterEnvByValue(env []string) (map[string]string, error) {
	valRe, err := getValueRegex()
	if err != nil {
		return nil, err
	}
	outw := make(map[string]string)
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		k := parts[0]
		v := ""
		if len(parts) > 1 {
			v = parts[1]
		}
		if !common.KeyNameRegex.MatchString(k) {
			continue
		}
		if valRe.MatchString(v) {
			outw[k] = v
		}
	}
	return outw, nil
}

func postMapToServerJSON(socketPath string, m map[string]string) ([]byte, int, error) {
	j, err := json.Marshal(m)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to marshal request JSON: %v", err)
	}

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest("POST", "http://unix/", bytes.NewReader(j))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respBody, resp.StatusCode, fmt.Errorf("failed to read response body: %v", err)
	}

	return respBody, resp.StatusCode, nil
}

func buildExecEnv(newMap map[string]string) []string {
	current := environFunc()
	out := make([]string, 0, len(current)+len(newMap))
	allowed := make(map[string]struct{}, len(current))

	// Copy current env unless overridden or skipped
	for _, kv := range current {
		k, _, _ := strings.Cut(kv, "=")

		if !strings.HasPrefix(k, "OJSTER_") {
			allowed[k] = struct{}{}
			if _, overridden := newMap[k]; !overridden {
				out = append(out, kv)
			}
		}
	}

	// Add overrides
	for k, v := range newMap {
		if _, ok := allowed[k]; ok {
			out = append(out, k+"="+v)
		}
	}

	return out
}

func getValueRegex() (*regexp.Regexp, error) {
	pattern := os.Getenv("OJSTER_REGEX")
	if pattern == "" {
		pattern = pqc.DefaultValueRegex()
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid OJSTER_REGEX %q: %w", pattern, err)
	}
	return re, nil
}
