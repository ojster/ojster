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

package run

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/ojster/ojster/internal/common"
	"github.com/ojster/ojster/internal/util"
	"github.com/ojster/ojster/internal/util/file"
)

const defaultValueRegex = `^'?(encrypted:[A-Za-z0-9+/=]+)'?$`

// Assign functions to vars so tests can override them
var (
	environFunc             = os.Environ
	execFunc                = syscall.Exec
	exitFunc                = os.Exit
	postMapToServerJSONFunc = postMapToServerJSON
	sleepFunc               = time.Sleep
)

func Run(nextArgs []string) {
	if len(nextArgs) < 1 {
		fmt.Fprintln(os.Stderr, util.Errf("run requires a next-binary to execute. Usage: ojster run <next-binary> [args...]"))
		exitFunc(2)
	}

	log.Println("ojster run")

	socketPath := file.GetSocketPath()

	allEnv := environFunc()
	requestMap := filterEnvByValue(allEnv)
	if len(requestMap) == 0 {
		fmt.Fprintln(os.Stderr, util.Errf("no environment variables have values matching OJSTER_REGEX; nothing to send"))
		exitFunc(2)
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

		var replyMap map[string]string
		decodeErr := json.Unmarshal(respBody, &replyMap)

		if isSuccessfulReply(err, statusCode, decodeErr, replyMap, requestedKeys) {
			newEnv = replyMap
			break
		}

		log.Printf("retrying in %s", backoff)
		sleepFunc(backoff)
		backoff = min(backoff*2, maxBackoff)
	}

	mergedEnv := buildExecEnv(newEnv)
	nextBin := nextArgs[0]
	nextBinPath, err := exec.LookPath(nextBin)
	if err != nil {
		fmt.Fprintln(os.Stderr, util.Errf("executable not found %q: %v", nextBin, err))
		exitFunc(2)
	}
	argv := append([]string{nextBin}, nextArgs[1:]...)
	if err := execFunc(nextBinPath, argv, mergedEnv); err != nil {
		fmt.Fprintln(os.Stderr, util.Errf("failed to exec %s: %v", nextBinPath, err))
		exitFunc(1)
	}
}

func hasUnexpectedKeys(reply map[string]string, requested map[string]struct{}) bool {
	for k := range reply {
		if _, ok := requested[k]; !ok {
			return true
		}
	}
	return false
}

func isSuccessfulReply(err error, status int, decodeErr error, reply map[string]string, requested map[string]struct{}) bool {
	return err == nil &&
		status >= 200 && status < 300 &&
		decodeErr == nil &&
		!hasUnexpectedKeys(reply, requested)
}

func filterEnvByValue(env []string) map[string]string {
	valRe := getValueRegex()
	out := make(map[string]string)
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
			out[k] = v
		}
	}
	return out
}

func postMapToServerJSON(socketPath string, m map[string]string) ([]byte, int, error) {
	j, err := json.Marshal(m)
	if err != nil {
		return nil, 0, util.Errf("failed to marshal request JSON: %v", err)
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
		return nil, 0, util.Errf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, util.Errf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respBody, resp.StatusCode, util.Errf("failed to read response body: %v", err)
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

func getValueRegex() *regexp.Regexp {
	pattern := os.Getenv("OJSTER_REGEX")
	if pattern == "" {
		pattern = defaultValueRegex
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Fprintln(os.Stderr, util.Errf("invalid OJSTER_REGEX %q: %v", pattern, err))
		exitFunc(2)
	}
	return re
}
