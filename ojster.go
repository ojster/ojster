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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
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

const defaultValueRegex = `^'?(encrypted:[A-Za-z0-9+/=]+)'?$`

var version = "0.0.0"
var startTime = time.Now()
var keyNameRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Assign functions to vars so tests can override them
var environFunc = os.Environ
var execFunc = syscall.Exec
var exitFunc = os.Exit
var postMapToServerJSONFunc = postMapToServerJSON
var sleepFunc = time.Sleep

// -------------------- main / helpers --------------------

func main() {
	log.SetFlags(0)

	prog := filepath.Base(os.Args[0])
	args := os.Args[1:]

	mode, subargs := dispatch(prog, args)

	switch mode {
	case "help":
		printHelpAndExit()
	case "version":
		fmt.Println(version)
	case "run":
		run(subargs)
	case "serve":
		serve(context.Background(), subargs)
	}
}

func dispatch(prog string, args []string) (mode string, subargs []string) {
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
	case "run":
		return "run", normalizeArgsForSubcommand(args[1:])
	case "serve":
		return "serve", normalizeArgsForSubcommand(args[1:])
	default:
		return "help", nil
	}
}

func printHelpAndExit() { fmt.Print(header); exitFunc(0) }

func normalizeArgsForSubcommand(raw []string) []string {
	if len(raw) > 0 && raw[0] == "--" {
		return raw[1:]
	}
	return raw
}

func errf(format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	if strings.HasPrefix(msg, "ojster:") {
		return errors.New(msg)
	}
	return errors.New("ojster: " + msg)
}

func readJSON(r io.Reader, maxBytes int64, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes))
	if err != nil {
		return errf("failed to read body: %v", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return errf("invalid JSON: %v", err)
	}
	return nil
}

func getValueRegex() *regexp.Regexp {
	pattern := os.Getenv("OJSTER_REGEX")
	if pattern == "" {
		pattern = defaultValueRegex
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		fmt.Fprintln(os.Stderr, errf("invalid OJSTER_REGEX %q: %v", pattern, err))
		exitFunc(2)
	}
	return re
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
		if !keyNameRegex.MatchString(k) {
			continue
		}
		if valRe.MatchString(v) {
			out[k] = v
		}
	}
	return out
}

func sanitizeServerError(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		return errf("server returned keys=%v", keys).Error()
	}
	return errf("server error: %s", string(body)).Error()
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

func getSocketPath() string {
	p := os.Getenv("OJSTER_SOCKET_PATH")
	if p == "" {
		return "/mnt/ojster/ipc.sock"
	}
	return p
}

// -------------------- RUN MODE (client) --------------------

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

func run(nextArgs []string) {
	if len(nextArgs) < 1 {
		fmt.Fprintln(os.Stderr, errf("run requires a next-binary to execute. Usage: ojster run <next-binary> [args...]"))
		exitFunc(2)
	}

	log.Println("ojster run")

	socketPath := getSocketPath()

	allEnv := environFunc()
	requestMap := filterEnvByValue(allEnv)
	if len(requestMap) == 0 {
		fmt.Fprintln(os.Stderr, errf("no environment variables have values matching OJSTER_REGEX; nothing to send"))
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
		fmt.Fprintln(os.Stderr, errf("executable not found %q: %v", nextBin, err))
		exitFunc(2)
	}
	argv := append([]string{nextBin}, nextArgs[1:]...)
	if err := execFunc(nextBinPath, argv, mergedEnv); err != nil {
		fmt.Fprintln(os.Stderr, errf("failed to exec %s: %v", nextBinPath, err))
		exitFunc(1)
	}
}

func postMapToServerJSON(socketPath string, m map[string]string) ([]byte, int, error) {
	j, err := json.Marshal(m)
	if err != nil {
		return nil, 0, errf("failed to marshal request JSON: %v", err)
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
		return nil, 0, errf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, errf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return respBody, resp.StatusCode, errf("failed to read response body: %v", err)
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

// -------------------- SERVE MODE (server) --------------------

const linuxTmpfsMagic = 0x01021994

func checkTempIsTmpfs(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return errf("failed to statfs %s: %v", path, err)
	}
	if uint64(stat.Type) != linuxTmpfsMagic {
		return errf("path %s is not on tmpfs (statfs type 0x%x)", path, uint64(stat.Type))
	}
	return nil
}

func serve(ctx context.Context, cmdArgs []string) {
	defaultCmd := []string{"dotenvx", "get", "-o"}
	cmd := defaultCmd
	if len(cmdArgs) > 0 {
		cmd = cmdArgs
	}

	if err := checkTempIsTmpfs(os.TempDir()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitFunc(1)
	}

	socketPath := getSocketPath()

	privateKeyFile := os.Getenv("OJSTER_PRIVATE_KEY_FILE")
	if privateKeyFile == "" {
		privateKeyFile = "/run/secrets/private_key"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("HEAD /health", healthHandler)
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		handlePost(w, r, cmd, privateKeyFile)
	})

	_ = os.RemoveAll(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, errf("failed to listen on unix socket %s: %v", socketPath, err))
		exitFunc(1)
	}

	if err := os.Chmod(socketPath, 0o666); err != nil {
		fmt.Fprintln(os.Stderr, errf("failed to chmod socket %s: %v", socketPath, err))
		ln.Close()
		exitFunc(1)
	}

	server := &http.Server{Handler: loggingMiddleware(mux)}

	fmt.Fprintf(os.Stderr, "ojster serving on unix socket %s\n", socketPath)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, errf("server error: %v", err))
		exitFunc(1)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		fmt.Fprintf(os.Stderr, "%s %s %s\n", r.Method, r.URL.Path, time.Since(start))
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime).Seconds()
	resp := map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
		"uptime": fmt.Sprintf("%.0f", uptime),
	}

	j, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(j)
}

// -------------------- POST HANDLER --------------------

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
		if !keyNameRegex.MatchString(k) {
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
