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

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ojster/ojster/internal/pqc"
)

//
// ─────────────────────────────────────────────────────────────
//   TEST HELPERS
// ─────────────────────────────────────────────────────────────
//

func EnvSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		out[k] = v
	}
	return out
}

func stubExec(t *testing.T) (*string, *[]string, *[]string) {
	t.Helper()
	var execPath string
	var execArgv []string
	var execEnv []string

	old := execFunc
	execFunc = func(path string, argv []string, envv []string) error {
		execPath = path
		execArgv = append([]string{}, argv...)
		execEnv = append([]string{}, envv...)
		return nil
	}
	t.Cleanup(func() { execFunc = old })
	return &execPath, &execArgv, &execEnv
}

func stubSleep(t *testing.T) {
	t.Helper()
	old := sleepFunc
	sleepFunc = func(time.Duration) {}
	t.Cleanup(func() { sleepFunc = old })
}

func stubPost(t *testing.T) {
	t.Helper()
	old := postMapToServerJSONFunc
	postMapToServerJSONFunc = func(socketPath string, m map[string]string) ([]byte, int, error) {
		return nil, 0, fmt.Errorf("stubbed")
	}
	t.Cleanup(func() { postMapToServerJSONFunc = old })
}

func startUnixHTTPServer(t *testing.T, handler http.Handler) (socketPath string, closeFunc func()) {
	t.Helper()
	socketPath = filepath.Join(t.TempDir(), "ojster.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}

	srv := &http.Server{Handler: handler}

	go func() {
		_ = srv.Serve(ln)
	}()

	closeFunc = func() {
		_ = srv.Close()
		_ = ln.Close()
	}
	return socketPath, closeFunc
}

//
// ─────────────────────────────────────────────────────────────
//   filterEnvByValue / regex validation
// ─────────────────────────────────────────────────────────────
//

// Test that an invalid regex passed into filterEnvByValue returns an error.
func TestFilterEnvByValue_InvalidRegex(t *testing.T) {
	env := []string{"A=1"}
	_, err := filterEnvByValue(env, "(")
	if err == nil {
		t.Fatalf("expected error for invalid regex")
	}
}

func TestFilterEnvByValue(t *testing.T) {
	t.Run("default_regex", func(t *testing.T) {
		// Construct canonical sealed values for tests
		mlkem := []byte{0x01, 0x02, 0x03}
		gcm := []byte{0x04, 0x05}
		sealed := pqc.BuildSealed(mlkem, gcm)

		env := []string{
			"GOOD=" + sealed,
			"WRAPPED='" + sealed + "'",
			"BAD=plain",
			"INVALID-NAME=" + sealed,
		}

		// Use the canonical default regex from pqc
		regex := pqc.DefaultValueRegex()

		out, err := filterEnvByValue(env, regex)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := out["GOOD"]; !ok {
			t.Fatalf("expected GOOD")
		}
		if _, ok := out["WRAPPED"]; !ok {
			t.Fatalf("expected WRAPPED")
		}
		if _, ok := out["BAD"]; ok {
			t.Fatalf("did not expect BAD")
		}
		if _, ok := out["INVALID-NAME"]; ok {
			t.Fatalf("did not expect INVALID-NAME")
		}
	})

	t.Run("custom_regex", func(t *testing.T) {
		env := []string{"A=foo123", "B=bar"}
		out, err := filterEnvByValue(env, "^foo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if _, ok := out["A"]; !ok {
			t.Fatalf("expected A")
		}
		if _, ok := out["B"]; ok {
			t.Fatalf("did not expect B")
		}
	})
}

//
// ─────────────────────────────────────────────────────────────
//   buildExecEnv
// ─────────────────────────────────────────────────────────────
//

func TestBuildExecEnv(t *testing.T) {
	origEnviron := environFunc
	t.Cleanup(func() { environFunc = origEnviron })

	environFunc = func() []string {
		return []string{
			"A=1",
			"B=2",
			"EMPTY=",
			"D=4",
			"OJSTER_FOO=1",
		}
	}

	overrides := map[string]string{
		"B":          "22", // allowed override
		"C":          "3",  // ignored (not in environ)
		"D":          "",   // allowed override to empty
		"OJSTER_FOO": "2",  // ignored (OJSTER_ keys cannot be overridden)
	}

	out := buildExecEnv(overrides)
	got := EnvSliceToMap(out)

	want := map[string]string{
		"A":     "1",
		"B":     "22",
		"EMPTY": "",
		"D":     "",
	}

	if !maps.Equal(got, want) {
		t.Fatalf("mismatch\nwant=%v\ngot=%v", want, got)
	}
}

//
// ─────────────────────────────────────────────────────────────
//   run()
// ─────────────────────────────────────────────────────────────
//

func TestRun_BasicFlow(t *testing.T) {
	execPath, execArgv, execEnv := stubExec(t)

	oldPost := postMapToServerJSONFunc
	t.Cleanup(func() { postMapToServerJSONFunc = oldPost })

	// Build a canonical sealed value using pqc helper
	mlkem := []byte{0x01, 0x02, 0x03}
	gcm := []byte{0x04, 0x05}
	sealed := pqc.BuildSealed(mlkem, gcm)

	postMapToServerJSONFunc = func(socketPath string, m map[string]string) ([]byte, int, error) {
		if len(m) != 1 || m["SECRET"] != sealed {
			t.Fatalf("unexpected request map: %#v", m)
		}
		return []byte(`{"SECRET":"decrypted"}`), 200, nil
	}

	// Ensure the environment contains the sealed value
	t.Setenv("SECRET", sealed)
	t.Setenv("PLAIN", "hello")

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	// Pass regex and socketPath explicitly. socketPath is unused by the stubbed post.
	code := Run(pqc.DefaultValueRegex(), "unused-socket", []string{"echo", "hello"}, &outBuf, &errBuf)
	if code != 0 {
		t.Fatalf("Run returned non-zero exit code: %d stderr=%q", code, errBuf.String())
	}

	if !strings.HasSuffix(*execPath, "echo") {
		t.Fatalf("expected exec path to end with echo, got %s", *execPath)
	}
	if len(*execArgv) != 2 || (*execArgv)[0] != "echo" || (*execArgv)[1] != "hello" {
		t.Fatalf("unexpected argv: %#v", *execArgv)
	}

	envMap := EnvSliceToMap(*execEnv)
	if envMap["SECRET"] != "decrypted" {
		t.Fatalf("expected SECRET=decrypted, got %v", envMap["SECRET"])
	}
}

//
// ─────────────────────────────────────────────────────────────
//   run() ERROR PATHS
// ─────────────────────────────────────────────────────────────
//

func TestRun_RetryScenarios(t *testing.T) {
	cases := []struct {
		name      string
		responses [][]byte
		statuses  []int
		wantCalls int
	}{
		{
			name: "server_errors_then_success",
			responses: [][]byte{
				[]byte("err"),
				[]byte("err"),
				[]byte(`{"SECRET":"ok"}`),
			},
			statuses:  []int{500, 500, 200},
			wantCalls: 3,
		},
		{
			name: "malformed_json_then_success",
			responses: [][]byte{
				[]byte("{bad"),
				[]byte("{bad"),
				[]byte(`{"SECRET":"ok"}`),
			},
			statuses:  []int{200, 200, 200},
			wantCalls: 3,
		},
		{
			name: "unexpected_keys_then_success",
			responses: [][]byte{
				[]byte(`{"SECRET":"x","BAD":"y"}`),
				[]byte(`{"SECRET":"ok"}`),
			},
			statuses:  []int{200, 200},
			wantCalls: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _ = stubExec(t)
			stubSleep(t)

			oldPost := postMapToServerJSONFunc
			t.Cleanup(func() { postMapToServerJSONFunc = oldPost })

			call := 0
			postMapToServerJSONFunc = func(socketPath string, m map[string]string) ([]byte, int, error) {
				resp := tc.responses[call]
				code := tc.statuses[call]
				call++
				return resp, code, nil
			}

			// Use canonical sealed format so the stricter pqc.DefaultValueRegex matches.
			mlkem := []byte{0x01, 0x02, 0x03}
			gcm := []byte{0x04, 0x05}
			sealed := pqc.BuildSealed(mlkem, gcm)

			t.Setenv("SECRET", sealed)

			var outBuf bytes.Buffer
			var errBuf bytes.Buffer

			// socketPath unused by stubbed post
			code := Run(pqc.DefaultValueRegex(), "unused-socket", []string{"echo"}, &outBuf, &errBuf)
			if code != 0 {
				t.Fatalf("Run returned non-zero exit code: %d stderr=%q", code, errBuf.String())
			}

			if call != tc.wantCalls {
				t.Fatalf("expected %d calls, got %d", tc.wantCalls, call)
			}
		})
	}
}

func TestRun_Error_NoNextBinary(t *testing.T) {
	stubPost(t)
	t.Setenv("SECRET", "") // ensure no encrypted vars

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	code := Run(pqc.DefaultValueRegex(), "unused-socket", []string{}, &outBuf, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit code %d for missing next-binary, got %d stderr=%q", 2, code, errBuf.String())
	}
}

func TestRun_Error_NoMatchingEnv(t *testing.T) {
	stubPost(t)
	t.Setenv("PLAIN", "hello")
	t.Setenv("SECRET", "") // ensure no encrypted vars

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	code := Run(pqc.DefaultValueRegex(), "unused-socket", []string{"echo"}, &outBuf, &errBuf)
	if code != 2 {
		t.Fatalf("expected exit code %d for no matching env, got %d stderr=%q", 2, code, errBuf.String())
	}
}

func TestRun_Error_ExecNotFound(t *testing.T) {
	// POST succeeds
	oldPost := postMapToServerJSONFunc
	t.Cleanup(func() { postMapToServerJSONFunc = oldPost })
	postMapToServerJSONFunc = func(url string, m map[string]string) ([]byte, int, error) {
		return []byte(`{"SECRET":"ok"}`), 200, nil
	}

	t.Setenv("SECRET", "OJSTER-1:ABC")

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	code := Run(pqc.DefaultValueRegex(), "unused-socket", []string{"does-not-exist"}, &outBuf, &errBuf)
	if code != 2 {
		t.Fatalf("expected exec-not-found exit code %d, got %d stderr=%q", 2, code, errBuf.String())
	}
}

//
// ─────────────────────────────────────────────────────────────
//   postMapToServerJSON
// ─────────────────────────────────────────────────────────────
//

func TestPostMapToServerJSON(t *testing.T) {
	socketPath, closeSrv := startUnixHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := map[string]string{}
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if m["A"] != "1" {
			t.Fatalf("expected A=1")
		}
		w.Write([]byte(`{"OK":"yes"}`))
	}))
	defer closeSrv()

	respBody, status, err := postMapToServerJSON(socketPath, map[string]string{"A": "1"})
	if err != nil {
		t.Fatalf("postMapToServerJSON error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200")
	}
	if string(respBody) != `{"OK":"yes"}` {
		t.Fatalf("unexpected body: %s", string(respBody))
	}
}
