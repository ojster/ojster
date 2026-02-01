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
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

//
// ─────────────────────────────────────────────────────────────
//   TEST HELPERS
// ─────────────────────────────────────────────────────────────
//

func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	f()

	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func runPost(t *testing.T, body []byte, cmd []string, priv string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handlePost(rec, req, cmd, priv)
	return rec
}

func expectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected %d, got %d (%s)", want, rec.Code, rec.Body.String())
	}
}

func expectBodyContains(t *testing.T, rec *httptest.ResponseRecorder, substr string) {
	t.Helper()
	if !strings.Contains(rec.Body.String(), substr) {
		t.Fatalf("expected body to contain %q, got %q", substr, rec.Body.String())
	}
}

func decodeJSON[T any](t *testing.T, data []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return v
}

func sh(script string) []string { return []string{"sh", "-c", script} }

func envSliceToMap(env []string) map[string]string {
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
	postMapToServerJSONFunc = func(url string, m map[string]string) ([]byte, int, error) {
		return nil, 0, fmt.Errorf("stubbed")
	}
	t.Cleanup(func() { postMapToServerJSONFunc = old })
}

func stubExit(t *testing.T) *int {
	t.Helper()
	var code int
	old := exitFunc
	exitFunc = func(c int) {
		code = c
		panic("exit")
	}
	t.Cleanup(func() { exitFunc = old })
	return &code
}

func expectExitPanic(t *testing.T, code *int, want int) {
	t.Helper()
	if r := recover(); r != "exit" {
		t.Fatalf("expected exit panic, got %v", r)
	}
	if *code != want {
		t.Fatalf("expected exit code %d, got %d", want, *code)
	}
}

func waitForServer(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/health")
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server did not start in time")
}

//
// ─────────────────────────────────────────────────────────────
//   DISPATCH TESTS
// ─────────────────────────────────────────────────────────────
//

func TestDispatch_BasicModes(t *testing.T) {
	tests := []struct {
		prog string
		args []string
		mode string
		want []string
	}{
		{"ojster", []string{}, "help", nil},
		{"ojster", []string{"help"}, "help", nil},
		{"ojster", []string{"version"}, "version", nil},
		{"ojster", []string{"run", "echo", "hi"}, "run", []string{"echo", "hi"}},
		{"ojster", []string{"serve", "--", "cmd"}, "serve", []string{"cmd"}},
		{"ojster", []string{"wat"}, "help", nil},
		{"docker-init", []string{"--", "echo", "hello"}, "run", []string{"echo", "hello"}},
	}

	for _, tc := range tests {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			mode, args := dispatch(tc.prog, tc.args)
			if mode != tc.mode {
				t.Fatalf("mode mismatch: want=%s got=%s", tc.mode, mode)
			}
			if !slices.Equal(args, tc.want) {
				t.Fatalf("args mismatch: want=%v got=%v", tc.want, args)
			}
		})
	}
}

//
// ─────────────────────────────────────────────────────────────
//   getValueRegex / filterEnvByValue / sanitizeServerError
// ─────────────────────────────────────────────────────────────
//

func TestGetValueRegex_InvalidRegex(t *testing.T) {
	code := stubExit(t)
	t.Setenv("OJSTER_REGEX", "(")

	defer expectExitPanic(t, code, 2)

	getValueRegex()
}

func TestFilterEnvByValue(t *testing.T) {
	t.Run("default_regex", func(t *testing.T) {
		t.Setenv("OJSTER_REGEX", "")

		env := []string{
			"GOOD=encrypted:ABC123",
			"WRAPPED='encrypted:XYZ'",
			"BAD=plain",
			"INVALID-NAME=encrypted:ABC",
		}

		out := filterEnvByValue(env)

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
		t.Setenv("OJSTER_REGEX", "^foo")

		env := []string{"A=foo123", "B=bar"}
		out := filterEnvByValue(env)

		if _, ok := out["A"]; !ok {
			t.Fatalf("expected A")
		}
		if _, ok := out["B"]; ok {
			t.Fatalf("did not expect B")
		}
	})
}

func TestSanitizeServerError_JSON(t *testing.T) {
	body := []byte(`{"A":"1","B":"2"}`)
	s := sanitizeServerError(body)
	if !strings.Contains(s, "A") || !strings.Contains(s, "B") {
		t.Fatalf("expected keys")
	}
	if strings.Contains(s, "1") || strings.Contains(s, "2") {
		t.Fatalf("should not show values")
	}
}

func TestSanitizeServerError_Text(t *testing.T) {
	s := sanitizeServerError([]byte("some error"))
	if s != "ojster: server error: some error" {
		t.Fatalf("unexpected: %q", s)
	}
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
	got := envSliceToMap(out)

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
//   checkTempIsTmpfs
// ─────────────────────────────────────────────────────────────
//

func TestCheckTempIsTmpfs(t *testing.T) {
	t.Run("statfs_error", func(t *testing.T) {
		err := checkTempIsTmpfs("/definitely-not-existing")
		if err == nil || !strings.Contains(err.Error(), "failed to statfs") {
			t.Fatalf("expected statfs error, got %v", err)
		}
	})

	t.Run("not_tmpfs", func(t *testing.T) {
		err := checkTempIsTmpfs("/tmp2")
		if err == nil || !strings.Contains(err.Error(), "not on tmpfs") {
			t.Fatalf("expected not-tmpfs error, got %v", err)
		}
	})

	t.Run("is_tmpfs", func(t *testing.T) {
		err := checkTempIsTmpfs("/tmp")
		if err != nil {
			t.Fatalf("expected /tmp to be tmpfs, got %v", err)
		}
	})
}

func TestServe_TmpfsFailure_StatfsError(t *testing.T) {
	code := stubExit(t)
	t.Setenv("TMPDIR", "/definitely-not-existing")

	out := captureStderr(t, func() {
		defer expectExitPanic(t, code, 1)
		serve(context.Background(), nil)
	})

	if !strings.Contains(out, "failed to statfs") {
		t.Fatalf("expected statfs failure, got: %s", out)
	}
}

//
// ─────────────────────────────────────────────────────────────
//   postMapToServerJSON
// ─────────────────────────────────────────────────────────────
//

func TestPostMapToServerJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m := decodeJSON[map[string]string](t, body)
		if m["A"] != "1" {
			t.Fatalf("expected A=1")
		}
		w.Write([]byte(`{"OK":"yes"}`))
	}))
	defer ts.Close()

	respBody, status, err := postMapToServerJSON(ts.URL, map[string]string{"A": "1"})
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

//
// ─────────────────────────────────────────────────────────────
//   healthHandler / loggingMiddleware
// ─────────────────────────────────────────────────────────────
//

func TestHealthHandler_OK(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	healthHandler(rec, req)
	expectStatus(t, rec, http.StatusOK)

	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON")
	}
	if m["status"] != "ok" {
		t.Fatalf("expected status ok")
	}
}

func TestLoggingMiddleware(t *testing.T) {
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	mw := loggingMiddleware(h)

	req := httptest.NewRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("handler not called")
	}
	expectStatus(t, rec, http.StatusTeapot)
}

//
// ─────────────────────────────────────────────────────────────
//   handlePost
// ─────────────────────────────────────────────────────────────
//

func TestHandlePost_Success(t *testing.T) {
	body := []byte(`{"FOO":"bar"}`)
	cmd := sh(`printf '{"FOO":"ok"}'`)
	rec := runPost(t, body, cmd, "/tmp/key")
	expectStatus(t, rec, http.StatusOK)

	out := decodeJSON[map[string]string](t, rec.Body.Bytes())
	if out["FOO"] != "ok" {
		t.Fatalf("expected FOO=ok, got %#v", out)
	}
}

func TestHandlePost_Errors(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		cmd      []string
		wantCode int
		wantSub  string
	}{
		{"invalid_json", "{bad json", sh(`printf '{}'`), 400, "invalid JSON"},
		{"invalid_key", `{"BAD-NAME":"v"}`, sh(`printf '{}'`), 400, "invalid key"},
		{"unexpected_keys", `{"GOOD":"v"}`, sh(`printf '{"GOOD":"1","BAD":"x"}'`), 502, "unexpected keys"},
		{"subprocess_invalid_json", `{"GOOD":"v"}`, sh(`printf '{bad json'`), 502, "invalid JSON"},
		{"exit_error", `{"FOO":"bar"}`, sh(`exit 3`), 502, "exit 3"},
		{"generic_error", `{"FOO":"bar"}`, []string{"does-not-exist"}, 500, "failed to run"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := runPost(t, []byte(tc.body), tc.cmd, "/x")
			expectStatus(t, rec, tc.wantCode)
			expectBodyContains(t, rec, tc.wantSub)
		})
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

	postMapToServerJSONFunc = func(url string, m map[string]string) ([]byte, int, error) {
		if len(m) != 1 || m["SECRET"] != "encrypted:ABC" {
			t.Fatalf("unexpected request map: %#v", m)
		}
		return []byte(`{"SECRET":"decrypted"}`), 200, nil
	}

	t.Setenv("SECRET", "encrypted:ABC")
	t.Setenv("PLAIN", "hello")

	run([]string{"echo", "hello"})

	if !strings.HasSuffix(*execPath, "echo") {
		t.Fatalf("expected exec path to end with echo, got %s", *execPath)
	}
	if len(*execArgv) != 2 || (*execArgv)[0] != "echo" || (*execArgv)[1] != "hello" {
		t.Fatalf("unexpected argv: %#v", *execArgv)
	}

	envMap := envSliceToMap(*execEnv)
	if envMap["SECRET"] != "decrypted" {
		t.Fatalf("expected SECRET=decrypted, got %v", envMap["SECRET"])
	}
}

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
			postMapToServerJSONFunc = func(url string, m map[string]string) ([]byte, int, error) {
				resp := tc.responses[call]
				code := tc.statuses[call]
				call++
				return resp, code, nil
			}

			t.Setenv("SECRET", "encrypted:ABC")

			run([]string{"echo"})

			if call != tc.wantCalls {
				t.Fatalf("expected %d calls, got %d", tc.wantCalls, call)
			}
		})
	}
}

//
// ─────────────────────────────────────────────────────────────
//   run() ERROR PATHS (exit stubbing)
// ─────────────────────────────────────────────────────────────
//

func TestRun_Error_NoNextBinary(t *testing.T) {
	code := stubExit(t)
	stubPost(t)
	t.Setenv("SECRET", "") // ensure no encrypted vars
	defer expectExitPanic(t, code, 2)
	run([]string{})
}

func TestRun_Error_NoMatchingEnv(t *testing.T) {
	code := stubExit(t)
	stubPost(t)
	t.Setenv("PLAIN", "hello")
	t.Setenv("SECRET", "") // ensure no encrypted vars
	defer expectExitPanic(t, code, 2)
	run([]string{"echo"})
}

func TestRun_Error_ExecNotFound(t *testing.T) {
	code := stubExit(t)

	// POST succeeds
	postMapToServerJSONFunc = func(url string, m map[string]string) ([]byte, int, error) {
		return []byte(`{"SECRET":"ok"}`), 200, nil
	}

	t.Setenv("SECRET", "encrypted:ABC")
	defer expectExitPanic(t, code, 2)
	run([]string{"does-not-exist"})
}

//
// ─────────────────────────────────────────────────────────────
//   serve()
// ─────────────────────────────────────────────────────────────
//

func TestServe_StartupAndHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	t.Setenv("OJSTER_PORT", fmt.Sprintf("%d", port))

	tmp := t.TempDir()
	t.Setenv("OJSTER_PRIVATE_KEY_FILE", filepath.Join(tmp, ".env"))

	done := make(chan struct{})
	go func() {
		serve(ctx, nil)
		close(done)
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForServer(t, baseURL)

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	cancel()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatalf("server did not shut down")
	}
}

func TestServe_InvalidPort(t *testing.T) {
	code := stubExit(t)
	t.Setenv("OJSTER_PORT", "not-a-number")
	defer expectExitPanic(t, code, 2)
	serve(context.Background(), nil)
}
