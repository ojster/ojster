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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ojster/ojster/internal/pqc"
)

//
// ─────────────────────────────────────────────────────────────
//   TEST HELPERS
// ─────────────────────────────────────────────────────────────
//

func ExpectBodyContains(t *testing.T, rec *httptest.ResponseRecorder, substr string) {
	t.Helper()
	if !strings.Contains(rec.Body.String(), substr) {
		t.Fatalf("expected body to contain %q, got %q", substr, rec.Body.String())
	}
}

func Sh(script string) []string { return []string{"sh", "-c", script} }

//
// ─────────────────────────────────────────────────────────────
//   handlePost
// ─────────────────────────────────────────────────────────────
//

func TestHandlePost_Success(t *testing.T) {
	body := []byte(`{"FOO":"bar"}`)
	cmd := Sh(`printf '{"FOO":"ok"}'`)
	rec := runPost(t, body, cmd, "/tmp/key")
	ExpectStatus(t, rec, http.StatusOK)

	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

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
		{"invalid_json", "{bad json", Sh(`printf '{}'`), 400, "invalid JSON"},
		{"invalid_key", `{"BAD-NAME":"v"}`, Sh(`printf '{}'`), 400, "invalid key"},
		{"unexpected_keys", `{"GOOD":"v"}`, Sh(`printf '{"GOOD":"1","BAD":"x"}'`), 502, "unexpected keys"},
		{"subprocess_invalid_json", `{"GOOD":"v"}`, Sh(`printf '{bad json'`), 502, "invalid JSON"},
		{"exit_error", `{"FOO":"bar"}`, Sh(`exit 3`), 502, "exit 3"},
		{"generic_error", `{"FOO":"bar"}`, []string{"does-not-exist"}, 500, "failed to run"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := runPost(t, []byte(tc.body), tc.cmd, "/x")
			ExpectStatus(t, rec, tc.wantCode)
			ExpectBodyContains(t, rec, tc.wantSub)
		})
	}
}

// Test that when cmdArgs is empty the handler uses the direct UnsealFromJSON path.
func TestHandlePost_DirectUnsealPath(t *testing.T) {
	td := t.TempDir()
	priv := filepath.Join(td, "priv.b64")
	pub := filepath.Join(td, "pub.b64")
	envFile := filepath.Join(td, "sealed.env")

	// Generate keypair
	var outBuf, errBuf bytes.Buffer
	if code := pqc.KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
		t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
	}

	// Seal a value into envFile under key "FOO"
	plaintext := []byte("direct-secret")
	if code := pqc.SealWithPlaintext(pub, envFile, "FOO", plaintext, &outBuf, &errBuf); code != 0 {
		t.Fatalf("SealWithPlaintext failed: code=%d stderr=%q", code, errBuf.String())
	}

	// Read the sealed value from the env file (format KEY=VALUE\n)
	b, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read sealed env file: %v", err)
	}
	// env file contains a single line "FOO=<sealed>"
	// Extract the part after '='
	line := string(bytes.TrimSpace(b))
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		t.Fatalf("unexpected sealed env format: %q", line)
	}
	sealedValue := parts[1]

	// Build request body with the sealed value (client sends sealed values)
	reqBodyMap := map[string]string{"FOO": sealedValue}
	reqBody, err := json.Marshal(reqBodyMap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// cmd == nil triggers the direct UnsealFromJSON path in handlePost
	rec := runPost(t, reqBody, nil, priv)
	ExpectStatus(t, rec, http.StatusOK)

	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	if out["FOO"] != string(plaintext) {
		t.Fatalf("expected FOO=%q, got %#v", string(plaintext), out)
	}
}
