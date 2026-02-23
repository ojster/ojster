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

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func expectBodyContains(t *testing.T, rec *httptest.ResponseRecorder, substr string) {
	t.Helper()
	if !strings.Contains(rec.Body.String(), substr) {
		t.Fatalf("expected body to contain %q, got %q", substr, rec.Body.String())
	}
}

func sh(script string) []string { return []string{"sh", "-c", script} }

//
// ─────────────────────────────────────────────────────────────
//   handlePost
// ─────────────────────────────────────────────────────────────
//

func TestHandlePost_Success(t *testing.T) {
	body := []byte(`{"FOO":"bar"}`)
	cmd := sh(`printf '{"FOO":"ok"}'`)
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
			ExpectStatus(t, rec, tc.wantCode)
			expectBodyContains(t, rec, tc.wantSub)
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

func TestHandlePost_DirectUnsealPath_StatusMapping(t *testing.T) {
	t.Run("missing private key -> 500", func(t *testing.T) {
		// Build a sealed-looking value but point to a non-existent private key
		// valid sealed value (we don't need real mlkem/gcm bytes for format tests)
		valid := pqc.BuildSealed([]byte{0x01, 0x02}, []byte{0x03, 0x04})
		reqBodyMap := map[string]string{"FOO": valid}
		reqBody, _ := json.Marshal(reqBodyMap)

		rec := runPost(t, reqBody, nil, "/nonexistent/priv.b64")
		ExpectStatus(t, rec, http.StatusInternalServerError)
		expectBodyContains(t, rec, "failed to read private key file")
	})

	t.Run("malformed sealed value -> 502", func(t *testing.T) {
		// Create a real keypair and a sealed value, then corrupt it so unseal fails.
		td := t.TempDir()
		priv := filepath.Join(td, "priv.b64")
		pub := filepath.Join(td, "pub.b64")
		envFile := filepath.Join(td, "sealed.env")

		var outBuf, errBuf bytes.Buffer
		if code := pqc.KeypairWithPaths(priv, pub, &outBuf, &errBuf); code != 0 {
			t.Fatalf("KeypairWithPaths failed: code=%d stderr=%q", code, errBuf.String())
		}

		if code := pqc.SealWithPlaintext(pub, envFile, "FOO", []byte("v"), &outBuf, &errBuf); code != 0 {
			t.Fatalf("SealWithPlaintext failed: code=%d stderr=%q", code, errBuf.String())
		}

		// Read the sealed value and corrupt it (remove separator)
		b, err := os.ReadFile(envFile)
		if err != nil {
			t.Fatalf("read sealed env file: %v", err)
		}
		line := string(bytes.TrimSpace(b))
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			t.Fatalf("unexpected sealed env format: %q", line)
		}
		// create malformed sealed value (prefix + single part)
		malformed := pqc.Prefix + "onlyonepart"
		reqBodyMap := map[string]string{"FOO": malformed}
		reqBody, _ := json.Marshal(reqBodyMap)

		rec := runPost(t, reqBody, nil, priv)
		ExpectStatus(t, rec, http.StatusBadGateway)
		expectBodyContains(t, rec, "sealed value for FOO malformed")
	})
}

func TestHandlePost_DirectUnsealPath_SimulatedBranches(t *testing.T) {
	orig := unsealMapFunc
	defer func() { unsealMapFunc = orig }()

	t.Run("unseal returned unexpected keys -> 502", func(t *testing.T) {
		// Simulate UnsealMap returning an extra key not requested
		unsealMapFunc = func(envMap map[string]string, privPath string, keys []string) (map[string]string, error) {
			// return a map with an unexpected key "BAD"
			return map[string]string{"GOOD": "v", "BAD": "x"}, nil
		}

		body := []byte(`{"GOOD":"v"}`)
		rec := runPost(t, body, nil, "/tmp/key")
		ExpectStatus(t, rec, http.StatusBadGateway)
		expectBodyContains(t, rec, "unseal returned unexpected keys")
	})

	t.Run("unseal produced no acceptable env entries -> 502", func(t *testing.T) {
		// Simulate UnsealMap returning an empty map (no sealed entries)
		unsealMapFunc = func(envMap map[string]string, privPath string, keys []string) (map[string]string, error) {
			return map[string]string{}, nil
		}

		body := []byte(`{"FOO":"plainvalue"}`)
		rec := runPost(t, body, nil, "/tmp/key")
		ExpectStatus(t, rec, http.StatusBadGateway)
		expectBodyContains(t, rec, "unseal produced no acceptable env entries")
	})

	t.Run("unseal missing keys -> 502", func(t *testing.T) {
		// Simulate UnsealMap returning ErrMissingKeys
		unsealMapFunc = func(envMap map[string]string, privPath string, keys []string) (map[string]string, error) {
			return nil, fmt.Errorf("%w: missing", pqc.ErrMissingKeys)
		}

		body := []byte(`{"FOO":"v"}`)
		rec := runPost(t, body, nil, "/tmp/key")
		ExpectStatus(t, rec, http.StatusBadGateway)
		expectBodyContains(t, rec, "missing")
	})

	t.Run("unseal unknown worker error -> 502", func(t *testing.T) {
		// Simulate UnsealMap returning ErrUnseal
		unsealMapFunc = func(envMap map[string]string, privPath string, keys []string) (map[string]string, error) {
			return nil, fmt.Errorf("%w: decapsulation failed", pqc.ErrUnseal)
		}

		body := []byte(`{"FOO":"v"}`)
		rec := runPost(t, body, nil, "/tmp/key")
		ExpectStatus(t, rec, http.StatusBadGateway)
		expectBodyContains(t, rec, "decapsulation failed")
	})
}
