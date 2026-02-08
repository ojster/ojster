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

package testutil

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

//
// ─────────────────────────────────────────────────────────────
//   TEST HELPERS
// ─────────────────────────────────────────────────────────────
//

func ExpectExitPanic(t *testing.T, code *int, want int) {
	t.Helper()
	if r := recover(); r != "exit" {
		t.Fatalf("expected exit panic, got %v", r)
	}
	if *code != want {
		t.Fatalf("expected exit code %d, got %d", want, *code)
	}
}

func StubExit(t *testing.T, target *func(int)) *int {
	t.Helper()
	var code int
	old := *target
	*target = func(c int) {
		code = c
		panic("exit")
	}
	t.Cleanup(func() { *target = old })
	return &code
}

func CaptureStderr(t *testing.T, f func()) string {
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

func ExpectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected %d, got %d (%s)", want, rec.Code, rec.Body.String())
	}
}

func ExpectBodyContains(t *testing.T, rec *httptest.ResponseRecorder, substr string) {
	t.Helper()
	if !strings.Contains(rec.Body.String(), substr) {
		t.Fatalf("expected body to contain %q, got %q", substr, rec.Body.String())
	}
}

func DecodeJSON[T any](t *testing.T, data []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return v
}

func EnvSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		out[k] = v
	}
	return out
}

func Sh(script string) []string { return []string{"sh", "-c", script} }
