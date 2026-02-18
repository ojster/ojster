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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

//
// ─────────────────────────────────────────────────────────────
//   TEST HELPERS
// ─────────────────────────────────────────────────────────────
//

func ExpectStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected %d, got %d (%s)", want, rec.Code, rec.Body.String())
	}
}

func runPost(t *testing.T, body []byte, cmd []string, priv string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handlePost(rec, req, cmd, priv)
	return rec
}

func waitForServer(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)

	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	client := &http.Client{Transport: tr, Timeout: 100 * time.Millisecond}

	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", "http://unix/", nil)
		resp, err := client.Do(req)
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
	// Make os.TempDir() point to a non-existent path for this test by setting TMPDIR.
	t.Setenv("TMPDIR", "/definitely-not-existing")

	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	// Pass empty socketPath and privateKeyFile; Serve will call checkTempIsTmpfs(os.TempDir()) and fail.
	code := Serve("", "", context.Background(), nil, &outBuf, &errBuf)
	if code == 0 {
		t.Fatalf("expected non-zero exit code for tmpfs failure")
	}
	if !strings.Contains(errBuf.String(), "failed to statfs") {
		t.Fatalf("expected statfs failure, got: %q", errBuf.String())
	}
}

//
// ─────────────────────────────────────────────────────────────
//   Serve()
// ─────────────────────────────────────────────────────────────
//

func TestServe_Startup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socketPath := filepath.Join(t.TempDir(), "ojster.sock")

	// create a temporary file to act as the private key file path
	tmp := t.TempDir()
	privateKeyFile := filepath.Join(tmp, ".env")
	// create the file so the server can symlink to it (handlePost may expect it)
	if err := os.WriteFile(privateKeyFile, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to create private key file: %v", err)
	}

	errCh := make(chan int, 1)
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	// Start Serve in a goroutine; pass explicit privateKeyFile and socketPath.
	go func() {
		code := Serve(privateKeyFile, socketPath, ctx, nil, &outBuf, &errBuf)
		errCh <- code
	}()

	// Wait for the server to be ready to accept connections.
	waitForServer(t, socketPath)

	client := getUnixHTTPClient(socketPath)

	resp, err := client.Get("http://unix/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// cancel and wait for Serve to return
	cancel()

	select {
	case code := <-errCh:
		if code != 0 {
			t.Fatalf("Serve returned non-zero exit code after shutdown: %d stderr=%q", code, errBuf.String())
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("server did not shut down")
	}
}

func TestServe_InvalidSocketPath(t *testing.T) {
	// point to a directory that cannot be created/listened on
	invalidSocket := "/definitely-not-existing-dir/ojster.sock"

	// privateKeyFile can be empty for this test
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	code := Serve("", invalidSocket, context.Background(), nil, &outBuf, &errBuf)
	if code == 0 || !strings.Contains(errBuf.String(), "failed to listen") {
		t.Fatalf("expected listen failure, got code=%d stderr=%q", code, errBuf.String())
	}
}

func getUnixHTTPClient(socketPath string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &http.Client{Transport: tr, Timeout: 500 * time.Millisecond}
}

//
// ─────────────────────────────────────────────────────────────
//   loggingMiddleware
// ─────────────────────────────────────────────────────────────
//

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
	ExpectStatus(t, rec, http.StatusTeapot)
}
