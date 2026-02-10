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

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ojster/ojster/internal/testutil"
)

//
// ─────────────────────────────────────────────────────────────
//   TEST HELPERS
// ─────────────────────────────────────────────────────────────
//

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
		req, _ := http.NewRequest("GET", "http://unix/health", nil)
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

	code := testutil.StubExit(t, &exitFunc)

	t.Setenv("TMPDIR", "/definitely-not-existing")

	out := testutil.CaptureStderr(t, func() {
		defer testutil.ExpectExitPanic(t, code, 1)
		Serve(context.Background(), nil)
	})

	if !strings.Contains(out, "failed to statfs") {
		t.Fatalf("expected statfs failure, got: %s", out)
	}
}

//
// ─────────────────────────────────────────────────────────────
//   Serve()
// ─────────────────────────────────────────────────────────────
//

func TestServe_StartupAndHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socketPath := filepath.Join(t.TempDir(), "ojster.sock")
	t.Setenv("OJSTER_SOCKET_PATH", socketPath)

	tmp := t.TempDir()
	t.Setenv("OJSTER_PRIVATE_KEY_FILE", filepath.Join(tmp, ".env"))

	done := make(chan struct{})
	go func() {
		Serve(ctx, nil)
		close(done)
	}()

	waitForServer(t, socketPath)

	client := getUnixHTTPClient(socketPath)

	resp, err := client.Get("http://unix/health")
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

func TestServe_InvalidSocketPath(t *testing.T) {
	code := testutil.StubExit(t, &exitFunc)

	// point to a directory that cannot be created/listened on
	t.Setenv("OJSTER_SOCKET_PATH", "/definitely-not-existing-dir/ojster.sock")
	defer testutil.ExpectExitPanic(t, code, 1)
	Serve(context.Background(), nil)
}

func getUnixHTTPClient(socketPath string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &http.Client{Transport: tr, Timeout: 500 * time.Millisecond}
}
