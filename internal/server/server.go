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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

const linuxTmpfsMagic = 0x01021994

func checkTempIsTmpfs(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return fmt.Errorf("failed to statfs %s: %v", path, err)
	}
	if uint64(stat.Type) != linuxTmpfsMagic {
		return fmt.Errorf("path %s is not on tmpfs (statfs type 0x%x)", path, uint64(stat.Type))
	}
	return nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		fmt.Fprintf(os.Stderr, "%s %s %s\n", r.Method, r.URL.Path, time.Since(start))
	})
}

// Serve starts the HTTP server and blocks until the server stops or ctx is cancelled.
// It writes informational and error messages to the provided writers and returns an
// integer exit code suitable for passing to os.Exit by the caller.
func Serve(privateKeyFile string, socketPath string, ctx context.Context, cmdArgs []string, outw io.Writer, errw io.Writer) int {

	// Ensure /tmp is tmpfs (security expectation for ephemeral files)
	if err := checkTempIsTmpfs(os.TempDir()); err != nil {
		fmt.Fprintln(errw, err)
		return 1
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		handlePost(w, r, cmdArgs, privateKeyFile)
	})

	// Ensure previous socket removed
	_ = os.RemoveAll(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to listen on unix socket %s: %v", socketPath, err))
		return 1
	}

	// Ensure socket is writable by client processes
	if err := os.Chmod(socketPath, 0o666); err != nil {
		fmt.Fprintln(errw, fmt.Errorf("failed to chmod socket %s: %v", socketPath, err))
		ln.Close()
		return 1
	}

	server := &http.Server{Handler: loggingMiddleware(mux)}

	fmt.Fprintf(errw, "ojster serving on unix socket %s\n", socketPath)

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	// Serve blocks until the server is closed.
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(errw, fmt.Errorf("server error: %v", err))
		ln.Close()
		return 1
	}

	return 0
}
