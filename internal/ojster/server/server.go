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
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/ojster/ojster/internal/util"
)

const linuxTmpfsMagic = 0x01021994

var exitFunc = os.Exit

func checkTempIsTmpfs(path string) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return util.Errf("failed to statfs %s: %v", path, err)
	}
	if uint64(stat.Type) != linuxTmpfsMagic {
		return util.Errf("path %s is not on tmpfs (statfs type 0x%x)", path, uint64(stat.Type))
	}
	return nil
}

func Serve(ctx context.Context, cmdArgs []string) {
	defaultCmd := []string{"dotenvx", "get", "-o"}
	cmd := defaultCmd
	if len(cmdArgs) > 0 {
		cmd = cmdArgs
	}

	if err := checkTempIsTmpfs(os.TempDir()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitFunc(1)
	}

	socketPath := util.GetSocketPath()

	privateKeyFile := os.Getenv("OJSTER_PRIVATE_KEY_FILE")
	if privateKeyFile == "" {
		privateKeyFile = "/run/secrets/private_key"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		handlePost(w, r, cmd, privateKeyFile)
	})

	_ = os.RemoveAll(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, util.Errf("failed to listen on unix socket %s: %v", socketPath, err))
		exitFunc(1)
	}

	if err := os.Chmod(socketPath, 0o666); err != nil {
		fmt.Fprintln(os.Stderr, util.Errf("failed to chmod socket %s: %v", socketPath, err))
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
		fmt.Fprintln(os.Stderr, util.Errf("server error: %v", err))
		exitFunc(1)
	}
}
