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

//go:build linux

package tty

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// ioctlFuncType is used so tests can replace the underlying ioctl/syscall behavior.
// The third parameter (ptr) is an unsafe.Pointer so callers can pass a pointer
// directly without converting through uintptr.
type ioctlFuncType func(trap, a1, a2 uintptr, ptr unsafe.Pointer, a4, a5 uintptr) (r1, r2 uintptr, err syscall.Errno)

// ioctlFunc defaults to a thin wrapper around syscall.Syscall6.
// Note: we convert the ptr (unsafe.Pointer) to uintptr when calling Syscall6.
var ioctlFunc ioctlFuncType = func(trap, a1, a2 uintptr, ptr unsafe.Pointer, a4, a5 uintptr) (uintptr, uintptr, syscall.Errno) {
	r1, r2, errno := syscall.Syscall6(trap, a1, a2, uintptr(ptr), a4, a5, 0)
	return r1, r2, errno
}

// isStdinTTY determines whether the provided file should be treated as a TTY.
// Tests may override this to force the /dev/tty branch.
var isStdinTTY = func(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// openDevTTY is used to open /dev/tty. Tests may override this to return a test file.
var openDevTTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// ReadSecretFromStdin reads a secret from stdin.
// - If stdin is a TTY: disable echo using termios, read until EOF, restore echo.
// - If stdin is not a TTY: read all bytes normally.
func ReadSecretFromStdin(prompt string) ([]byte, error) {
	f := os.Stdin

	// Check if stdin is a TTY
	if !isStdinTTY(f) {
		return io.ReadAll(f)
	}

	// Try to open /dev/tty (best UX)
	tty, err := openDevTTY()
	if err != nil {
		// fallback: operate directly on stdin
		fmt.Fprint(os.Stderr, prompt)
		return readWithTermios(f, os.Stderr)
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	return readWithTermios(tty, tty)
}

// readWithTermios disables echo using TCGETS/TCSETS, reads until EOF, restores echo.
func readWithTermios(f *os.File, out *os.File) ([]byte, error) {
	fd := int(f.Fd())

	// Load current termios
	var old syscall.Termios
	if _, _, errno := ioctlFunc(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TCGETS),
		unsafe.Pointer(&old),
		0, 0,
	); errno != 0 {
		// Cannot disable echo → fallback
		return io.ReadAll(f)
	}

	// Modify termios: disable ECHO
	new := old
	new.Lflag &^= syscall.ECHO

	// Apply new settings
	if _, _, errno := ioctlFunc(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TCSETS),
		unsafe.Pointer(&new),
		0, 0,
	); errno != 0 {
		return io.ReadAll(f)
	}

	// Ensure echo is restored
	defer func() {
		ioctlFunc(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(syscall.TCSETS),
			unsafe.Pointer(&old),
			0, 0,
		)
		fmt.Fprintln(out)
	}()

	// Read until EOF (Ctrl‑D)
	var buf bytes.Buffer
	_, err := io.Copy(&buf, f)
	return buf.Bytes(), err
}
