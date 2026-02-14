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

// ReadSecretFromStdin reads a secret from stdin.
// - If stdin is a TTY: disable echo using termios, read until EOF, restore echo.
// - If stdin is not a TTY: read all bytes normally.
func ReadSecretFromStdin(prompt string) ([]byte, error) {
	f := os.Stdin

	// Check if stdin is a TTY
	fi, err := f.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return io.ReadAll(f)
	}

	// Try to open /dev/tty (best UX)
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
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
func readWithTermios(f *os.File, outw *os.File) ([]byte, error) {
	fd := int(f.Fd())

	// Load current termios
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&old)),
		0, 0, 0,
	); errno != 0 {
		// Cannot disable echo → fallback
		return io.ReadAll(f)
	}

	// Modify termios: disable ECHO
	new := old
	new.Lflag &^= syscall.ECHO

	// Apply new settings
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(syscall.TCSETS),
		uintptr(unsafe.Pointer(&new)),
		0, 0, 0,
	); errno != 0 {
		return io.ReadAll(f)
	}

	// Ensure echo is restored
	defer func() {
		syscall.Syscall6(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(syscall.TCSETS),
			uintptr(unsafe.Pointer(&old)),
			0, 0, 0,
		)
		fmt.Fprintln(outw)
	}()

	// Read until EOF (Ctrl‑D)
	var buf bytes.Buffer
	_, err := io.Copy(&buf, f)
	return buf.Bytes(), err
}
