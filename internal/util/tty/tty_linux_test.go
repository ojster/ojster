//go:build linux

package tty

import (
	"bytes"
	"io"
	"os"
	"syscall"
	"testing"
	"unsafe"
)

// --- helpers ---------------------------------------------------------------

func makePipeWithPayload(t *testing.T, payload []byte) (r *os.File, cleanup func()) {
	t.Helper()
	rf, wf, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	if len(payload) > 0 {
		if _, err := wf.Write(payload); err != nil {
			_ = wf.Close()
			_ = rf.Close()
			t.Fatalf("failed to write payload: %v", err)
		}
	}
	_ = wf.Close()
	return rf, func() { _ = rf.Close() }
}

func makeTempOut(t *testing.T) (f *os.File, cleanup func()) {
	t.Helper()
	tmp, err := os.CreateTemp("", "tty-test-out")
	if err != nil {
		t.Fatalf("failed to create temp out file: %v", err)
	}
	return tmp, func() {
		tmp.Close()
		_ = os.Remove(tmp.Name())
	}
}

func captureAndAssertNewline(t *testing.T, out *os.File) {
	t.Helper()
	_, _ = out.Seek(0, io.SeekStart)
	outBytes, _ := io.ReadAll(out)
	if len(outBytes) == 0 {
		t.Fatalf("expected deferred newline in out, got empty")
	}
	if !bytes.Contains(outBytes, []byte("\n")) {
		t.Fatalf("expected deferred newline in out, got: %q", outBytes)
	}
}

// withFakeIoctl installs a fake ioctlFunc that returns success for TCGETS/TCSETS
// and writes a Termios with ECHO set into the provided pointer. It restores the
// original ioctlFunc when the provided callback returns.
func withFakeIoctl(t *testing.T, cb func()) {
	t.Helper()
	orig := ioctlFunc
	defer func() { ioctlFunc = orig }()

	ioctlFunc = func(trap, a1, a2 uintptr, ptr unsafe.Pointer, a4, a5 uintptr) (uintptr, uintptr, syscall.Errno) {
		request := a2
		if request == uintptr(syscall.TCGETS) {
			tp := (*syscall.Termios)(ptr)
			*tp = syscall.Termios{}
			tp.Lflag = syscall.ECHO | syscall.ICANON
			return 0, 0, 0
		}
		if request == uintptr(syscall.TCSETS) {
			return 0, 0, 0
		}
		return 0, 0, 0
	}

	cb()
}

// --- tests -----------------------------------------------------------------

func TestReadSecretFromStdin_NonTTY(t *testing.T) {
	r, cleanup := makePipeWithPayload(t, []byte("super-secret\nline2\n"))
	defer cleanup()

	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()
	os.Stdin = r

	out, err := ReadSecretFromStdin("prompt: ")
	if err != nil {
		t.Fatalf("ReadSecretFromStdin returned error: %v", err)
	}
	if !bytes.Equal(out, []byte("super-secret\nline2\n")) {
		t.Fatalf("unexpected secret read: want=%q got=%q", "super-secret\nline2\n", out)
	}
}

func TestReadWithTermios_Fallback(t *testing.T) {
	r, cleanup := makePipeWithPayload(t, []byte("fallback-secret"))
	defer cleanup()

	tmpOut, outCleanup := makeTempOut(t)
	defer outCleanup()

	got, err := readWithTermios(r, tmpOut)
	if err != nil {
		t.Fatalf("readWithTermios returned error: %v", err)
	}
	if !bytes.Equal(got, []byte("fallback-secret")) {
		t.Fatalf("unexpected payload: want=%q got=%q", "fallback-secret", got)
	}

	// On non-tty fallback, no newline is expected; accept empty or newline.
	_, _ = tmpOut.Seek(0, io.SeekStart)
	outBytes, _ := io.ReadAll(tmpOut)
	if len(outBytes) == 0 {
		t.Logf("no deferred newline written (expected on non-tty fallback)")
		return
	}
	if !bytes.Contains(outBytes, []byte("\n")) {
		t.Fatalf("expected deferred newline in out, got: %q", outBytes)
	}
}

func TestReadWithTermios_Success(t *testing.T) {
	r, cleanup := makePipeWithPayload(t, []byte("tty-simulated-secret"))
	defer cleanup()

	tmpOut, outCleanup := makeTempOut(t)
	defer outCleanup()

	withFakeIoctl(t, func() {
		got, err := readWithTermios(r, tmpOut)
		if err != nil {
			t.Fatalf("readWithTermios returned error: %v", err)
		}
		if !bytes.Equal(got, []byte("tty-simulated-secret")) {
			t.Fatalf("unexpected payload: want=%q got=%q", "tty-simulated-secret", got)
		}
	})

	captureAndAssertNewline(t, tmpOut)
}

func TestReadSecretFromStdin_DevTTYPath(t *testing.T) {
	// prepare pipe that will act as /dev/tty
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	// write payload and close writer to signal EOF to reader
	payload := []byte("devtty-secret")
	if _, err := w.Write(payload); err != nil {
		_ = w.Close()
		_ = r.Close()
		t.Fatalf("failed to write payload: %v", err)
	}
	_ = w.Close()

	// save originals
	origIsTTY := isStdinTTY
	origOpen := openDevTTY
	origIoctl := ioctlFunc
	defer func() {
		isStdinTTY = origIsTTY
		openDevTTY = origOpen
		ioctlFunc = origIoctl
	}()

	// force branch and return our pipe as /dev/tty
	isStdinTTY = func(f *os.File) bool { return true }
	openDevTTY = func() (*os.File, error) { return r, nil }

	// ensure ioctl succeeds
	ioctlFunc = func(trap, a1, a2 uintptr, ptr unsafe.Pointer, a4, a5 uintptr) (uintptr, uintptr, syscall.Errno) {
		request := a2
		if request == uintptr(syscall.TCGETS) {
			tp := (*syscall.Termios)(ptr)
			*tp = syscall.Termios{}
			tp.Lflag = syscall.ECHO | syscall.ICANON
			return 0, 0, 0
		}
		if request == uintptr(syscall.TCSETS) {
			return 0, 0, 0
		}
		return 0, 0, 0
	}

	// Call ReadSecretFromStdin which will use our openDevTTY (r).
	got, err := ReadSecretFromStdin("prompt: ")
	if err != nil {
		t.Fatalf("ReadSecretFromStdin returned error: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected payload: want=%q got=%q", payload, got)
	}

	// verify deferred newline via direct readWithTermios call into a temp out
	r2, cleanup2 := makePipeWithPayload(t, payload)
	defer cleanup2()
	tmpOut, outCleanup := makeTempOut(t)
	defer outCleanup()

	withFakeIoctl(t, func() {
		got2, err := readWithTermios(r2, tmpOut)
		if err != nil {
			t.Fatalf("readWithTermios returned error: %v", err)
		}
		if !bytes.Equal(got2, payload) {
			t.Fatalf("unexpected payload from readWithTermios: want=%q got=%q", payload, got2)
		}
	})

	captureAndAssertNewline(t, tmpOut)
}
