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

package file

import (
	"os"
	"path/filepath"
	"testing"
)

// helper: create a temp dir and return a path inside it
func tmpPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// helper: read file content and mode
func readFileAndMode(t *testing.T, path string) (string, os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return string(b), st.Mode().Perm()
}

func TestWriteFileAtomic_SuccessAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	data := []byte("hello-atomic")
	perm := os.FileMode(0o640)

	if err := WriteFileAtomic(path, data, perm); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	got, mode := readFileAndMode(t, path)
	if got != string(data) {
		t.Fatalf("content mismatch: want=%q got=%q", string(data), got)
	}
	if mode != perm {
		t.Fatalf("mode mismatch: want=%o got=%o", perm, mode)
	}
}

func TestWriteFileAtomic_CreateTempFailsWhenDirIsFile(t *testing.T) {
	// Create a file where we will pretend a directory should be.
	td := t.TempDir()
	notDir := filepath.Join(td, "notdir")
	if err := os.WriteFile(notDir, []byte("i am a file"), 0o644); err != nil {
		t.Fatalf("setup write file: %v", err)
	}

	// Use a path whose directory component is the file we just created.
	path := filepath.Join(notDir, "out.txt")

	err := WriteFileAtomic(path, []byte("x"), 0o600)
	if err == nil {
		// On some platforms the OS may allow CreateTemp with a file path in surprising ways;
		// guard against false negatives by cleaning up and failing.
		_ = os.Remove(path)
		t.Fatalf("expected error when directory is a file, got nil")
	}
}

func TestWriteFileAtomic_OverwriteExistingFile(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "exists.txt")

	// create initial file
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	// overwrite via WriteFileAtomic
	if err := WriteFileAtomic(path, []byte("newcontent"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic overwrite failed: %v", err)
	}

	got, mode := readFileAndMode(t, path)
	if got != "newcontent" {
		t.Fatalf("overwrite content mismatch: want=%q got=%q", "newcontent", got)
	}
	if mode != 0o600 {
		t.Fatalf("overwrite mode mismatch: want=%o got=%o", 0o600, mode)
	}
}

func TestPermissionBehavior(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "perm.txt")
	if err := WriteFileAtomic(path, []byte("p"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}
	_, mode := readFileAndMode(t, path)
	if mode != 0o600 {
		t.Fatalf("expected 0600 on non-windows, got %o", mode)
	}
}
