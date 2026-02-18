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

package file

import (
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to path atomically.
// It writes to a temporary file in the same directory, fsyncs it,
// then renames it over the target. Permissions are applied to the final file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)

	// Create temporary file in same directory
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// Ensure cleanup on failure
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// Write data
	if _, err := tmp.Write(data); err != nil {
		return err
	}

	// Sync to disk
	if err := tmp.Sync(); err != nil {
		return err
	}

	// Close before rename
	if err := tmp.Close(); err != nil {
		return err
	}

	// Rename atomically
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	// Apply permissions
	return os.Chmod(path, perm)
}
