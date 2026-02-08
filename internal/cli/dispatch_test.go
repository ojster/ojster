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

package cli

import (
	"slices"
	"strings"
	"testing"
)

func TestDispatch_BasicModes(t *testing.T) {
	tests := []struct {
		prog string
		args []string
		mode string
		want []string
	}{
		{"ojster", []string{}, "help", nil},
		{"ojster", []string{"help"}, "help", nil},
		{"ojster", []string{"version"}, "version", nil},
		{"ojster", []string{"run", "echo", "hi"}, "run", []string{"echo", "hi"}},
		{"ojster", []string{"serve", "--", "cmd"}, "serve", []string{"cmd"}},
		{"ojster", []string{"wat"}, "help", nil},
		{"docker-init", []string{"--", "echo", "hello"}, "run", []string{"echo", "hello"}},
	}

	for _, tc := range tests {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			mode, args := Dispatch(tc.prog, tc.args)
			if mode != tc.mode {
				t.Fatalf("mode mismatch: want=%s got=%s", tc.mode, mode)
			}
			if !slices.Equal(args, tc.want) {
				t.Fatalf("args mismatch: want=%v got=%v", tc.want, args)
			}
		})
	}
}
