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
	"net/http"
	"testing"

	"github.com/ojster/ojster/internal/testutil"
)

//
// ─────────────────────────────────────────────────────────────
//   handlePost
// ─────────────────────────────────────────────────────────────
//

var sh = testutil.Sh

func TestHandlePost_Success(t *testing.T) {
	body := []byte(`{"FOO":"bar"}`)
	cmd := sh(`printf '{"FOO":"ok"}'`)
	rec := runPost(t, body, cmd, "/tmp/key")
	testutil.ExpectStatus(t, rec, http.StatusOK)

	out := testutil.DecodeJSON[map[string]string](t, rec.Body.Bytes())
	if out["FOO"] != "ok" {
		t.Fatalf("expected FOO=ok, got %#v", out)
	}
}

func TestHandlePost_Errors(t *testing.T) {

	cases := []struct {
		name     string
		body     string
		cmd      []string
		wantCode int
		wantSub  string
	}{
		{"invalid_json", "{bad json", sh(`printf '{}'`), 400, "invalid JSON"},
		{"invalid_key", `{"BAD-NAME":"v"}`, sh(`printf '{}'`), 400, "invalid key"},
		{"unexpected_keys", `{"GOOD":"v"}`, sh(`printf '{"GOOD":"1","BAD":"x"}'`), 502, "unexpected keys"},
		{"subprocess_invalid_json", `{"GOOD":"v"}`, sh(`printf '{bad json'`), 502, "invalid JSON"},
		{"exit_error", `{"FOO":"bar"}`, sh(`exit 3`), 502, "exit 3"},
		{"generic_error", `{"FOO":"bar"}`, []string{"does-not-exist"}, 500, "failed to run"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := runPost(t, []byte(tc.body), tc.cmd, "/x")
			testutil.ExpectStatus(t, rec, tc.wantCode)
			testutil.ExpectBodyContains(t, rec, tc.wantSub)
		})
	}
}
