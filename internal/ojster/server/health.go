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
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var startTime = time.Now()

func healthHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime).Seconds()
	resp := map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
		"uptime": fmt.Sprintf("%.0f", uptime),
	}

	j, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(j)
}
