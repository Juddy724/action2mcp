package console

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/execution"
	"action2mcp/internal/mcp"
	"action2mcp/internal/recording"
	"action2mcp/internal/store"
	"action2mcp/web"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]any{"error": err.Error()})
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func readJSON(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("请求格式错误: %v", err)
	}
	return nil
}

// localOnly blocks cross-site requests from web pages (DNS rebinding / CSRF protection).
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, ok := strings.Cut(host, ":"); ok {
			host = h
		}
		if host != "localhost" && host != "127.0.0.1" && host != "[::1]" && host != "::1" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if o := r.Header.Get("Origin"); o != "" && o != "null" {
			u, err := url.Parse(o)
			if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(web.FS)))

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.status()) })

	mux.HandleFunc("POST /api/recordings/start", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Name, URL string }
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		id, err := a.browser().StartRecording(in.Name, in.URL)
		if err != nil {
			writeErr(w, 409, err)
			return
		}
		writeJSON(w, 200, map[string]any{"id": id})
	})
	mux.HandleFunc("POST /api/recordings/stop", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Reason string }
		readJSON(r, &in)
		if in.Reason == "" {
			in.Reason = "console"
		}
		info, err := a.browser().StopRecording(in.Reason)
		if err != nil {
			writeJSON(w, 409, map[string]any{"error": err.Error(), "last": info})
			return
		}
		writeJSON(w, 200, info)
	})
	mux.HandleFunc("GET /api/recordings", func(w http.ResponseWriter, r *http.Request) {
		l, err := a.store.ListRecordings()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, l)
	})
	mux.HandleFunc("GET /api/recordings/{id}", func(w http.ResponseWriter, r *http.Request) {
		rec, err := a.store.GetRecording(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("录制不存在"))
			return
		}
		reqs, err := a.store.ListRequests(rec.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		notes, err := a.store.RequestNotes(rec.ID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		for i := range reqs {
			reqs[i].URL = a.vault.Scrub(analysis.MaskURL(reqs[i].URL))
			if reqs[i].Method != "GET" && reqs[i].Method != "HEAD" {
				if full, err := a.store.GetRequest(reqs[i].ID); err == nil {
					reqs[i].IsLogin = analysis.IsLoginRequest(full)
				}
			}
			recording.ApplyNote(&reqs[i], notes)
		}
		writeJSON(w, 200, map[string]any{"recording": rec, "requests": reqs})
	})
	mux.HandleFunc("DELETE /api/recordings/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.store.DeleteRecording(pathID(r))
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		q, err := a.store.GetRequest(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("请求不存在"))
			return
		}
		cands := a.analysis().AnnotateCandidates(q, execution.SuggestParams(q))
		notes, err := a.store.RequestNotes(q.RecordingID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		q = a.analysis().ScrubRequest(q)
		recording.ApplyNote(q, notes)
		writeJSON(w, 200, map[string]any{"request": q, "candidates": cands})
	})
	mux.HandleFunc("PUT /api/requests/{id}/note", func(w http.ResponseWriter, r *http.Request) {
		q, err := a.store.GetRequest(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("请求不存在"))
			return
		}
		var n recording.Note
		if err := readJSON(r, &n); err != nil {
			writeErr(w, 400, err)
			return
		}
		// Identity and authorship always come from this console operation.
		n.RequestID, n.RecordingID, n.Source = q.ID, q.RecordingID, "user"
		if err := a.store.SetRequestNote(n); err != nil {
			switch {
			case errors.Is(err, sql.ErrNoRows):
				writeErr(w, 404, errors.New("请求不存在"))
			case errors.Is(err, recording.ErrInvalidNote):
				writeErr(w, 400, err)
			default:
				writeErr(w, 500, err)
			}
			return
		}
		notes, err := a.store.RequestNotes(q.RecordingID)
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, notes[q.ID])
	})
	mux.HandleFunc("DELETE /api/requests/{id}/note", func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.store.GetRequest(pathID(r)); err != nil {
			writeErr(w, 404, errors.New("请求不存在"))
			return
		}
		if err := a.store.DeleteRequestNote(pathID(r)); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/requests/{id}/draft", func(w http.ResponseWriter, r *http.Request) {
		q, err := a.store.GetRequest(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("请求不存在"))
			return
		}
		var in struct {
			Params []execution.Candidate `json:"params"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		t, err := a.buildRequestDraft(q, in.Params)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, t)
	})

	// tools
	mux.HandleFunc("GET /api/tools", func(w http.ResponseWriter, r *http.Request) {
		l, err := a.store.ListTools()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, l)
	})
	mux.HandleFunc("GET /api/tools/{id}", func(w http.ResponseWriter, r *http.Request) {
		t, err := a.store.GetTool(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("工具不存在"))
			return
		}
		writeJSON(w, 200, map[string]any{"tool": t, "input_schema": t.InputSchema()})
	})
	saveTool := func(w http.ResponseWriter, r *http.Request, id int64) {
		var in struct {
			execution.Tool
			Approval json.RawMessage `json:"approval"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		t := in.Tool
		if in.Approval != nil {
			if err := json.Unmarshal(in.Approval, &t.Approval); err != nil || t.Approval == "" {
				writeErr(w, 400, errors.New("审批模式只能是 off 或 always"))
				return
			}
		}
		t.ID = id
		if err := a.tools().Persist(&t); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, t)
	}
	mux.HandleFunc("POST /api/tools", func(w http.ResponseWriter, r *http.Request) { saveTool(w, r, 0) })
	mux.HandleFunc("PUT /api/tools/{id}", func(w http.ResponseWriter, r *http.Request) { saveTool(w, r, pathID(r)) })
	mux.HandleFunc("DELETE /api/tools/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.store.DeleteTool(pathID(r))
		a.toolsChanged()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/tools/{id}/convert-to-middleware", func(w http.ResponseWriter, r *http.Request) {
		id := pathID(r)
		m, err := a.store.ConvertToolToSQLMiddleware(id)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		a.toolsChanged()
		writeJSON(w, 200, m)
	})
	mux.HandleFunc("POST /api/tools/{id}/run", func(w http.ResponseWriter, r *http.Request) {
		t, err := a.store.GetTool(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("工具不存在"))
			return
		}
		var in struct {
			Args map[string]any `json:"args"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		res, err := a.engine().Execute(t, in.Args)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, res)
	})

	// packs
	mux.HandleFunc("GET /api/packs", func(w http.ResponseWriter, r *http.Request) {
		l, err := a.store.ListPacks()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, l)
	})
	savePack := func(w http.ResponseWriter, r *http.Request, id int64) {
		var p store.Pack
		if err := readJSON(r, &p); err != nil {
			writeErr(w, 400, err)
			return
		}
		p.ID = id
		p.Name = strings.TrimSpace(p.Name)
		p.Scenarios = strings.TrimSpace(p.Scenarios)
		p.Guide = strings.TrimSpace(p.Guide)
		if err := a.store.SavePack(&p); err != nil {
			writeErr(w, 400, err)
			return
		}
		a.toolsChanged()
		writeJSON(w, 200, p)
	}
	mux.HandleFunc("POST /api/packs", func(w http.ResponseWriter, r *http.Request) { savePack(w, r, 0) })
	mux.HandleFunc("PUT /api/packs/{id}", func(w http.ResponseWriter, r *http.Request) { savePack(w, r, pathID(r)) })
	mux.HandleFunc("POST /api/packs/{id}/toggle", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		readJSON(r, &in)
		if err := a.store.SetPackEnabled(pathID(r), in.Enabled); err != nil {
			writeErr(w, 400, err)
			return
		}
		a.toolsChanged()
		writeJSON(w, 200, a.status())
	})
	// membership: POST /api/packs/{id}/tools {"ids":[..]} adds, DELETE /api/packs/{id}/tools/{mid} removes
	// (same for /middleware). Other members are left untouched.
	for _, kind := range []string{"tools", "middleware"} {
		kind := kind
		mux.HandleFunc("POST /api/packs/{id}/"+kind, func(w http.ResponseWriter, r *http.Request) {
			var in struct {
				IDs []int64 `json:"ids"`
			}
			if err := readJSON(r, &in); err != nil {
				writeErr(w, 400, err)
				return
			}
			n, err := a.store.AddPackMembers(pathID(r), kind, in.IDs)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			if n > 0 {
				a.toolsChanged()
			}
			writeJSON(w, 200, map[string]any{"ok": true, "added": n})
		})
		mux.HandleFunc("DELETE /api/packs/{id}/"+kind+"/{mid}", func(w http.ResponseWriter, r *http.Request) {
			mid, _ := strconv.ParseInt(r.PathValue("mid"), 10, 64)
			ok, err := a.store.RemovePackMember(pathID(r), kind, mid)
			if err != nil {
				writeErr(w, 400, err)
				return
			}
			if ok {
				a.toolsChanged()
			}
			writeJSON(w, 200, map[string]any{"ok": true, "removed": ok})
		})
	}
	mux.HandleFunc("DELETE /api/packs/{id}", func(w http.ResponseWriter, r *http.Request) {
		a.store.DeletePack(pathID(r))
		a.toolsChanged()
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// browser / credentials
	mux.HandleFunc("POST /api/browser/open", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ URL string }
		readJSON(r, &in)
		if in.URL != "" && !strings.Contains(in.URL, "://") {
			in.URL = "https://" + in.URL
		}
		if err := a.browser().OpenBrowser(in.URL); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /api/credentials", func(w http.ResponseWriter, r *http.Request) {
		cs := a.store.AllCookies()
		domains := map[string]int{}
		for _, c := range cs {
			domains[strings.TrimPrefix(c.Domain, ".")]++
		}
		writeJSON(w, 200, map[string]any{"domains": domains, "count": len(cs)})
	})
	mux.HandleFunc("DELETE /api/credentials", func(w http.ResponseWriter, r *http.Request) {
		a.store.ClearCookies()
		_ = a.login().ClearAllSiteHeaders()
		writeJSON(w, 200, map[string]any{"ok": true})
	})

	// export / import
	mux.HandleFunc("GET /api/export", func(w http.ResponseWriter, r *http.Request) {
		b, err := a.transfer().Export()
		if err != nil {
			writeErr(w, 500, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="action2mcp-%s.a2m"`, time.Now().Format("20060102-1504")))
		w.Write(b)
	})
	mux.HandleFunc("POST /api/import", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		res, err := a.transfer().Import(b)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, res)
	})
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); a.shutdown(); a.exit() }()
	})

	a.registerV2(mux)
	a.registerMW(mux)

	// MCP
	mux.HandleFunc("POST /mcp", a.mcpServer().ServeHTTP)
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) { a.sessions.ServeStream(w, r, a.quit) })
	mux.HandleFunc("DELETE /mcp", a.sessions.ServeDelete)

	// settings (MCP exposure mode, built-in 录制分析 pack, approval timeout)
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, a.settingsView())
	})
	mux.HandleFunc("PUT /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			MCPMode             *string         `json:"mcp_mode"`
			RecAnalysis         *bool           `json:"rec_analysis"`
			ApprovalTimeoutSecs json.RawMessage `json:"approval_timeout_secs"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		if in.MCPMode == nil && in.RecAnalysis == nil && in.ApprovalTimeoutSecs == nil {
			writeErr(w, 400, errors.New("没有要更新的设置"))
			return
		}
		updates := map[string]string{}
		if in.MCPMode != nil {
			if *in.MCPMode != mcp.ModeTiered && *in.MCPMode != mcp.ModeFlat {
				writeErr(w, 400, errors.New("mcp_mode 只能是 tiered 或 flat"))
				return
			}
			updates["mcp_mode"] = *in.MCPMode
		}
		if in.RecAnalysis != nil {
			v := "off"
			if *in.RecAnalysis {
				v = "on"
			}
			updates[analysis.SettingEnabled] = v
		}
		if in.ApprovalTimeoutSecs != nil {
			var secs int
			if err := json.Unmarshal(in.ApprovalTimeoutSecs, &secs); err != nil || secs < 30 || secs > 1800 {
				writeErr(w, 400, errors.New("approval_timeout_secs 必须是 30–1800 的整数"))
				return
			}
			updates["approval_timeout_secs"] = strconv.Itoa(secs)
		}
		if err := a.store.SetSettings(updates); err != nil {
			writeErr(w, 500, err)
			return
		}
		a.toolsChanged()
		writeJSON(w, 200, a.settingsView())
	})
	// Approval routes apply their strict JSON guard before the legacy console guard.
	console := http.NewServeMux()
	a.registerApprovals(console)
	console.Handle("/", localOnly(mux))
	return console
}

// buildRequestDraft is the POST /api/requests/{id}/draft path: chosen fields become
// template params, secrets become {{secret.X}}, and the tool is not saved yet.
func (a *Server) buildRequestDraft(q *recording.Request, params []execution.Candidate) (*execution.Tool, error) {
	t, err := execution.BuildDraft(q, a.analysis().PrepareDraft(q, params))
	if err != nil {
		return nil, err
	}
	t.Name = execution.SuggestToolName(q)
	if rec, err := a.store.GetRecording(q.RecordingID); err == nil && rec != nil {
		t.Title = rec.Name
	}
	t.SourceReqID = q.ID
	return t, nil
}

func (a *Server) settingsView() map[string]any {
	return map[string]any{"mcp_mode": a.mcpServer().Mode(), "rec_analysis": a.analysis().Enabled(),
		"approval_timeout_secs": int(a.store.ApprovalTimeout() / time.Second)}
}
