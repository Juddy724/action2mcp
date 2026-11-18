package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/store"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The literal filename is a compatibility contract, not a value imported from
// the constructor under test. Seed BEFORE NewApp, like an in-place upgrade.
func TestExistingDataFilenameAndCatalogVisibility(t *testing.T) {
	for _, tc := range []struct {
		name           string
		seeded, shadow bool
	}{
		{name: "empty"}, {name: "populated", seeded: true}, {name: "populated_with_shadow", seeded: true, shadow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seeded := tc.seeded
			dir := t.TempDir()
			path := filepath.Join(dir, "a2m.db")
			legacy, err := store.OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if seeded {
				tool := &execution.Tool{Name: "legacy_lookup", Method: "GET", URL: "http://127.0.0.1:9/synthetic", Approval: "off"}
				if err := legacy.SaveTool(tool); err != nil {
					t.Fatal(err)
				}
				mw := &mwconfig.Middleware{Name: "legacy_cache", Type: "redis", Config: mwconfig.MWConfig{Host: "127.0.0.1", Port: 9, Perms: map[string]bool{"read": true}}}
				if err := legacy.SaveMiddleware(mw); err != nil {
					t.Fatal(err)
				}
				if err := legacy.SavePack(&store.Pack{Name: "legacy_pack", Enabled: true, ToolIDs: []int64{tool.ID}, MiddlewareIDs: []int64{mw.ID}}); err != nil {
					t.Fatal(err)
				}
				if err := legacy.SetSettings(map[string]string{"rec_analysis": "off", "approval_timeout_secs": "123"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := legacy.DB().Close(); err != nil {
				t.Fatal(err)
			}
			shadowPath := filepath.Join(dir, "a2m.DB()")
			shadow := []byte("synthetic shadow; must not be opened, merged or deleted")
			if tc.shadow {
				if err := os.WriteFile(shadowPath, shadow, 0600); err != nil {
					t.Fatal(err)
				}
			}
			app, err := NewApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer app.Shutdown()
			// database_list observes the handle actually used, not raw rows in another file.
			var seq int
			var dbName, actual string
			if err := app.store.DB().QueryRow("PRAGMA database_list").Scan(&seq, &dbName, &actual); err != nil {
				t.Fatal(err)
			}
			wantPath := path
			if r, err := filepath.EvalSymlinks(path); err == nil {
				wantPath = r
			}
			gotPath := actual
			if r, err := filepath.EvalSymlinks(actual); err == nil {
				gotPath = r
			}
			if gotPath != wantPath {
				t.Fatalf("opened %q, want existing database %q", actual, path)
			}
			if tc.shadow {
				got, err := os.ReadFile(shadowPath)
				if err != nil || string(got) != string(shadow) {
					t.Fatalf("existing shadow changed: %v", err)
				}
			} else if _, err := os.Stat(shadowPath); !os.IsNotExist(err) {
				t.Fatalf("unexpected shadow database: %v", err)
			}
			want := 0
			if seeded {
				want = 1
			}
			tools, err := app.store.ListTools()
			if err != nil || len(tools) != want {
				t.Fatalf("tools=%d err=%v", len(tools), err)
			}
			packs, err := app.store.ListPacks()
			if err != nil || len(packs) != want {
				t.Fatalf("packs=%d err=%v", len(packs), err)
			}
			mws, err := app.store.ListMiddleware()
			if err != nil || len(mws) != want {
				t.Fatalf("middleware=%d err=%v", len(mws), err)
			}
			for _, route := range []string{"/api/tools", "/api/packs", "/api/middleware"} {
				req := httptest.NewRequest("GET", route, nil)
				req.Host = "127.0.0.1"
				w := httptest.NewRecorder()
				app.Handler().ServeHTTP(w, req)
				var rows []json.RawMessage
				body := w.Body.Bytes()
				if route == "/api/middleware" {
					var envelope struct {
						Items json.RawMessage `json:"items"`
					}
					if err := json.Unmarshal(body, &envelope); err != nil {
						t.Fatal(err)
					}
					body = envelope.Items
				}
				if w.Code != 200 || json.Unmarshal(body, &rows) != nil || len(rows) != want {
					t.Fatalf("%s status=%d body=%s", route, w.Code, w.Body.String())
				}
			}
			c := &recTestClient{t: t, handler: app.Handler()}
			c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "synthetic-upgrade"}})
			if len(c.toolNames()) != 4 {
				t.Fatal("tiered entry tools missing")
			}
			text, bad := c.tool("list_packs", map[string]any{})
			if bad {
				t.Fatal(text)
			}
			if strings.Contains(text, "legacy_pack") != seeded {
				t.Fatalf("MCP list_packs does not match existing data: %s", text)
			}
			if seeded {
				if app.store.GetSetting("approval_timeout_secs", "") != "123" {
					t.Fatal("legacy settings not loaded")
				}
				text, bad = c.tool("load_pack", map[string]any{"pack": "legacy_pack"})
				if bad {
					t.Fatal(text)
				}
				names := c.toolNames()
				found := map[string]bool{}
				for _, n := range names {
					found[n] = true
				}
				if !found["legacy_lookup"] || !found["redis_scan"] {
					t.Fatalf("legacy tools/middleware not visible via MCP: %v", names)
				}
				st := app.Status()
				if st.TotalTools != 1 || st.EnabledPacks != 1 || st.ExposedMW != 1 {
					t.Fatalf("runtime status=%+v", st)
				}
			}
		})
	}
}
