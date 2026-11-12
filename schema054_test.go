package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMigrationV6ToV7PreservesHTTPTools(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v6.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT, approval TEXT NOT NULL DEFAULT 'off', rev INTEGER NOT NULL DEFAULT 1);
INSERT INTO tools(name,title,description,method,url,headers,body,params,cred_headers,source_request_id,created_at,updated_at,approval,rev) VALUES('legacy','旧工具','','POST','https://example.com/api','{}','','[]','[]',0,'','','always',3);
PRAGMA user_version=6;`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if !s.hasColumn("tools", "config") {
			t.Fatal("config column missing")
		}
		old, err := s.GetToolByName("legacy")
		if err != nil || old.Approval != "always" || old.Rev != 3 || old.Method != "POST" {
			t.Fatalf("migration changed old tool: %+v %v", old, err)
		}
		if old.Config.sqlGuardEnabled() {
			t.Fatal("HTTP tool should not have sql guard after migration")
		}
		var version int
		if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != schemaUserVersion {
			t.Fatalf("version=%d err=%v", version, err)
		}
		s.db.Close()
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("db permissions too open: %o", st.Mode().Perm())
		}
	}
}

func TestWSDefaultApprovalAlways(t *testing.T) {
	s := testStore(t)
	tool := &Tool{Name: "ws_query", Method: "WS", URL: "wss://sql.example.com/api/ws/execute"}
	if err := s.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	if tool.Approval != "always" || tool.Rev != 1 {
		t.Fatalf("approval=%s rev=%d", tool.Approval, tool.Rev)
	}
	got, err := s.GetTool(tool.ID)
	if err != nil || got.Approval != "always" {
		t.Fatal(err)
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	return s
}
