package middleware

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func cachedSQLTarget(t *testing.T, c Config) (*Drivers, *Target, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE TABLE orders(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO orders(body) VALUES('one'),('two'),('three');"); err != nil {
		t.Fatal(err)
	}
	d := &Drivers{}
	m := &Target{ID: 1, Name: "local-sql", Type: "mysql", Config: c, Password: func() (string, error) { return "", nil }}
	d.put(m.ID, m.cacheKey(""), db)
	return d, m, db
}

func TestSQLExecutionRetainsReadOnlyRowsAndParameters(t *testing.T) {
	d, m, _ := cachedSQLTarget(t, Config{MaxRows: 2})
	rows, err := d.runSQL(context.Background(), m, &sqlPlan{SQL: "SELECT body FROM orders WHERE id>? ORDER BY id", Query: true, ReadOnly: true}, []any{0})
	if err != nil || rows.RowCount != 2 || !rows.Truncated || rows.Rows[0][0] != "one" || rows.Rows[1][0] != "two" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	// SQL execution through the public port must still observe the checked action.
	observer := &observation{allow: true}
	reply, isError := d.Execute(context.Background(), m, "db_query", map[string]any{"sql": "SELECT body FROM orders WHERE id=?", "params": []any{2}}, observer)
	if reply != "observed-and-scrubbed" || isError || observer.err != nil || !strings.Contains(observer.result, `"two"`) || !strings.Contains(observer.action, "SELECT") {
		t.Fatalf("reply=%q error=%t observation=%+v", reply, isError, observer)
	}
}

func TestSQLExecutionRetainsResultBudgetAndWriteMetadata(t *testing.T) {
	d, m, db := cachedSQLTarget(t, Config{MaxResultKB: 1})
	if _, err := db.Exec("UPDATE orders SET body=? WHERE id=1", strings.Repeat("界", 1000)); err != nil {
		t.Fatal(err)
	}
	rows, err := d.runSQL(context.Background(), m, &sqlPlan{SQL: "SELECT body FROM orders ORDER BY id", Query: true}, nil)
	if err != nil || !rows.Truncated || rows.RowCount != 0 || !strings.Contains(rows.Note, "1 KB") {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	write, err := d.runSQL(context.Background(), m, &sqlPlan{SQL: "INSERT INTO orders(body) VALUES(?)"}, []any{"four"})
	if err != nil || write.AffectedRows == nil || *write.AffectedRows != 1 || write.LastInsertID == nil || *write.LastInsertID != 4 {
		t.Fatalf("write=%+v err=%v", write, err)
	}
}

func TestMySQLConnectorEnablesInterpolateParams(t *testing.T) {
	m := &Target{ID: 1, Name: "ob-test", Type: "mysql", Config: Config{Host: "127.0.0.1", Port: 2883, User: "u", Database: "d"}}
	cfg, err := m.mysqlConnector("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InterpolateParams {
		t.Fatal("expected InterpolateParams=true for OceanBase compatibility")
	}
	if cfg.MultiStatements {
		t.Fatal("MultiStatements must remain false")
	}
}
