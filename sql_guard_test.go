package main

import (
	"strings"
	"testing"
)

func TestSQLGuardAcceptsSafeSelect(t *testing.T) {
	for _, sql := range []string{
		"SELECT id FROM t WHERE id=1 LIMIT 1",
		"SELECT SUM(id) FROM t WHERE id=1 LIMIT 1",
		"SELECT COUNT(*) FROM t LIMIT 10",
		"SELECT * FROM t WHERE id IN (SELECT id FROM t2 LIMIT 5) LIMIT 10",
		"WITH cte AS (SELECT id FROM t WHERE id>0) SELECT * FROM cte LIMIT 10",
		"SELECT a FROM t UNION SELECT b FROM u LIMIT 10",
		"SELECT IFNULL(name,'') FROM t LIMIT 200",
		"SELECT DATE_FORMAT(NOW(), '%Y-%m-%d') FROM t LIMIT 1",
	} {
		if err := checkGuardedSQL(sql, 200); err != nil {
			t.Errorf("%s: %v", sql, err)
		}
	}
}

func TestSQLGuardRejects(t *testing.T) {
	cases := []struct {
		sql string
		sub string
	}{
		{"SELECT id FROM t", "LIMIT"},
		{"SELECT id FROM t LIMIT 201", "1–200"},
		{"SELECT id FROM t LIMIT 10, 201", "1–200"},
		{"SELECT id FROM t WHERE id IN (SELECT id FROM u LIMIT 1)", "LIMIT"},
		{"SELECT id FROM t WHERE id>0 -- comment\n", "LIMIT"},
		{"SELECT 'x' LIMIT 1; DROP TABLE t", "一条"},
		{"INSERT INTO t VALUES (1)", "只读"},
		{"DELETE FROM t LIMIT 1", "只读"},
		{"SELECT id FROM t LIMIT 1 FOR UPDATE", "锁"},
		{"SELECT id FROM t LIMIT 1 INTO OUTFILE '/tmp/x'", "INTO"},
		{"SELECT SLEEP(1) FROM t LIMIT 1", "SLEEP"},
		{"SELECT BENCHMARK(100, MD5(1)) FROM t LIMIT 1", "函数"},
		{"SELECT LOAD_FILE('/etc/passwd') LIMIT 1", "LOAD_FILE"},
		{"SELECT @a:=1 FROM t LIMIT 1", "变量"},
		{"SELECT app.f_write(id) FROM t LIMIT 1", "限定"},
		{"SELECT `sum`(id) FROM t WHERE id=1 LIMIT 1", "聚合"},
		{"SELECT * FROM t AS `<derived2>` LIMIT 1", "别名"},
		{"SELECT id FROM t WHERE id>0 /*!99999 LIMIT 1 */", "条件注释"},
		{"SELECT id FROM t WHERE id>0 /*!50000 LIMIT 1 */", "条件注释"},
		{"SELECT 'x\\' AS v FROM t WHERE id > 0 -- ' AS v FROM t WHERE id = 1 LIMIT 1", "不一致"},
		{"SELECT 1 FROM t LIMIT 1+199", "解析"},
		{"EXPLAIN SELECT id FROM t LIMIT 1", "只读"},
	}
	for _, tc := range cases {
		err := checkGuardedSQL(tc.sql, 200)
		if err == nil {
			t.Errorf("accepted: %s", tc.sql)
			continue
		}
		if tc.sub != "" && !strings.Contains(err.Error(), tc.sub) {
			t.Errorf("%s: got %q, want substring %q", tc.sql, err.Error(), tc.sub)
		}
	}
}

func TestSQLGuardMaxRowsHonored(t *testing.T) {
	if err := checkGuardedSQL("SELECT id FROM t LIMIT 200", 10); err == nil {
		t.Fatal("LIMIT 200 should fail when max_rows=10")
	}
	if err := checkGuardedSQL("SELECT id FROM t LIMIT 10", 10); err != nil {
		t.Fatal(err)
	}
}

func TestSQLGuardAllowsLiteralInStringConditional(t *testing.T) {
	sql := "SELECT '/*!' AS v FROM t LIMIT 1"
	if err := checkGuardedSQL(sql, 200); err != nil {
		t.Fatal(err)
	}
}
