package app

import (
	"strings"
	"testing"
)

func sqlCfg() *MWConfig {
	c := &MWConfig{Database: "shop", Perms: map[string]bool{"select": true}}
	return c
}

func TestClassifySQL(t *testing.T) {
	c := sqlCfg()
	cases := []struct {
		sql   string
		perms string // joined perms, or "ERR:substr"
	}{
		{"select * from orders", "select"},
		{"SeLeCt id FrOm orders where id=1", "select"},
		{"show tables", "select"},
		{"describe orders", "select"},
		{"explain select * from orders", "select"},
		{"insert into orders(id) values(1)", "insert"},
		{"replace into orders(id) values(1)", "insert,update"},
		{"insert into orders(id) values(1) on duplicate key update id=2", "insert,update"},
		{"insert into orders select * from orders2", "insert,select"},
		{"update orders set a=1 where id=1", "update"},
		{"delete from orders where id=1", "delete"},
		{"select * from orders for update", "select,update"},
		{"create table t(id int)", "ddl"},
		{"drop table orders", "ddl"},
		{"alter table orders add column x int", "ddl"},
		// bypass attempts
		{"select 1; drop table orders", "ERR:一条"},
		{"select 1;drop table orders;", "ERR:一条"},
		{"select 1 /*; drop table x */", "select"},
		{"/*!50000 drop table orders */", "ddl"},
		{"select * from orders -- ; delete from orders", "select"},
		{"select * from orders # ; delete from orders", "select"},
		{"with x as (select 1) delete from orders", "ERR:"},
		{"with x as (select * from orders) select * from x", "select"},
		{"select * from orders union select * from orders into outfile '/tmp/x'", "ERR:"},
		{"select * from orders into outfile '/tmp/x'", "ERR:INTO"},
		{"select load_file('/etc/passwd')", "ERR:LOAD_FILE"},
		{"select sleep(100)", "ERR:SLEEP"},
		{"select benchmark(100000000, md5(1))", "ERR:BENCHMARK"},
		{"load data infile '/etc/passwd' into table orders", "ERR:"},
		{"grant all on *.* to x", "ERR:"},
		{"set global max_connections=1", "ERR:"},
		{"set @@global.read_only=1", "ERR:"},
		{"call proc()", "ERR:"},
		{"lock tables orders write", "ERR:"},
		{"handler orders open", "ERR:"},
		{"prepare s from 'delete from orders'", "ERR:"},
		{"execute s", "ERR:"},
		{"do sleep(5)", "ERR:"},
		{"update orders set a=1", "ERR:WHERE"},
		{"delete from orders", "ERR:WHERE"},
		{"delete from orders where 1=1", "ERR:WHERE"},
		{"delete from orders where true", "ERR:WHERE"},
		{"truncate table orders", "ERR:TRUNCATE"},
		{"select * from mysql.user", "ERR:"},
		{"show global variables", "ERR:GLOBAL"},
		{"select @@global.version", "select"},
		{"select @a:=1", "select"}, {"select * from mysql.user", "ERR:mysql"},
		{"select * from orders where id = (select max(id) from orders) for update", "select,update"},
		{"kill 1", "ERR:"},
		{"shutdown", "ERR:"},
		{"rename user a to b", "ERR:"},
		{"create user x", "ERR:"},
		{"flush privileges", "ERR:"},
		{"begin", "ERR:"},
		{"xyz garbage", "ERR:无法解析"},
		{"", "ERR:"},
	}
	for _, tc := range cases {
		p, err := classifySQL(tc.sql, c)
		if strings.HasPrefix(tc.perms, "ERR:") {
			if err == nil {
				t.Errorf("%q: expected error, got perms %v sql %q", tc.sql, p.Perms, p.SQL)
			} else if want := strings.TrimPrefix(tc.perms, "ERR:"); want != "" && !strings.Contains(err.Error(), want) {
				t.Errorf("%q: error %q does not contain %q", tc.sql, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", tc.sql, err)
			continue
		}
		got := strings.Join(uniq(p.Perms), ",")
		if !sameSet(got, tc.perms) {
			t.Errorf("%q: perms %s, want %s", tc.sql, got, tc.perms)
		}
	}
}

func sameSet(a, b string) bool {
	m := map[string]bool{}
	for _, x := range strings.Split(a, ",") {
		m[x] = true
	}
	n := map[string]bool{}
	for _, x := range strings.Split(b, ",") {
		n[x] = true
	}
	if len(m) != len(n) {
		return false
	}
	for k := range m {
		if !n[k] {
			return false
		}
	}
	return true
}

func TestSQLLimitAndScope(t *testing.T) {
	c := sqlCfg()
	c.MaxRows = 50
	p, err := classifySQL("select * from orders", c)
	if err != nil || !strings.Contains(strings.ToUpper(p.SQL), "LIMIT 51") {
		t.Fatalf("limit not applied: %v %v", p, err)
	}
	p, _ = classifySQL("select * from orders limit 5", c)
	if !strings.Contains(p.SQL, "LIMIT 5") {
		t.Fatalf("small limit changed: %s", p.SQL)
	}
	c.AllowedTables = []string{"orders"}
	if _, err := classifySQL("select * from users", c); err == nil {
		t.Fatal("table scope not enforced")
	}
	if _, err := classifySQL("select * from orders o join users u on o.uid=u.id", c); err == nil {
		t.Fatal("join scope not enforced")
	}
	if _, err := classifySQL("select * from orders where uid in (select id from users)", c); err == nil {
		t.Fatal("subquery scope not enforced")
	}
	if _, err := classifySQL("select * from hr.orders", c); err == nil {
		t.Fatal("db scope not enforced")
	}
	if _, err := classifySQL("select * from information_schema.tables", c); err == nil {
		t.Fatal("system schema allowed with scope")
	}
	if _, err := classifySQL("with users as (select 1) select * from users", c); err != nil {
		t.Fatalf("CTE name treated as table: %v", err)
	}
	c.AllowedTables = nil
	c.AllowedDBs = []string{"shop"}
	if _, err := classifySQL("show tables from hr", c); err == nil {
		t.Fatal("show db scope")
	}
	if _, err := classifySQL("select * from hr.x", c); err == nil {
		t.Fatal("db scope")
	}
	f := false
	c.RequireWhere = &f
	if _, err := classifySQL("delete from orders", c); err != nil {
		t.Fatal("where guard off should allow")
	}
}

func TestClassifyRedis(t *testing.T) {
	c := &MWConfig{}
	cases := []struct {
		cmd, want string
	}{
		{"GET a", "read"}, {"get a", "read"}, {"gEt a", "read"}, {"HGETALL h", "read"}, {"MGET a b", "read"},
		{"SET a 1", "write"}, {"EXPIRE a 10", "write"}, {"MSET a 1 b 2", "write"},
		{"DEL a", "delete"}, {"LPOP l", "delete"}, {"EVAL 'return 1' 0", "script"},
		{"FLUSHALL", "ERR"}, {"flushdb", "ERR"}, {"CONFIG GET *", "ERR"}, {"SHUTDOWN", "ERR"}, {"DEBUG SLEEP 1", "ERR"},
		{"KEYS *", "ERR"}, {"SCRIPT FLUSH", "ERR"}, {"SELECT 2", "ERR"}, {"COPY a b DB 3", "ERR"}, {"MOVE a 3", "ERR"},
		{"MIGRATE x", "ERR"}, {"ACL LIST", "ERR"}, {"BLPOP a 0", "ERR"}, {"MULTI", "ERR"}, {"UNKNOWNCMD", "ERR"}, {"SORT a STORE b", "ERR"},
	}
	for _, tc := range cases {
		args, _ := splitCommand(tc.cmd)
		perm, _, err := classifyRedis(args, c)
		if tc.want == "ERR" {
			if err == nil {
				t.Errorf("%q should be blocked", tc.cmd)
			}
			continue
		}
		if err != nil || perm != tc.want {
			t.Errorf("%q: got %q %v want %s", tc.cmd, perm, err, tc.want)
		}
	}
	c.KeyPrefixes = []string{"order:"}
	for _, bad := range []string{"GET user:1", "MGET order:1 user:1", "MSET order:1 x user:1 y", "RENAME order:1 user:1", "EVAL 'return 1' 0", "DBSIZE"} {
		args, _ := splitCommand(bad)
		if _, _, err := classifyRedis(args, c); err == nil {
			t.Errorf("%q should be out of prefix scope", bad)
		}
	}
	args, _ := splitCommand(`SET order:1 "hello world"`)
	if len(args) != 3 || args[2] != "hello world" {
		t.Fatalf("split: %q", args)
	}
	if _, _, err := classifyRedis(args, c); err != nil {
		t.Fatal(err)
	}
	if !globWithinPrefixes("order:*", c.KeyPrefixes) || globWithinPrefixes("*", c.KeyPrefixes) || globWithinPrefixes("ord*", c.KeyPrefixes) || globWithinPrefixes("order[:]*", c.KeyPrefixes) {
		t.Fatal("glob prefix check")
	}
}

func TestTopicScope(t *testing.T) {
	c := &MWConfig{Topics: []string{"order_*", "pay"}}
	if c.checkTopic("order_created") != nil || c.checkTopic("pay") != nil {
		t.Fatal("allowed")
	}
	if c.checkTopic("payx") == nil || c.checkTopic("user") == nil {
		t.Fatal("denied")
	}
}
