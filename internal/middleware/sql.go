package middleware

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-sql-driver/mysql"
	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/format"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// sqlPlan is the result of the server-side SQL check. SQL is the statement re-generated from the
// parsed syntax tree; only that text is sent to the database, so what runs is exactly what was checked.
type sqlPlan struct {
	SQL      string
	Perms    []string // required permissions (select/insert/update/delete/ddl)
	ReadOnly bool     // run inside a read-only transaction
	Query    bool     // returns rows
	Kind     string   // SELECT / INSERT / ...
	Tables   []string
}

var sqlBlockedFuncs = map[string]string{
	"load_file": "读取服务器文件", "sleep": "长时间占用连接", "benchmark": "长时间占用连接",
	"get_lock": "加锁", "release_lock": "加锁", "release_all_locks": "加锁", "is_free_lock": "加锁", "is_used_lock": "加锁",
	"master_pos_wait": "复制控制", "source_pos_wait": "复制控制", "sys_exec": "执行系统命令", "sys_eval": "执行系统命令",
}

var systemSchemas = map[string]bool{"mysql": true, "information_schema": true, "performance_schema": true, "sys": true, "oceanbase": true}

var sqlShowAllowed = map[ast.ShowStmtType]bool{
	ast.ShowDatabases: true, ast.ShowTables: true, ast.ShowColumns: true, ast.ShowCreateTable: true, ast.ShowCreateView: true,
	ast.ShowIndex: true, ast.ShowTableStatus: true, ast.ShowWarnings: true, ast.ShowErrors: true, ast.ShowCharset: true,
	ast.ShowCollation: true, ast.ShowEngines: true, ast.ShowCreateDatabase: true, ast.ShowVariables: true, ast.ShowStatus: true,
}

type sqlVisitor struct {
	tables  []*ast.TableName
	ctes    map[string]bool
	err     error
	lock    bool
	into    bool
	columns int
}

func (v *sqlVisitor) Enter(n ast.Node) (ast.Node, bool) {
	switch x := n.(type) {
	case *ast.TableName:
		v.tables = append(v.tables, x)
	case *ast.CommonTableExpression:
		v.ctes[x.Name.L] = true
	case *ast.SelectStmt:
		if x.SelectIntoOpt != nil {
			v.into = true
		}
		if x.LockInfo != nil && x.LockInfo.LockType != ast.SelectLockNone {
			v.lock = true
		}
	case *ast.FuncCallExpr:
		if why, bad := sqlBlockedFuncs[x.FnName.L]; bad && v.err == nil {
			v.err = fmt.Errorf("已拦截：不允许使用函数 %s（%s）", strings.ToUpper(x.FnName.O), why)
		}
	case *ast.ColumnNameExpr:
		v.columns++
	case *ast.VariableExpr:
		if x.IsSystem && x.Value != nil && v.err == nil {
			v.err = errors.New("已拦截：不允许修改系统变量")
		}
	}
	return n, false
}

func (v *sqlVisitor) Leave(n ast.Node) (ast.Node, bool) { return n, true }

func whereHasColumn(e ast.ExprNode) bool {
	if e == nil {
		return false
	}
	v := &sqlVisitor{ctes: map[string]bool{}}
	e.Accept(v)
	return v.columns > 0
}

func restoreSQL(n ast.Node) (string, error) {
	var sb strings.Builder
	if err := n.Restore(format.NewRestoreCtx(format.DefaultRestoreFlags|format.RestoreStringWithoutCharset, &sb)); err != nil {
		return "", errors.New("已拦截：无法安全地重新生成这条 SQL")
	}
	return sb.String(), nil
}

// classifySQL parses one statement, decides which permissions it needs and checks the scope.
// It never executes anything.
func classifySQL(text string, c *Config) (*sqlPlan, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("SQL 不能为空")
	}
	p := parser.New()
	stmts, _, err := p.Parse(text, "utf8mb4", "")
	if err != nil {
		msg := err.Error()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, errors.New("已拦截：SQL 无法解析（只支持标准 MySQL 语法）：" + msg)
	}
	if len(stmts) == 0 {
		return nil, errors.New("SQL 不能为空")
	}
	if len(stmts) > 1 {
		return nil, errors.New("已拦截：一次只能执行一条 SQL 语句（检测到多条语句）")
	}
	stmt := stmts[0]
	plan := &sqlPlan{}
	need := func(p ...string) { plan.Perms = append(plan.Perms, p...) }
	maxRows := c.maxRows()
	var whereCheck func(ast.ExprNode, string) error = func(w ast.ExprNode, verb string) error {
		if !c.requireWhere() {
			return nil
		}
		if w == nil {
			return fmt.Errorf("已拦截：%s 必须带 WHERE 条件（中间件开启了「写操作必须带 WHERE」保护）", verb)
		}
		if !whereHasColumn(w) {
			return fmt.Errorf("已拦截：%s 的 WHERE 条件必须引用具体的列（例如 WHERE id = 1），不能是恒真条件", verb)
		}
		return nil
	}
	inner := stmt
	if ex, ok := stmt.(*ast.ExplainStmt); ok {
		inner = ex.Stmt
		plan.Kind = "EXPLAIN"
		need("select")
		switch ex.Stmt.(type) {
		case *ast.SelectStmt, *ast.SetOprStmt, *ast.ShowStmt:
		case *ast.InsertStmt, *ast.UpdateStmt, *ast.DeleteStmt:
			if ex.Analyze {
				return nil, errors.New("已拦截：EXPLAIN ANALYZE 只能用于 SELECT（它会真正执行语句）")
			}
		default:
			return nil, errors.New("已拦截：EXPLAIN 只能用于 SELECT / INSERT / UPDATE / DELETE")
		}
	}
	switch x := inner.(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		need("select")
		plan.Query, plan.ReadOnly = true, true
		if plan.Kind == "" {
			plan.Kind = "SELECT"
			applyLimit(inner, maxRows)
		}
	case *ast.ShowStmt:
		if !sqlShowAllowed[x.Tp] {
			return nil, errors.New("已拦截：不支持这种 SHOW 语句（可用 SHOW TABLES / SHOW COLUMNS / SHOW CREATE TABLE / SHOW INDEX 等）")
		}
		if x.Tp == ast.ShowVariables || x.Tp == ast.ShowStatus {
			if x.GlobalScope {
				return nil, errors.New("已拦截：不支持 SHOW GLOBAL")
			}
		}
		need("select")
		plan.Query, plan.ReadOnly = true, true
		if plan.Kind == "" {
			plan.Kind = "SHOW"
		}
		if x.DBName != "" {
			if err := c.checkDB(x.DBName); err != nil {
				return nil, err
			}
		}
	case *ast.InsertStmt:
		if plan.Kind == "" {
			plan.Kind = "INSERT"
			if x.IsReplace {
				plan.Kind = "REPLACE"
			}
		}
		need("insert")
		if x.IsReplace {
			need("update") // REPLACE overwrites an existing row with the same key
		}
		if len(x.OnDuplicate) > 0 {
			need("update")
		}
		if x.Select != nil {
			need("select")
		}
	case *ast.UpdateStmt:
		if plan.Kind == "" {
			plan.Kind = "UPDATE"
		}
		need("update")
		if err := whereCheck(x.Where, "UPDATE"); err != nil {
			return nil, err
		}
	case *ast.DeleteStmt:
		if plan.Kind == "" {
			plan.Kind = "DELETE"
		}
		need("delete")
		if err := whereCheck(x.Where, "DELETE"); err != nil {
			return nil, err
		}
	case *ast.TruncateTableStmt:
		if plan.Kind != "" {
			return nil, errors.New("已拦截：不支持 EXPLAIN 这种语句")
		}
		plan.Kind = "TRUNCATE"
		need("delete")
		if c.requireWhere() {
			return nil, errors.New("已拦截：TRUNCATE 会清空整张表（中间件开启了「写操作必须带 WHERE」保护，请改用带条件的 DELETE）")
		}
	case *ast.CreateTableStmt, *ast.AlterTableStmt, *ast.DropTableStmt, *ast.RenameTableStmt, *ast.CreateIndexStmt,
		*ast.DropIndexStmt, *ast.CreateViewStmt:
		if plan.Kind != "" {
			return nil, errors.New("已拦截：不支持 EXPLAIN 这种语句")
		}
		plan.Kind = "DDL"
		need("ddl")
		if ct, ok := x.(*ast.CreateTableStmt); ok && ct.Select != nil {
			need("select")
		}
	case *ast.CreateDatabaseStmt, *ast.DropDatabaseStmt, *ast.AlterDatabaseStmt:
		if plan.Kind != "" {
			return nil, errors.New("已拦截：不支持 EXPLAIN 这种语句")
		}
		plan.Kind = "DDL"
		need("ddl")
		var name string
		switch d := x.(type) {
		case *ast.CreateDatabaseStmt:
			name = d.Name.O
		case *ast.DropDatabaseStmt:
			name = d.Name.O
		case *ast.AlterDatabaseStmt:
			name = d.Name.O
		}
		if len(c.AllowedTables) > 0 {
			return nil, errors.New("已拦截：中间件限定了可访问的表，不能对整个库做 DDL")
		}
		if name != "" {
			if err := c.checkDB(name); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("已拦截：不允许执行这类语句（%s）。只支持 SELECT / SHOW / DESCRIBE / EXPLAIN / INSERT / REPLACE / UPDATE / DELETE，以及开启 DDL 权限后的 CREATE / ALTER / DROP / TRUNCATE", stmtKind(stmt))
	}
	v := &sqlVisitor{ctes: map[string]bool{}}
	stmt.Accept(v)
	if v.err != nil {
		return nil, v.err
	}
	if v.into {
		return nil, errors.New("已拦截：不允许 SELECT … INTO（导出到文件或变量）")
	}
	if plan.Kind == "EXPLAIN" {
		plan.Query, plan.ReadOnly = true, true
	}
	if v.lock {
		// SELECT … FOR UPDATE / LOCK IN SHARE MODE takes row locks: treat as a write.
		need("update")
		plan.ReadOnly = false
	}
	seen := map[string]bool{}
	for _, t := range v.tables {
		if t.Schema.L == "" && v.ctes[t.Name.L] {
			continue
		}
		db := t.Schema.O
		if db == "" {
			db = c.Database
		}
		if err := c.checkTable(db, t.Name.O); err != nil {
			return nil, err
		}
		full := t.Name.O
		if t.Schema.O != "" {
			full = t.Schema.O + "." + t.Name.O
		}
		if !seen[full] {
			seen[full] = true
			plan.Tables = append(plan.Tables, full)
		}
	}
	if s, ok := inner.(*ast.ShowStmt); ok && s.Tp == ast.ShowTables && s.DBName == "" && c.Database == "" && len(c.AllowedDBs) > 0 {
		return nil, errors.New("请指定数据库：SHOW TABLES FROM 库名")
	}
	out, err := restoreSQL(stmt)
	if err != nil {
		return nil, err
	}
	plan.SQL = out
	return plan, nil
}

func stmtKind(s ast.StmtNode) string {
	t := fmt.Sprintf("%T", s)
	t = strings.TrimPrefix(t, "*ast.")
	return strings.TrimSuffix(t, "Stmt")
}

// applyLimit adds LIMIT max+1 (to detect truncation) when missing, or lowers a larger literal LIMIT.
func applyLimit(n ast.StmtNode, max int) {
	var lim **ast.Limit
	switch x := n.(type) {
	case *ast.SelectStmt:
		lim = &x.Limit
	case *ast.SetOprStmt:
		lim = &x.Limit
	default:
		return
	}
	want := uint64(max + 1)
	if *lim == nil {
		*lim = &ast.Limit{Count: ast.NewValueExpr(want, "", "")}
		return
	}
	if v, ok := (*lim).Count.(ast.ValueExpr); ok {
		var cur uint64
		switch x := v.GetValue().(type) {
		case int64:
			cur = uint64(x)
		case uint64:
			cur = x
		default:
			return
		}
		if cur > want {
			(*lim).Count = ast.NewValueExpr(want, "", "")
		}
	}
}

// ---------- scope ----------

func (c *Config) checkDB(db string) error {
	if len(c.AllowedDBs) == 0 {
		return nil
	}
	for _, d := range c.AllowedDBs {
		if strings.EqualFold(d, db) {
			return nil
		}
	}
	return fmt.Errorf("无权限：数据库 %s 不在允许访问的范围内（允许：%s）", db, strings.Join(c.AllowedDBs, "、"))
}

func (c *Config) checkTable(db, table string) error {
	scoped := len(c.AllowedDBs) > 0 || len(c.AllowedTables) > 0
	if strings.EqualFold(db, "mysql") {
		return errors.New("无权限：不允许访问 mysql 系统库（里面有数据库账号和密码哈希）")
	}
	if scoped && systemSchemas[strings.ToLower(db)] {
		return fmt.Errorf("无权限：不允许访问系统库 %s", db)
	}
	if db == "" && scoped {
		return fmt.Errorf("请写明表 %s 所在的库（库名.表名），或在中间件里设置默认库", table)
	}
	if err := c.checkDB(db); err != nil {
		return err
	}
	if len(c.AllowedTables) == 0 {
		return nil
	}
	for _, t := range c.AllowedTables {
		t = strings.TrimSpace(t)
		tdb, tname, has := strings.Cut(t, ".")
		if !has {
			tname, tdb = t, c.Database
		}
		if !strings.EqualFold(tdb, db) {
			continue
		}
		if tname == "*" || strings.EqualFold(tname, table) {
			return nil
		}
	}
	return fmt.Errorf("无权限：表 %s.%s 不在允许访问的范围内", db, table)
}

// ---------- connection + execution ----------

func (m *Target) mysqlConnector(pw string) (*mysql.Config, error) {
	c := m.Config
	cfg := mysql.NewConfig()
	cfg.User = c.User
	cfg.Passwd = pw
	cfg.Net = "tcp"
	port := c.Port
	if port == 0 {
		port = 3306
	}
	cfg.Addr = joinHostPort(c.Host, port)
	cfg.DBName = c.Database
	cfg.Timeout = 8 * time.Second
	cfg.ReadTimeout = time.Duration(c.timeoutSec()+5) * time.Second
	cfg.WriteTimeout = cfg.ReadTimeout
	cfg.MultiStatements = false
	cfg.AllowAllFiles = false
	cfg.InterpolateParams = false
	cfg.AllowNativePasswords = true
	cfg.AllowCleartextPasswords = c.TLS
	if c.TLS {
		cfg.TLSConfig = "true"
		if c.TLSSkipVerify {
			cfg.TLSConfig = "skip-verify"
		}
	}
	cfg.Collation = "utf8mb4_general_ci"
	cfg.InterpolateParams = true
	return cfg, nil
}

func (a *Drivers) mysqlDB(m *Target) (*sql.DB, error) {
	pw, err := m.Password()
	if err != nil {
		return nil, err
	}
	key := m.cacheKey(pw)
	if v, ok := a.pool.Load(key); ok {
		return v.(*sql.DB), nil
	}
	cfg, _ := m.mysqlConnector(pw)
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(2 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	a.put(m.ID, key, db)
	return db, nil
}

type sqlResult struct {
	Columns      []string `json:"columns,omitempty"`
	Rows         [][]any  `json:"rows,omitempty"`
	RowCount     int      `json:"row_count"`
	Truncated    bool     `json:"truncated,omitempty"`
	Note         string   `json:"note,omitempty"`
	AffectedRows *int64   `json:"affected_rows,omitempty"`
	LastInsertID *int64   `json:"last_insert_id,omitempty"`
}

func (a *Drivers) runSQL(ctx context.Context, m *Target, plan *sqlPlan, params []any) (*sqlResult, error) {
	db, err := a.mysqlDB(m)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(m.Config.timeoutSec())*time.Second)
	defer cancel()
	if !plan.Query {
		r, err := db.ExecContext(ctx, plan.SQL, params...)
		if err != nil {
			return nil, err
		}
		n, _ := r.RowsAffected()
		id, _ := r.LastInsertId()
		res := &sqlResult{AffectedRows: &n}
		if id > 0 {
			res.LastInsertID = &id
		}
		return res, nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var rows *sql.Rows
	if plan.ReadOnly {
		tx, terr := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if terr == nil {
			defer tx.Rollback()
			rows, err = tx.QueryContext(ctx, plan.SQL, params...)
		} else {
			rows, err = conn.QueryContext(ctx, plan.SQL, params...)
		}
	} else {
		rows, err = conn.QueryContext(ctx, plan.SQL, params...)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	res := &sqlResult{Columns: cols, Rows: [][]any{}}
	max := m.Config.maxRows()
	budget := m.Config.maxResultBytes()
	size := 0
	for rows.Next() {
		if len(res.Rows) >= max {
			res.Truncated = true
			res.Note = fmt.Sprintf("结果超过 %d 行，只返回前 %d 行。请加 WHERE 条件或 LIMIT 缩小范围。", max, max)
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, v := range vals {
			vals[i] = sqlValue(v)
		}
		b, _ := json.Marshal(vals)
		size += len(b)
		if size > budget {
			res.Truncated = true
			res.Note = fmt.Sprintf("结果超过 %d KB，已截断。请只查询需要的列或缩小范围。", budget/1024)
			break
		}
		res.Rows = append(res.Rows, vals)
	}
	if err := rows.Err(); err != nil && !res.Truncated {
		return nil, err
	}
	res.RowCount = len(res.Rows)
	return res, nil
}

func sqlValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case []byte:
		if utf8.Valid(x) {
			return string(x)
		}
		return "base64:" + base64.StdEncoding.EncodeToString(x)
	case time.Time:
		return x.Format("2006-01-02 15:04:05")
	case int64, float64, bool, string:
		return x
	case uint64:
		return strconv.FormatUint(x, 10)
	}
	return fmt.Sprint(v)
}

func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

func joinHostPort(h string, p int) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]:" + strconv.Itoa(p)
	}
	return h + ":" + strconv.Itoa(p)
}
