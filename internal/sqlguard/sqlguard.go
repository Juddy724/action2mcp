// Package sqlguard checks that one SQL statement is a single read-only SELECT
// with an explicit LIMIT. It does not open a database connection.
package sqlguard

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/mysql"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// MaxRowsCap is the largest LIMIT the guard accepts.
const MaxRowsCap = 200

// Kind identifies the category of an accepted read-only SQL statement.
type Kind string

const (
	KindSelect     Kind = "select"
	KindDescribe   Kind = "describe"
	KindListTables Kind = "list_tables"
)

// Options controls which read-only SQL statements CheckWithOptions accepts.
type Options struct {
	MaxRows         int
	AllowDescribe   bool
	AllowListTables bool
}

var (
	errSQLUnparsed           = errors.New("SQL 无法解析")
	errSQLNotSelect          = errors.New("只允许执行单条只读 SELECT（含 WITH … SELECT）")
	errSQLNotSelectOrDesc    = errors.New("只允许执行单条只读 SELECT（含 WITH … SELECT）或表结构查看（DESCRIBE / SHOW COLUMNS / SHOW INDEX / SHOW CREATE TABLE）")
	errSQLNotSelectOrList    = errors.New("只允许执行单条只读 SELECT（含 WITH … SELECT）或表列表查看（SHOW TABLES）")
	errSQLNotSelectOrMeta    = errors.New("只允许执行单条只读 SELECT（含 WITH … SELECT）、表列表（SHOW TABLES）或表结构查看（DESCRIBE / SHOW COLUMNS / SHOW INDEX / SHOW CREATE TABLE）")
	errSQLDescribeWithWhere  = errors.New("表结构/表列表查看语句不支持 WHERE 子句")
	errSQLNeedLimit          = errors.New("必须在 SQL 末尾写上 LIMIT，且不超过允许的行数")
	errSQLCondComment        = errors.New("不允许使用条件注释")
	errSQLModeConflict       = errors.New("SQL 在不同解析模式下含义不一致，已拒绝执行")
	errSQLSynthetic          = errors.New("表名或别名与 EXPLAIN 合成行标识冲突")
)

var syntheticAliasRe = regexp.MustCompile(`(?i)^<(derived|subquery|union)\d+>$`)

var sqlGuardAggFuncs = map[string]bool{
	"count": true, "sum": true, "avg": true, "min": true, "max": true, "group_concat": true,
}

var sqlGuardAllowFuncs = map[string]bool{
	"if": true, "ifnull": true, "nullif": true, "coalesce": true,
	"cast": true, "convert": true,
	"concat": true, "concat_ws": true, "substring": true, "substr": true, "left": true, "right": true,
	"trim": true, "ltrim": true, "rtrim": true, "upper": true, "lower": true,
	"length": true, "char_length": true, "character_length": true, "replace": true, "instr": true, "locate": true,
	"lpad": true, "rpad": true, "reverse": true, "repeat": true, "space": true,
	"abs": true, "ceil": true, "ceiling": true, "floor": true, "round": true, "truncate": true,
	"mod": true, "least": true, "greatest": true, "sign": true,
	"date": true, "date_format": true, "str_to_date": true, "date_add": true, "date_sub": true,
	"datediff": true, "timestampdiff": true, "year": true, "month": true, "day": true,
	"hour": true, "minute": true, "second": true, "now": true, "curdate": true, "curtime": true,
	"current_date": true, "current_time": true, "current_timestamp": true,
	"from_unixtime": true, "unix_timestamp": true, "isnull": true,
}

type sqlModeSet struct {
	name        string
	noBackslash bool
	ansiQuotes  bool
	mode        mysql.SQLMode
}

func sqlGuardModes() []sqlModeSet {
	return []sqlModeSet{
		{name: "default", mode: mysql.ModeNone},
		{name: "NO_BACKSLASH_ESCAPES", noBackslash: true, mode: mysql.ModeNoBackslashEscapes},
		{name: "ANSI_QUOTES", ansiQuotes: true, mode: mysql.ModeANSIQuotes},
		{name: "BOTH", noBackslash: true, ansiQuotes: true, mode: mysql.ModeNoBackslashEscapes | mysql.ModeANSIQuotes},
	}
}

func Check(sql string, maxRows int) error {
	_, err := CheckWithOptions(sql, Options{MaxRows: maxRows})
	return err
}

func CheckWithOptions(sql string, opts Options) (Kind, error) {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "", errors.New("SQL 不能为空")
	}
	maxRows := opts.MaxRows
	if maxRows < 1 || maxRows > MaxRowsCap {
		maxRows = MaxRowsCap
	}
	type result struct {
		stmtKind Kind
		astType  string
		limit    int
		err      error
	}
	var rs []result
	for _, m := range sqlGuardModes() {
		r := result{}
		if err := scanConditionalComments(sql, m.noBackslash, m.ansiQuotes); err != nil {
			r.err = err
		} else {
			r.stmtKind, r.astType, r.limit, r.err = inspectSQL(sql, m, maxRows, opts.AllowDescribe, opts.AllowListTables)
		}
		rs = append(rs, r)
	}
	same := true
	for i := 1; i < len(rs); i++ {
		a, b := rs[0], rs[i]
		aOK, bOK := a.err == nil, b.err == nil
		if aOK != bOK || a.stmtKind != b.stmtKind || a.astType != b.astType || a.limit != b.limit {
			same = false
			break
		}
		if !aOK && a.err.Error() != b.err.Error() {
			same = false
			break
		}
	}
	if !same {
		return "", errSQLModeConflict
	}
	return rs[0].stmtKind, rs[0].err
}

func notAllowedStmtErr(allowDescribe, allowListTables bool) error {
	switch {
	case allowDescribe && allowListTables:
		return errSQLNotSelectOrMeta
	case allowDescribe:
		return errSQLNotSelectOrDesc
	case allowListTables:
		return errSQLNotSelectOrList
	default:
		return errSQLNotSelect
	}
}

func inspectSQL(sql string, mode sqlModeSet, maxRows int, allowDescribe, allowListTables bool) (stmtKind Kind, astType string, limit int, err error) {
	p := parser.New()
	p.SetSQLMode(mode.mode)
	stmts, _, err := p.Parse(sql, "", "")
	if err != nil || len(stmts) == 0 {
		msg := "SQL 无法解析"
		if err != nil {
			msg += "：" + truncate(err.Error(), 200)
		}
		return "", "", 0, errors.New(msg)
	}
	if len(stmts) != 1 {
		return "", "", 0, errors.New("只允许一条 SQL 语句")
	}
	stmt := stmts[0]
	switch stmt.(type) {
	case *ast.SelectStmt, *ast.SetOprStmt:
		limit, err = outerLimitCount(stmt, maxRows)
		if err != nil {
			return "", "", 0, err
		}
		v := &sqlGuardVisitor{maxRows: maxRows}
		stmt.Accept(v)
		if v.err != nil {
			return "", "", 0, v.err
		}
		return KindSelect, fmt.Sprintf("%T", stmt), limit, nil
	default:
		if show, kind, ok := unwrapMetadataShow(stmt); ok {
			if (kind == KindDescribe && !allowDescribe) || (kind == KindListTables && !allowListTables) {
				return "", "", 0, notAllowedStmtErr(allowDescribe, allowListTables)
			}
			if show.Where != nil {
				return "", "", 0, errSQLDescribeWithWhere
			}
			v := &sqlGuardVisitor{maxRows: maxRows}
			stmt.Accept(v)
			if v.err != nil {
				return "", "", 0, v.err
			}
			return kind, fmt.Sprintf("%T:%d", stmt, show.Tp), 0, nil
		}
		return "", "", 0, notAllowedStmtErr(allowDescribe, allowListTables)
	}
}

func unwrapMetadataShow(stmt ast.StmtNode) (*ast.ShowStmt, Kind, bool) {
	var show *ast.ShowStmt
	switch s := stmt.(type) {
	case *ast.ExplainStmt:
		if s.Analyze || s.Explore || s.Format != "" || s.SQLDigest != "" || s.ReplayerFile != "" || s.PlanDigest != "" {
			return nil, "", false
		}
		sh, ok := s.Stmt.(*ast.ShowStmt)
		if !ok || sh.Tp != ast.ShowColumns {
			return nil, "", false
		}
		show = sh
	case *ast.ShowStmt:
		show = s
	default:
		return nil, "", false
	}
	switch show.Tp {
	case ast.ShowTables:
		return show, KindListTables, true
	case ast.ShowColumns, ast.ShowIndex, ast.ShowCreateTable:
		if show.Table == nil || strings.TrimSpace(show.Table.Name.O) == "" {
			return nil, "", false
		}
		return show, KindDescribe, true
	default:
		return nil, "", false
	}
}

func outerLimitCount(stmt ast.StmtNode, maxRows int) (int, error) {
	var lim *ast.Limit
	switch s := stmt.(type) {
	case *ast.SelectStmt:
		lim = s.Limit
	case *ast.SetOprStmt:
		lim = s.Limit
	}
	if lim == nil || lim.Count == nil {
		return 0, errSQLNeedLimit
	}
	n, ok := literalInt(lim.Count)
	if !ok {
		return 0, errors.New("LIMIT 的行数必须是字面整数，不能使用表达式或占位符")
	}
	if n < 1 || n > maxRows {
		return 0, fmt.Errorf("LIMIT 必须在 1–%d 之间，当前是 %d", maxRows, n)
	}
	return n, nil
}

func literalInt(n ast.ExprNode) (int, bool) {
	v, ok := n.(ast.ValueExpr)
	if !ok {
		return 0, false
	}
	switch x := v.GetValue().(type) {
	case int64:
		return int(x), x >= 0 && int64(int(x)) == x
	case uint64:
		if x > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(x), true
	case int:
		return x, true
	case string:
		i, err := strconv.Atoi(x)
		return i, err == nil
	default:
		return 0, false
	}
}

type sqlGuardVisitor struct {
	err     error
	maxRows int
}

func (v *sqlGuardVisitor) Enter(n ast.Node) (ast.Node, bool) {
	if v.err != nil {
		return n, true
	}
	switch x := n.(type) {
	case *ast.SelectStmt:
		if x.SelectIntoOpt != nil {
			v.err = errors.New("不允许 SELECT … INTO")
		}
		if x.LockInfo != nil && x.LockInfo.LockType != ast.SelectLockNone {
			v.err = errors.New("不允许带锁读取（FOR UPDATE / LOCK IN SHARE MODE / FOR SHARE）")
		}
	case *ast.TableSource:
		if syntheticAliasRe.MatchString(strings.TrimSpace(x.AsName.O)) || syntheticAliasRe.MatchString(strings.TrimSpace(x.AsName.L)) {
			v.err = errSQLSynthetic
		}
	case *ast.TableName:
		if syntheticAliasRe.MatchString(strings.TrimSpace(x.Name.O)) || syntheticAliasRe.MatchString(strings.TrimSpace(x.Name.L)) {
			v.err = errSQLSynthetic
		}
	case *ast.FuncCallExpr:
		if x.Schema.L != "" || x.Schema.O != "" {
			v.err = fmt.Errorf("不允许调用带限定名的函数 %s.%s", x.Schema.O, x.FnName.O)
			break
		}
		name := strings.ToLower(x.FnName.L)
		if name == "" {
			name = strings.ToLower(x.FnName.O)
		}
		if sqlGuardAggFuncs[name] {
			v.err = fmt.Errorf("函数 %s 必须以原生聚合形式调用，不允许使用引号或通用调用", strings.ToUpper(name))
			break
		}
		if !sqlGuardAllowFuncs[name] {
			v.err = fmt.Errorf("不允许使用函数 %s", strings.ToUpper(name))
		}
	case *ast.AggregateFuncExpr:
		name := strings.ToLower(x.F)
		if !sqlGuardAggFuncs[name] {
			v.err = fmt.Errorf("不允许使用聚合函数 %s", strings.ToUpper(name))
		}
	case *ast.WindowFuncExpr:
		v.err = errors.New("不允许使用窗口函数")
	case *ast.VariableExpr:
		v.err = errors.New("不允许使用用户变量或系统变量")
	case *ast.PrepareStmt, *ast.ExecuteStmt, *ast.DeallocateStmt, *ast.LoadDataStmt, *ast.SetStmt:
		v.err = errSQLNotSelect
	}
	return n, v.err != nil
}

func (v *sqlGuardVisitor) Leave(n ast.Node) (ast.Node, bool) {
	return n, v.err == nil
}

func scanConditionalComments(sql string, noBackslash, ansiQuotes bool) error {
	s := sql
	i := 0
	for i < len(s) {
		ch, w := decodeRune(s, i)
		if ch == utf8.RuneError && w == 1 {
			return errors.New("SQL 包含无法识别的字符，已拒绝执行")
		}
		switch {
		case ch == '\'':
			next, ok := skipQuoted(s, i+w, '\'', !noBackslash)
			if !ok {
				return errSQLUnparsed
			}
			i = next
		case ch == '"':
			escape := !noBackslash
			if ansiQuotes {
				escape = false
			}
			next, ok := skipQuoted(s, i+w, '"', escape)
			if !ok {
				return errSQLUnparsed
			}
			i = next
		case ch == '`':
			next, ok := skipQuoted(s, i+w, '`', false)
			if !ok {
				return errSQLUnparsed
			}
			i = next
		case ch == '-' && i+1 < len(s) && s[i+1] == '-':
			// Require comment start (-- followed by space or end), as MySQL does.
			if i+2 >= len(s) || unicode.IsSpace(rune(s[i+2])) {
				for i < len(s) && s[i] != '\n' {
					i++
				}
			} else {
				i += w
			}
		case ch == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case ch == '/' && i+1 < len(s) && s[i+1] == '*':
			body := s[i+2:]
			if strings.HasPrefix(body, "!") || strings.HasPrefix(strings.ToUpper(body), "T!") || strings.HasPrefix(strings.ToUpper(body), "M!") {
				return errSQLCondComment
			}
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return errSQLUnparsed
			}
			i = i + 2 + end + 2
		default:
			i += w
		}
	}
	return nil
}

func decodeRune(s string, i int) (rune, int) {
	return utf8.DecodeRuneInString(s[i:])
}

func skipQuoted(s string, i int, quote byte, backslash bool) (int, bool) {
	for i < len(s) {
		if backslash && s[i] == '\\' {
			if i+1 >= len(s) {
				return 0, false
			}
			i += 2
			continue
		}
		if s[i] == quote {
			if i+1 < len(s) && s[i+1] == quote {
				i += 2
				continue
			}
			return i + 1, true
		}
		i++
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…[已截断]"
	}
	return s
}
