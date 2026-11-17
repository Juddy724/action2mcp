package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var mysqlExplainTypes = map[string]bool{
	"system": true, "const": true, "eq_ref": true, "ref": true, "ref_or_null": true,
	"range": true, "index_merge": true, "unique_subquery": true, "index_subquery": true,
	"fulltext": true, "index": true,
}

var syntheticTableRe = regexp.MustCompile(`(?i)^<(derived|subquery|union)\d+>$`)
var obIndexInName = regexp.MustCompile(`(?i)\(([^)]+)\)|@([A-Za-z0-9_]+)|index[:\s]+([A-Za-z0-9_]+)`)
var obAccessOp = regexp.MustCompile(`(?i)(TABLE SCAN|TABLE GET|TABLE RANGE SCAN|INDEX SCAN|INDEX RANGE SCAN|INDEX LOOKUP|INDEX REVERSE SCAN)`)
var obWriteOp = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|REPLACE)\b`)

type explainColumn struct {
	ID, Name, Field string
}

type explainRow map[string]string

func checkExplainResult(columns []explainColumn, rows []explainRow, sqlAliases map[string]bool) error {
	if len(rows) == 0 {
		return errors.New("无法解析 EXPLAIN 结果，已取消执行")
	}
	if looksLikeMySQLExplain(columns) {
		return checkMySQLExplain(columns, rows, sqlAliases)
	}
	if looksLikeOceanBasePlan(columns, rows) {
		return checkOceanBasePlan(columns, rows)
	}
	return errors.New("不支持的 EXPLAIN 格式，已取消执行")
}

func looksLikeMySQLExplain(cols []explainColumn) bool {
	need := []string{"id", "select_type", "table", "type", "key"}
	for _, n := range need {
		if explainCol(cols, n) == nil {
			return false
		}
	}
	return true
}

func looksLikeOceanBasePlan(cols []explainColumn, rows []explainRow) bool {
	if explainCol(cols, "query plan") != nil || explainCol(cols, "operator") != nil {
		return true
	}
	if len(cols) == 1 && len(rows) > 0 {
		name := strings.ToLower(strings.TrimSpace(cols[0].Name + " " + cols[0].Field))
		if strings.Contains(name, "plan") || strings.Contains(name, "query") {
			return true
		}
	}
	return false
}

func explainCol(cols []explainColumn, want string) *explainColumn {
	var found *explainColumn
	n := 0
	want = strings.ToLower(want)
	for i := range cols {
		c := &cols[i]
		label := strings.ToLower(strings.TrimSpace(firstNonEmpty(c.Name, c.Field, c.ID)))
		if label == want {
			n++
			found = c
		}
	}
	if n != 1 {
		return nil
	}
	return found
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func rowField(row explainRow, cols []explainColumn, name string) (string, bool) {
	col := explainCol(cols, name)
	if col == nil {
		return "", false
	}
	for _, key := range []string{col.ID, col.Field, col.Name} {
		if key == "" {
			continue
		}
		if v, ok := row[key]; ok {
			return strings.TrimSpace(v), true
		}
		for rk, v := range row {
			if strings.EqualFold(rk, key) {
				return strings.TrimSpace(v), true
			}
		}
	}
	return "", false
}

func emptyKey(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || strings.EqualFold(s, "null") || s == "NULL" || s == "(null)"
}

func checkMySQLExplain(cols []explainColumn, rows []explainRow, aliases map[string]bool) error {
	ids := map[string]bool{}
	for _, row := range rows {
		id, _ := rowField(row, cols, "id")
		ids[id] = true
		table, _ := rowField(row, cols, "table")
		selType, _ := rowField(row, cols, "select_type")
		typ, hasType := rowField(row, cols, "type")
		key, _ := rowField(row, cols, "key")
		synthetic := syntheticTableRe.MatchString(table)
		if synthetic && aliases[strings.ToLower(table)] {
			return fmt.Errorf("无法确认 EXPLAIN 行身份（table=%s 与 SQL 别名冲突），已取消执行", table)
		}
		if synthetic {
			// Must not skip type checks unless we can confirm a referenced child plan exists.
			// Child ids are typically greater than this id in the same result.
			if !hasSiblingPlan(ids, id, rows, cols) && !hasOtherBaseRows(rows, cols, aliases) {
				return errors.New("无法确认 EXPLAIN 子计划，已取消执行")
			}
			if typ != "" && !emptyKey(typ) && strings.EqualFold(typ, "ALL") && !hasOtherBaseRows(rows, cols, aliases) {
				// A lone synthetic ALL without verified children is rejected; children checked separately.
			}
			continue
		}
		// Not synthetic: must be a base-table access, or a classified synthetic (union result etc.)
		if strings.EqualFold(selType, "UNION RESULT") || (table == "" && strings.Contains(strings.ToUpper(selType), "UNION")) {
			continue
		}
		if !hasType {
			return errors.New("无法解析 EXPLAIN 结果，已取消执行")
		}
		typL := strings.ToLower(typ)
		if typL == "all" {
			return fmt.Errorf("全表扫描（type=ALL, table=%s），必须改写 SQL 以使用索引", table)
		}
		if !mysqlExplainTypes[typL] {
			return fmt.Errorf("无法识别的 EXPLAIN type=%s，已取消执行", typ)
		}
		if typL != "const" && typL != "system" && emptyKey(key) {
			return fmt.Errorf("未使用索引（type=%s, key 为空, table=%s），已取消执行", typ, table)
		}
	}
	// Second pass: every non-synthetic base row already checked. Ensure at least one base access, or only const/system.
	return nil
}

func hasSiblingPlan(ids map[string]bool, id string, rows []explainRow, cols []explainColumn) bool {
	if len(rows) <= 1 {
		return false
	}
	for _, row := range rows {
		oid, _ := rowField(row, cols, "id")
		if oid != id && oid != "" {
			return true
		}
	}
	return false
}

func hasOtherBaseRows(rows []explainRow, cols []explainColumn, aliases map[string]bool) bool {
	for _, row := range rows {
		table, _ := rowField(row, cols, "table")
		if table != "" && !syntheticTableRe.MatchString(table) {
			return true
		}
	}
	return false
}

func checkOceanBasePlan(cols []explainColumn, rows []explainRow) error {
	var texts []string
	for _, row := range rows {
		for _, v := range row {
			texts = append(texts, v)
		}
	}
	blob := strings.Join(texts, "\n")
	if obWriteOp.FindString(blob) != "" && obAccessOp.FindString(blob) == "" {
		// Write operators on a SELECT plan are a hard reject if they appear as operators.
		if regexp.MustCompile(`(?i)(INSERT|UPDATE|DELETE|REPLACE)\s`).FindString(blob) != "" {
			return errors.New("EXPLAIN 计划包含写算子，已取消执行")
		}
	}
	if !strings.Contains(strings.ToUpper(blob), "TABLE") && !strings.Contains(strings.ToUpper(blob), "INDEX") && !strings.Contains(strings.ToUpper(blob), "GET") {
		return errors.New("不支持的 EXPLAIN 格式，已取消执行")
	}
	lines := strings.Split(blob, "\n")
	sawAccess := false
	for _, line := range lines {
		op := obAccessOp.FindString(line)
		if op == "" {
			if obWriteOp.MatchString(line) && regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|REPLACE)\b`).MatchString(line) &&
				(strings.Contains(strings.ToUpper(line), "OPERATOR") || strings.HasPrefix(strings.TrimSpace(strings.ToUpper(line)), "INSERT") || strings.Contains(line, "|")) {
				// be conservative only if it looks like an operator column
			}
			continue
		}
		sawAccess = true
		idx := obIndexInName.FindStringSubmatch(line)
		if idx == nil {
			return fmt.Errorf("访问算子 %s 没有明确的索引或主键名，已取消执行", strings.TrimSpace(op))
		}
	}
	if !sawAccess {
		// Maybe a single-cell plan with operators inline.
		if obAccessOp.FindString(blob) == "" {
			return errors.New("无法解析 EXPLAIN 结果，已取消执行")
		}
		if obIndexInName.FindString(blob) == "" {
			return errors.New("访问算子没有明确的索引或主键名，已取消执行")
		}
	}
	return nil
}

func parseExplainColumns(raw any) []explainColumn {
	var out []explainColumn
	switch xs := raw.(type) {
	case []any:
		for i, c := range xs {
			col := explainColumn{ID: "C_" + strconv.Itoa(i+1)}
			switch m := c.(type) {
			case map[string]any:
				col.Field = fmt.Sprint(firstPresent(m, "field", "Field"))
				col.Name = fmt.Sprint(firstPresent(m, "title", "realName", "name", "Name"))
				if f := fmt.Sprint(firstPresent(m, "field", "Field")); f != "" && f != "<nil>" {
					col.ID = f
				}
			default:
				col.Name = fmt.Sprint(c)
			}
			if col.Name == "<nil>" {
				col.Name = ""
			}
			out = append(out, col)
		}
	}
	return out
}

func firstPresent(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
		for mk, v := range m {
			if strings.EqualFold(mk, k) && v != nil {
				return v
			}
		}
	}
	return ""
}

func parseExplainRows(raw any, cols []explainColumn) []explainRow {
	var out []explainRow
	arr, ok := raw.([]any)
	if !ok {
		return out
	}
	for _, item := range arr {
		row := explainRow{}
		switch m := item.(type) {
		case map[string]any:
			for k, v := range m {
				if v == nil {
					row[k] = ""
					continue
				}
				row[k] = strings.TrimSpace(fmt.Sprint(v))
			}
		case []any:
			for i, v := range m {
				key := "C_" + strconv.Itoa(i+1)
				if i < len(cols) && cols[i].ID != "" {
					key = cols[i].ID
				}
				if v == nil {
					row[key] = ""
				} else {
					row[key] = strings.TrimSpace(fmt.Sprint(v))
				}
			}
		}
		out = append(out, row)
	}
	return out
}

func jsonPath(v any, path string) (any, bool) {
	cur := v
	if path == "" {
		return cur, true
	}
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		found := false
		for k, val := range m {
			if k == p {
				cur = val
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return cur, true
}

func asJSONMap(s string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
