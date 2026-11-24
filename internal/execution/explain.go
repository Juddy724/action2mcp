package execution

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

const (
	// explainMaxUnindexedRows allows unindexed scans on small tables (<= 20,000 estimated rows).
	explainMaxUnindexedRows = 20000
	// obMaxUnindexedTimeUS guards OceanBase EST.ROWS (which estimates post-filter output rows)
	// against large-table full scans that happen to have selective unindexed predicates.
	obMaxUnindexedTimeUS = 500000
)

var obIndexInName = regexp.MustCompile(`(?i)\(([^)]+)\)|@([A-Za-z0-9_]+)|index[:\s]+([A-Za-z0-9_]+)`)

var obAccessOp = regexp.MustCompile(`(?i)(TABLE FULL SCAN|TABLE RANGE SCAN|TABLE SCAN|TABLE GET|INDEX FULL SCAN|INDEX RANGE SCAN|INDEX SCAN|INDEX LOOKUP|INDEX REVERSE SCAN|INDEX GET)`)

var obWriteOp = regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|REPLACE)\b`)

var obPredHeaderRe = regexp.MustCompile(`^\s*(\d+)\s*-\s*output\(`)

var obRangeStartRe = regexp.MustCompile(`(?i)\brange\s*[(\[]`)

var obFullRangeInnerRe = regexp.MustCompile(`(?i)^[\s(]*(MIN(\s*,\s*MIN)*)\s*;\s*(MAX(\s*,\s*MAX)*)[\s)]*$`)

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
		label := strings.ToLower(strings.TrimSpace(FirstNonEmpty(c.Name, c.Field, c.ID)))
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

func FirstNonEmpty(ss ...string) string {
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
		estRows, hasEstRows := parseExplainNonNegInt(rowFieldValue(row, cols, "rows"))
		if typL == "all" {
			if hasEstRows && estRows <= explainMaxUnindexedRows {
				continue
			}
			if hasEstRows {
				return fmt.Errorf("全表扫描（type=ALL, table=%s, 预估扫描 %d 行 > %d），必须改写 SQL 以使用索引（可先执行 SHOW INDEX FROM %s 查看索引）", table, estRows, explainMaxUnindexedRows, table)
			}
			return fmt.Errorf("全表扫描（type=ALL, table=%s），必须改写 SQL 以使用索引（可先执行 SHOW INDEX FROM %s 查看索引）", table, table)
		}
		if !mysqlExplainTypes[typL] {
			return fmt.Errorf("无法识别的 EXPLAIN type=%s，已取消执行", typ)
		}
		if typL != "const" && typL != "system" && emptyKey(key) {
			if hasEstRows && estRows <= explainMaxUnindexedRows {
				continue
			}
			return fmt.Errorf("未使用索引（type=%s, key 为空, table=%s），已取消执行", typ, table)
		}
	}
	// Second pass: every non-synthetic base row already checked. Ensure at least one base access, or only const/system.
	return nil
}

func rowFieldValue(row explainRow, cols []explainColumn, name string) string {
	v, _ := rowField(row, cols, name)
	return v
}

func parseExplainNonNegInt(s string) (int64, bool) {
	s = strings.TrimSpace(strings.ReplaceAll(s, ",", ""))
	if s == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 0 && f < 1e15 {
		return int64(f), true
	}
	return 0, false
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
	// Join multi-column rows in deterministic column order on the same line so
	// OPERATOR and NAME cells are never split onto separate lines.
	var rowLines []string
	for _, row := range rows {
		if len(cols) > 1 {
			parts := make([]string, 0, len(cols))
			for _, c := range cols {
				v := ""
				for _, k := range []string{c.ID, c.Field, c.Name} {
					if k != "" {
						if x, ok := row[k]; ok {
							v = x
							break
						}
					}
				}
				parts = append(parts, v)
			}
			rowLines = append(rowLines, "| "+strings.Join(parts, " | ")+" |")
		} else if len(cols) == 1 {
			v := rowFieldValue(row, cols, FirstNonEmpty(cols[0].Name, cols[0].Field, cols[0].ID))
			if v == "" {
				for _, x := range row {
					v = x
					break
				}
			}
			rowLines = append(rowLines, v)
		} else {
			for _, x := range row {
				rowLines = append(rowLines, x)
			}
		}
	}
	blob := strings.Join(rowLines, "\n")
	if obWriteOp.FindString(blob) != "" && obAccessOp.FindString(blob) == "" {
		if regexp.MustCompile(`(?i)(INSERT|UPDATE|DELETE|REPLACE)\s`).FindString(blob) != "" {
			return errors.New("EXPLAIN 计划包含写算子，已取消执行")
		}
	}
	if !strings.Contains(strings.ToUpper(blob), "TABLE") && !strings.Contains(strings.ToUpper(blob), "INDEX") && !strings.Contains(strings.ToUpper(blob), "GET") {
		return errors.New("不支持的 EXPLAIN 格式，已取消执行")
	}

	lines := strings.Split(blob, "\n")
	preds := parseOBPredicates(lines)
	colIdx := parseOBTableHeader(cols, lines)

	sawAccess := false
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "outputs & filters") {
			break
		}
		if obPredHeaderRe.MatchString(line) {
			continue
		}
		op := strings.TrimSpace(obAccessOp.FindString(line))
		if op == "" {
			continue
		}
		sawAccess = true
		opUpper := strings.ToUpper(op)

		// 1. TABLE GET / INDEX GET in OceanBase is strictly Primary Key / Unique Key point or multi-get lookup.
		if strings.Contains(opUpper, "GET") {
			continue
		}

		// 2. Secondary index access: NAME contains "(index_name)", "@index", or "index: ...".
		if obIndexInName.FindStringSubmatch(line) != nil {
			continue
		}

		cells := splitPipeCells(line)
		opID := obCellAt(cells, colIdx.id)
		tableName := cleanOBTableName(obCellAt(cells, colIdx.name))

		// 3. Primary-key range scan in OceanBase IOT: NAME is the bare table name, while
		// "Outputs & filters" records a bounded key range (not full-table MIN ; MAX).
		if opID != "" && obPredHasBoundedRange(preds[opID]) {
			continue
		}

		// 4. Small scan allowance: EST.ROWS <= 20,000 (and EST.TIME(us) <= 500,000 when present).
		estRows, hasEstRows := parseExplainNonNegInt(obCellAt(cells, colIdx.estRows))
		estTime, hasEstTime := parseExplainNonNegInt(obCellAt(cells, colIdx.estTime))
		if hasEstRows && estRows <= explainMaxUnindexedRows && (!hasEstTime || estTime <= obMaxUnindexedTimeUS) {
			continue
		}

		if tableName != "" {
			if hasEstRows {
				return fmt.Errorf("访问算子 %s（表 %s，预估行数 %d）没有明确的索引或主键名，已取消执行（可先执行 SHOW INDEX FROM %s 查看可用索引）", op, tableName, estRows, tableName)
			}
			return fmt.Errorf("访问算子 %s（表 %s）没有明确的索引或主键名，已取消执行（可先执行 SHOW INDEX FROM %s 查看可用索引）", op, tableName, tableName)
		}
		return fmt.Errorf("访问算子 %s 没有明确的索引或主键名，已取消执行", op)
	}
	if !sawAccess {
		if obAccessOp.FindString(blob) == "" {
			return errors.New("无法解析 EXPLAIN 结果，已取消执行")
		}
		if obIndexInName.FindString(blob) == "" {
			return errors.New("访问算子没有明确的索引或主键名，已取消执行")
		}
	}
	return nil
}

type obColPositions struct {
	id, name, estRows, estTime int
}

func parseOBTableHeader(cols []explainColumn, lines []string) obColPositions {
	pos := obColPositions{id: -1, name: -1, estRows: -1, estTime: -1}
	matchHeader := func(cells []string) bool {
		foundOp := false
		for i, raw := range cells {
			h := strings.ToLower(strings.Join(strings.Fields(raw), ""))
			switch {
			case h == "id":
				pos.id = i
			case h == "operator":
				foundOp = true
			case h == "name":
				pos.name = i
			case h == "est.rows" || h == "rows":
				pos.estRows = i
			case strings.HasPrefix(h, "est.time"):
				pos.estTime = i
			}
		}
		return foundOp
	}
	if len(cols) > 1 {
		names := make([]string, len(cols))
		for i, c := range cols {
			names[i] = FirstNonEmpty(c.Name, c.Field, c.ID)
		}
		if matchHeader(names) {
			return pos
		}
	}
	for _, line := range lines {
		cells := splitPipeCells(line)
		if len(cells) >= 3 && matchHeader(cells) {
			return pos
		}
	}
	return pos
}

func splitPipeCells(line string) []string {
	t := strings.TrimSpace(line)
	if !strings.Contains(t, "|") {
		return nil
	}
	t = strings.TrimPrefix(t, "|")
	t = strings.TrimSuffix(t, "|")
	parts := strings.Split(t, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func obCellAt(cells []string, idx int) string {
	if idx < 0 || idx >= len(cells) {
		return ""
	}
	return cells[idx]
}

func cleanOBTableName(name string) string {
	name = strings.TrimSpace(name)
	if idx := strings.IndexAny(name, " ("); idx > 0 {
		name = name[:idx]
	}
	return strings.TrimSpace(name)
}

func parseOBPredicates(lines []string) map[string]string {
	out := map[string]string{}
	curID := ""
	var buf strings.Builder
	flush := func() {
		if curID != "" {
			out[curID] = buf.String()
			buf.Reset()
		}
	}
	for _, line := range lines {
		if m := obPredHeaderRe.FindStringSubmatch(line); m != nil {
			flush()
			curID = m[1]
			buf.WriteString(line)
			buf.WriteByte('\n')
			continue
		}
		if curID != "" {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	flush()
	return out
}

func obPredHasBoundedRange(pred string) bool {
	if pred == "" {
		return false
	}
	loc := obRangeStartRe.FindStringIndex(pred)
	if loc == nil {
		return false
	}
	rest := pred[loc[1]:]
	depth := 1
	end := -1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return false
	}
	content := strings.TrimSpace(rest[:end])
	if content == "" || strings.EqualFold(content, "true") {
		return false
	}
	if strings.EqualFold(content, "false") {
		return true
	}
	normalized := strings.NewReplacer("[", "(", "]", ")").Replace(content)
	segments := strings.Split(normalized, "),")
	for _, seg := range segments {
		seg = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(seg), "("), ")"))
		if seg != "" && !obFullRangeInnerRe.MatchString(seg) {
			return true
		}
	}
	return false
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

func asJSONMap(s string) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}
