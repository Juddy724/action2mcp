package store

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	schemaVersionSQLConsole         = 8
	schemaVersionSQLConsoleEnv      = 9
	schemaVersionResultFull         = 10 // 0.5.9: approvals.result_full
	schemaVersionSQLConsoleApproval = 11
	schemaVersionResultPresentation = 12 // 0.5.12: result_format / detect_failure / op_kind in tools.config
	schemaUserVersion               = schemaVersionResultPresentation
)

func sqlConsoleNameFromTool(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "sql_console"
	}
	if strings.HasSuffix(name, "_sql_query") {
		return strings.TrimSuffix(name, "_query")
	}
	if strings.HasSuffix(name, "_query") {
		base := strings.TrimSuffix(name, "_query")
		if base != "" {
			return base
		}
	}
	return name
}

func collectTimeoutSec(cfg execution.ToolConfig) int {
	if cfg.Collect != nil && cfg.Collect.TimeoutMS > 0 {
		s := cfg.Collect.TimeoutMS / 1000
		if s < 1 {
			s = 1
		}
		return s
	}
	return 30
}

func collectMaxKB(cfg execution.ToolConfig) int {
	if cfg.Collect != nil && cfg.Collect.MaxBytes > 0 {
		kb := cfg.Collect.MaxBytes / 1024
		if kb < 1 {
			kb = 1
		}
		return kb
	}
	return 256
}

func lookupOrReserveSQLConsoleName(tx *sql.Tx, want, rawURL string) (id int64, reused bool, name string, err error) {
	for i := 0; i < 8; i++ {
		name = want
		if i > 0 {
			name = fmt.Sprintf("%s_%d", want, i+1)
		}
		var typ, cfg string
		var mid int64
		err = tx.QueryRow(`SELECT id,type,config FROM middleware WHERE name=?`, name).Scan(&mid, &typ, &cfg)
		if err == sql.ErrNoRows {
			return 0, false, name, nil
		}
		if err != nil {
			return 0, false, name, err
		}
		c, decErr := mwconfig.DecodeMWConfig(cfg)
		if decErr != nil {
			continue
		}
		if typ == "websocket" && c.IsSQLConsole() && strings.TrimSpace(c.URL) == strings.TrimSpace(rawURL) {
			return mid, true, name, nil
		}
	}
	return 0, false, want, fmt.Errorf("无法为中间件分配名称（%s 已被占用）", want)
}

// extractDatasourceFromMessages copies literal fixed fields onto one
// datasource (alias "default", description left empty for the user to fill):
// dsId, envId and envType go on the row; spaceCode and dbType go to
// middleware-level defaults. Those JSON paths are rewritten to {{ds.*}}
// placeholders. A missing envType becomes PROD.
func extractDatasourceFromMessages(messages []string, sqlPath string) (mwconfig.MWDatasource, mwconfig.MWSQLDefaults, []string, error) {
	ds := mwconfig.MWDatasource{Alias: "default"}
	var defaults mwconfig.MWSQLDefaults
	paths := mwconfig.DefaultDSFieldPaths()
	reverse := map[string]string{}
	for name, p := range paths {
		reverse[p] = name
	}
	out := make([]string, 0, len(messages))
	for _, tmpl := range messages {
		prefix, tail, ok := execution.SplitCommandJSON(tmpl)
		if !ok {
			out = append(out, tmpl)
			continue
		}
		dec := json.NewDecoder(strings.NewReader(tail))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return mwconfig.MWDatasource{}, mwconfig.MWSQLDefaults{}, nil, err
		}
		harvestFixedFields(&ds, &defaults, v, "", sqlPath, reverse)
		vals := ds.FieldValues(&mwconfig.MWConfig{SQLDefaults: defaults, Datasources: []mwconfig.MWDatasource{ds}})
		for name, path := range paths {
			if _, ok := vals[name]; ok {
				mwconfig.SetJSONPathCreate(&v, path, "{{ds."+name+"}}")
			}
		}
		for key := range ds.Fields {
			if strings.Contains(key, ".") {
				mwconfig.SetJSONPathCreate(&v, key, "{{ds."+key+"}}")
			}
		}
		out = append(out, strings.TrimRight(prefix, " ")+" "+string(execution.CompactJSON(v)))
	}
	if strings.TrimSpace(ds.EnvType) == "" {
		ds.EnvType = "PROD"
	}
	return ds, defaults, out, nil
}

func harvestFixedFields(ds *mwconfig.MWDatasource, defaults *mwconfig.MWSQLDefaults, v any, path, sqlPath string, reverse map[string]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if path != "" {
				p = path + "." + k
			}
			harvestFixedFields(ds, defaults, child, p, sqlPath, reverse)
		}
	case string:
		if path == "" || path == sqlPath || execution.BindingPlaceholder(x) || strings.Contains(x, "{{") {
			return
		}
		assignHarvestedField(ds, defaults, path, x, reverse)
	default:
		if path == "" || path == sqlPath {
			return
		}
		if s, ok := x.(string); ok && (execution.BindingPlaceholder(s) || strings.Contains(s, "{{")) {
			return
		}
		assignHarvestedField(ds, defaults, path, x, reverse)
	}
}

func assignHarvestedField(ds *mwconfig.MWDatasource, defaults *mwconfig.MWSQLDefaults, path string, val any, reverse map[string]string) {
	if mwconfig.IsEmptyJSONValue(val) {
		return
	}
	if name, ok := reverse[path]; ok {
		switch name {
		case "space_code":
			defaults.SpaceCode = fmt.Sprint(val)
		case "ds_id":
			ds.DSID = val
		case "env_id":
			ds.EnvID = val
		case "env_type":
			ds.EnvType = strings.TrimSpace(fmt.Sprint(val))
		case "db_type":
			defaults.DBType = fmt.Sprint(val)
		}
		return
	}
	if path == "token" || strings.HasSuffix(path, ".token") || strings.Contains(strings.ToLower(path), "token") || strings.Contains(strings.ToLower(path), "cookie") {
		return
	}
	if ds.Fields == nil {
		ds.Fields = map[string]any{}
	}
	ds.Fields[path] = val
}

func promoteSQLConsoleRowEnvTx(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id,type,config FROM middleware`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id     int64
		typ    string
		config string
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.typ, &r.config); err != nil {
			return err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	ts := now()
	for _, r := range list {
		if r.typ != "websocket" {
			continue
		}
		c, err := mwconfig.DecodeMWConfig(r.config)
		if err != nil || !c.IsSQLConsole() || !mwconfig.SQLConsoleEnvNeedsPromote(c) {
			continue
		}
		mwconfig.ApplySQLConsoleEnvPromotion(&c)
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE middleware SET config=?,updated_at=? WHERE id=?`, string(b), ts, r.id); err != nil {
			return err
		}
	}
	return nil
}

func applySQLConsoleApprovalDefaultTx(tx *sql.Tx) error {
	rows, err := tx.Query(`SELECT id,type,config FROM middleware`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type row struct {
		id     int64
		typ    string
		config string
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.typ, &r.config); err != nil {
			return err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	ts := now()
	for _, r := range list {
		if r.typ != "websocket" {
			continue
		}
		c, err := mwconfig.DecodeMWConfig(r.config)
		if err != nil || !c.IsSQLConsole() {
			continue
		}
		if strings.TrimSpace(c.Approval) != "" {
			continue
		}
		c.Approval = "always"
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE middleware SET config=?,updated_at=? WHERE id=?`, string(b), ts, r.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrateV8WSToolsToSQLMiddleware() error {
	var ver int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	if ver >= schemaVersionSQLConsole {
		return nil
	}
	_, err := s.convertWSToolsToSQLMiddleware(0)
	return err
}

// convertWSToolsToSQLMiddleware converts method=WS tools with an enabled SQL
// guard into sql_console middleware. toolID=0 converts all such tools (startup
// migration). It is idempotent and runs in one transaction.
func (s *Store) convertWSToolsToSQLMiddleware(toolID int64) ([]int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	ids, err := s.convertWSToolsTx(tx, toolID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) convertWSToolsTx(tx *sql.Tx, toolID int64) ([]int64, error) {
	q := `SELECT id,name,title,description,method,url,headers,body,params,COALESCE(config,'{}') FROM tools`
	args := []any{}
	if toolID > 0 {
		q += ` WHERE id=?`
		args = append(args, toolID)
	}
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type row struct {
		id                         int64
		name, title, desc, method  string
		url, headers, body, params string
		config                     string
	}
	var tools []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name, &r.title, &r.desc, &r.method, &r.url, &r.headers, &r.body, &r.params, &r.config); err != nil {
			return nil, err
		}
		if !execution.IsWSMethod(r.method) {
			continue
		}
		cfg, err := execution.ParseToolConfigJSON(r.config)
		if err != nil || !cfg.SqlGuardEnabled() {
			continue
		}
		tools = append(tools, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var created []int64
	for _, r := range tools {
		id, err := s.convertOneWSToolTx(tx, r.id, r.name, r.title, r.desc, r.url, r.headers, r.body, r.config)
		if err != nil {
			return nil, err
		}
		if id != 0 {
			created = append(created, id)
		}
	}
	return created, nil
}

func (s *Store) convertOneWSToolTx(tx *sql.Tx, toolID int64, name, title, desc, rawURL, headersJSON, body, configJSON string) (int64, error) {
	cfg, err := execution.ParseToolConfigJSON(configJSON)
	if err != nil {
		return 0, fmt.Errorf("工具 %s 的配置无法解析，已中止迁移", name)
	}
	cfg.ApplyDefaults()
	msgs := cfg.Messages
	if len(msgs) == 0 && strings.TrimSpace(body) != "" {
		msgs = []string{body}
	}
	ds, defaults, msgs, err := extractDatasourceFromMessages(msgs, cfg.SQLGuardPath())
	if err != nil {
		return 0, fmt.Errorf("工具 %s 无法抽取数据源字段：%w", name, err)
	}
	headers := map[string]string{}
	if strings.TrimSpace(headersJSON) != "" {
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return 0, fmt.Errorf("工具 %s 的请求头无法解析", name)
		}
	}
	mwconfig.NormalizeCookieHeaderBinding(headers)
	wantName := sqlConsoleNameFromTool(name)
	mwID, reused, wantName, err := lookupOrReserveSQLConsoleName(tx, wantName, rawURL)
	if err != nil {
		return 0, err
	}
	mw := &mwconfig.Middleware{ID: mwID, Name: wantName, Type: "websocket", Config: mwconfig.MWConfig{
		WSMode:      mwconfig.WSModeSQLConsole,
		URL:         rawURL,
		WSMessages:  msgs,
		WSHeaders:   headers,
		SQLPath:     cfg.SQLGuardPath(),
		Datasources: []mwconfig.MWDatasource{ds},
		SQLDefaults: defaults,
		MaxRows:     cfg.MaxRows(),
		TimeoutSec:  collectTimeoutSec(cfg),
		MaxResultKB: collectMaxKB(cfg),
		WSCollect:   cfg.Collect,
		WSAuth:      cfg.Auth,
		Description: strings.TrimSpace(desc),
		Perms:       map[string]bool{"select": true},
	}}
	if title != "" && mw.Config.Description == "" {
		mw.Config.Description = title
	}
	if err := mw.Normalize(); err != nil {
		return 0, fmt.Errorf("工具 %s 无法转换为中间件：%w", name, err)
	}
	b, err := json.Marshal(mw.Config)
	if err != nil {
		return 0, err
	}
	ts := now()
	if mw.ID == 0 {
		res, err := tx.Exec(`INSERT INTO middleware(name,type,config,created_at,updated_at) VALUES(?,?,?,?,?)`, mw.Name, mw.Type, string(b), ts, ts)
		if err != nil {
			return 0, err
		}
		mw.ID, _ = res.LastInsertId()
	} else if !reused {
		if _, err := tx.Exec(`UPDATE middleware SET name=?,type=?,config=?,updated_at=? WHERE id=?`, mw.Name, mw.Type, string(b), ts, mw.ID); err != nil {
			return 0, err
		}
	} else {
		// Already a matching sql_console middleware: keep its config, only move membership.
		_ = reused
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO pack_middleware(pack_id,mw_id) SELECT pack_id,? FROM pack_tools WHERE tool_id=?`, mw.ID, toolID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM pack_tools WHERE tool_id=?`, toolID); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM tools WHERE id=?`, toolID); err != nil {
		return 0, err
	}
	return mw.ID, nil
}

func (s *Store) ConvertToolToSQLMiddleware(id int64) (*mwconfig.Middleware, error) {
	if id <= 0 {
		return nil, errors.New("工具不存在")
	}
	ids, err := s.convertWSToolsToSQLMiddleware(id)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		// Maybe already converted: try by expected name from a missing tool.
		return nil, errors.New("这个工具不是带 SQL 护栏的 WebSocket 工具，或已经转换过了")
	}
	return s.GetMiddleware(ids[0])
}

func (s *Store) migrateV9SQLConsoleRowEnv() error {
	var ver int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	if ver >= schemaVersionSQLConsoleEnv {
		return nil
	}
	return s.promoteAllSQLConsoleRowEnv()
}

// promoteAllSQLConsoleRowEnv copies leftover middleware-level env_id / env_type
// onto datasource rows that are missing them, then drops those default keys.
// Idempotent and transactional.
func (s *Store) promoteAllSQLConsoleRowEnv() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := promoteSQLConsoleRowEnvTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) migrateV11SQLConsoleApproval() error {
	var ver int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	if ver >= schemaVersionSQLConsoleApproval {
		return nil
	}
	return s.applySQLConsoleApprovalDefault()
}

// applySQLConsoleApprovalDefault writes approval=always onto existing SQL
// console middleware that have no mode set yet. Already-set off/always are
// left alone. Other middleware types are not touched. Idempotent and transactional.
func (s *Store) applySQLConsoleApprovalDefault() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := applySQLConsoleApprovalDefaultTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}
