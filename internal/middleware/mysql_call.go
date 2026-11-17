package middleware

import (
	"context"
	"fmt"
	"strings"
)

func (a *Drivers) testMySQL(ctx context.Context, m *Target) (string, error) {
	db, err := a.mysqlDB(m)
	if err != nil {
		return "", err
	}
	var ver string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&ver); err != nil {
		a.Drop(m.ID)
		return "", err
	}
	return "连接成功，数据库版本 " + ver, nil
}

func (a *Drivers) callDB(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	var sqlText string
	switch c.tool {
	case "db_query":
		sqlText = argStr(args, "sql")
	case "db_list_tables":
		db := strings.TrimSpace(argStr(args, "database"))
		if db == "" {
			db = c.m.Config.Database
		}
		if db == "" {
			sqlText = "SHOW TABLES"
		} else {
			sqlText = "SHOW TABLES FROM " + quoteIdent(db)
		}
	case "db_describe_table":
		t := strings.TrimSpace(argStr(args, "table"))
		if t == "" {
			return "请提供表名", true
		}
		if d, n, ok := strings.Cut(t, "."); ok {
			sqlText = "SHOW COLUMNS FROM " + quoteIdent(d) + "." + quoteIdent(n)
		} else {
			sqlText = "SHOW COLUMNS FROM " + quoteIdent(t)
		}
	}
	c.action = sqlText
	plan, err := classifySQL(sqlText, &c.m.Config)
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "无权限") {
			msg = fmt.Sprintf("无权限：中间件「%s」%s", c.m.Name, strings.TrimPrefix(msg, "无权限："))
		}
		return c.blocked(msg), true
	}
	if msg, ok := c.need(plan.Perms...); !ok {
		return msg, true
	}
	var params []any
	if ps, ok := args["params"].([]any); ok {
		for _, p := range ps {
			switch x := p.(type) {
			case map[string]any, []any:
				params = append(params, jsonText(x))
			default:
				params = append(params, x)
			}
		}
	}
	res, err := a.runSQL(ctx, c.m, plan, params)
	if err != nil {
		return c.done("", err)
	}
	if c.tool == "db_list_tables" && len(c.m.Config.AllowedTables) > 0 {
		db := strings.TrimSpace(argStr(args, "database"))
		if db == "" {
			db = c.m.Config.Database
		}
		kept := [][]any{}
		for _, r := range res.Rows {
			if len(r) > 0 && c.m.Config.checkTable(db, fmt.Sprint(r[0])) == nil {
				kept = append(kept, r)
			}
		}
		res.Rows, res.RowCount = kept, len(kept)
	}
	return c.done(jsonText(res), nil)
}
