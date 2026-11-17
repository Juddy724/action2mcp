package store

import (
	"action2mcp/internal/mwconfig"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type AuditEntry struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	Client  string `json:"client"`
	MW      string `json:"mw"`
	Tool    string `json:"tool"`
	Action  string `json:"action"`
	Perm    string `json:"perm"`
	Allowed bool   `json:"allowed"`
	Result  string `json:"result"`
	MS      int64  `json:"ms"`
}

func (s *Store) ListMiddleware() ([]*mwconfig.Middleware, error) {
	rows, err := s.db.Query(`SELECT id,name,type,config,created_at,updated_at FROM middleware ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*mwconfig.Middleware{}
	for rows.Next() {
		var m mwconfig.Middleware
		var cfg string
		rows.Scan(&m.ID, &m.Name, &m.Type, &cfg, &m.CreatedAt, &m.UpdatedAt)
		if decoded, err := mwconfig.DecodeMWConfig(cfg); err == nil {
			m.Config = decoded
		} else {
			json.Unmarshal([]byte(cfg), &m.Config)
		}
		m.Normalize()
		out = append(out, &m)
	}
	return out, nil
}

func (s *Store) GetMiddleware(id int64) (*mwconfig.Middleware, error) {
	all, err := s.ListMiddleware()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, errors.New("中间件不存在")
}

func (s *Store) GetMiddlewareByName(name string) (*mwconfig.Middleware, error) {
	all, _ := s.ListMiddleware()
	for _, m := range all {
		if m.Name == name {
			return m, nil
		}
	}
	return nil, errors.New("中间件不存在")
}

func (s *Store) SaveMiddleware(m *mwconfig.Middleware) error {
	if err := m.Normalize(); err != nil {
		return err
	}
	b, _ := json.Marshal(m.Config)
	ts := now()
	if m.ID == 0 {
		r, err := s.db.Exec(`INSERT INTO middleware(name,type,config,created_at,updated_at) VALUES(?,?,?,?,?)`, m.Name, m.Type, string(b), ts, ts)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("已经有名为「%s」的中间件了", m.Name)
			}
			return err
		}
		m.ID, _ = r.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE middleware SET name=?,type=?,config=?,updated_at=? WHERE id=?`, m.Name, m.Type, string(b), ts, m.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("已经有名为「%s」的中间件了", m.Name)
	}
	return err
}

func (s *Store) DeleteMiddleware(id int64) error {
	_, err := s.db.Exec(`DELETE FROM middleware WHERE id=?`, id)
	return err
}

// ExposedMiddleware returns middleware that belong to at least one enabled pack, with those pack names.
func (s *Store) ExposedMiddleware() ([]*mwconfig.Middleware, map[int64][]string) {
	all, _ := s.ListMiddleware()
	packs, _ := s.ListPacks()
	names := map[int64][]string{}
	for _, p := range packs {
		if !p.Enabled {
			continue
		}
		for _, id := range p.MiddlewareIDs {
			names[id] = append(names[id], p.Name)
		}
	}
	out := []*mwconfig.Middleware{}
	for _, m := range all {
		if len(names[m.ID]) > 0 {
			out = append(out, m)
		}
	}
	return out, names
}

func (s *Store) ListAudit(mw string, limit int) []AuditEntry {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows *sql.Rows
	var err error
	if mw != "" {
		rows, err = s.db.Query(`SELECT id,ts,client,mw,tool,action,perm,allowed,result,ms FROM mw_audit WHERE mw=? ORDER BY id DESC LIMIT ?`, mw, limit)
	} else {
		rows, err = s.db.Query(`SELECT id,ts,client,mw,tool,action,perm,allowed,result,ms FROM mw_audit ORDER BY id DESC LIMIT ?`, limit)
	}
	out := []AuditEntry{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		var al int
		rows.Scan(&e.ID, &e.TS, &e.Client, &e.MW, &e.Tool, &e.Action, &e.Perm, &al, &e.Result, &e.MS)
		e.Allowed = al != 0
		out = append(out, e)
	}
	return out
}

// AppendAudit stores one already-scrubbed/clipped audit row and keeps the newest 5000.
func (s *Store) AppendAudit(e AuditEntry) {
	s.db.Exec(`INSERT INTO mw_audit(ts,client,mw,tool,action,perm,allowed,result,ms) VALUES(?,?,?,?,?,?,?,?,?)`,
		now(), e.Client, e.MW, e.Tool, e.Action, e.Perm, b2i(e.Allowed), e.Result, e.MS)
	s.db.Exec(`DELETE FROM mw_audit WHERE id <= (SELECT MAX(id) FROM mw_audit) - 5000`)
}
