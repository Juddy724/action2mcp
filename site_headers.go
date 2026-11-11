package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

func credOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "wss":
		scheme = "https"
	case "ws":
		scheme = "http"
	case "http", "https":
	default:
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" || u.Scheme == "ws" {
			// already mapped scheme
		}
	} else if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		// Keep non-default ports. If Hostname() stripped brackets, JoinHostPort handles IPv6.
		if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
			return scheme + "://" + net.JoinHostPort(host, port)
		}
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

func headerNameKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func siteHeaderAD(origin, name string) string {
	return "site_header|" + origin + "|" + name
}

type harvestHop struct {
	origin     string
	generation int64
	url        string
}

type harvestState struct {
	mu      sync.Mutex
	gen     map[string]int64 // cred origin -> current generation
	pending map[string]harvestHop
}

func (a *App) ensureHarvest() *harvestState {
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.harvest == nil {
		a.harvest = &harvestState{gen: map[string]int64{}, pending: map[string]harvestHop{}}
	}
	return a.harvest
}

func (a *App) BeginHarvestGeneration(rawURL string) int64 {
	origin := credOrigin(rawURL)
	if origin == "" || a.store == nil {
		return 0
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	defer hs.mu.Unlock()
	var gen int64
	err := a.store.db.QueryRow(`INSERT INTO site_header_gens(origin, generation, started_at)
VALUES(?,1,?)
ON CONFLICT(origin) DO UPDATE SET generation=generation+1, started_at=excluded.started_at
RETURNING generation`, origin, now()).Scan(&gen)
	if err != nil {
		return 0
	}
	hs.gen[origin] = gen
	return gen
}

func (a *App) harvestGeneration(origin string) int64 {
	hs := a.ensureHarvest()
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if g, ok := hs.gen[origin]; ok {
		return g
	}
	var gen int64
	if a.store != nil {
		_ = a.store.db.QueryRow(`SELECT generation FROM site_header_gens WHERE origin=?`, origin).Scan(&gen)
	}
	hs.gen[origin] = gen
	return gen
}

func (a *App) InvalidateHarvestGeneration(rawURL string) {
	origin := credOrigin(rawURL)
	if origin == "" || a.store == nil {
		return
	}
	a.BeginHarvestGeneration(origin)
	// Bump again after a tombstone write so late events of the old gen cannot land.
}

func (a *App) TrackHarvestHop(requestKey, rawURL string) {
	origin := credOrigin(rawURL)
	if origin == "" || requestKey == "" {
		return
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.pending[requestKey] = harvestHop{origin: origin, generation: a.peekGenLocked(hs, origin), url: rawURL}
}

func (a *App) peekGenLocked(hs *harvestState, origin string) int64 {
	if g, ok := hs.gen[origin]; ok {
		return g
	}
	var gen int64
	if a.store != nil {
		_ = a.store.db.QueryRow(`SELECT generation FROM site_header_gens WHERE origin=?`, origin).Scan(&gen)
	}
	hs.gen[origin] = gen
	return gen
}

func (a *App) ForgetHarvestHop(requestKey string) {
	if requestKey == "" {
		return
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	delete(hs.pending, requestKey)
	hs.mu.Unlock()
}

// HarvestRequestHeader stores a credential request header if the hop is uniquely bound.
func (a *App) HarvestRequestHeader(requestKey, rawURL, name, value string) error {
	if a == nil || a.vault == nil || a.store == nil {
		return errors.New("本地密钥不可用")
	}
	name = headerNameKey(name)
	if name == "" || value == "" || name == "cookie" || name == "authorization" {
		return nil
	}
	if !IsCredHeader(name) {
		return nil
	}
	origin := credOrigin(rawURL)
	gen := a.harvestGeneration(origin)
	if requestKey != "" {
		hs := a.ensureHarvest()
		hs.mu.Lock()
		hop, ok := hs.pending[requestKey]
		hs.mu.Unlock()
		if !ok {
			// Extra-info first: remember only if we also have a URL for this key later.
			if rawURL == "" {
				return nil
			}
			a.TrackHarvestHop(requestKey, rawURL)
			hop = harvestHop{origin: origin, generation: gen, url: rawURL}
		} else {
			if rawURL != "" && credOrigin(rawURL) != hop.origin {
				// Cross-origin redirect extra header cannot be uniquely bound.
				return nil
			}
			origin = hop.origin
			gen = hop.generation
		}
	} else if origin == "" {
		return nil
	}
	if origin == "" {
		return nil
	}
	enc, err := a.vault.encryptAD(siteHeaderAD(origin, name), value)
	if err != nil {
		return err
	}
	_, err = a.store.db.Exec(`INSERT INTO site_headers(origin, name, value_enc, generation, updated_at)
VALUES(?,?,?,?,?)
ON CONFLICT(origin, name) DO UPDATE SET
 value_enc=CASE WHEN excluded.generation>=site_headers.generation THEN excluded.value_enc ELSE site_headers.value_enc END,
 generation=CASE WHEN excluded.generation>=site_headers.generation THEN excluded.generation ELSE site_headers.generation END,
 updated_at=CASE WHEN excluded.generation>=site_headers.generation THEN excluded.updated_at ELSE site_headers.updated_at END`,
		origin, name, enc, gen, now())
	return err
}

func (a *App) GetSiteHeader(rawURL, name string) (string, error) {
	if a == nil || a.vault == nil || a.store == nil {
		return "", errors.New("本地密钥不可用")
	}
	origin := credOrigin(rawURL)
	name = headerNameKey(name)
	if origin == "" || name == "" {
		return "", fmt.Errorf("站点缺少请求头 %s，请在登录中心登录该网站后再试", name)
	}
	var enc string
	var gen int64
	err := a.store.db.QueryRow(`SELECT value_enc, generation FROM site_headers WHERE origin=? AND name=?`, origin, name).Scan(&enc, &gen)
	if err == sql.ErrNoRows || (err == nil && enc == "") {
		return "", fmt.Errorf("站点缺少请求头 %s，请在登录中心登录该网站后再试", name)
	}
	if err != nil {
		return "", errors.New("无法读取站点请求头")
	}
	plain, err := a.vault.decryptAD(siteHeaderAD(origin, name), enc)
	if err != nil {
		return "", err
	}
	if plain == "" {
		return "", fmt.Errorf("站点缺少请求头 %s，请在登录中心登录该网站后再试", name)
	}
	return plain, nil
}

// SiteHeaderSecrets returns decrypted header values for secret matching. Fail closed on decrypt errors.
func (a *App) SiteHeaderSecrets(rawURL string) ([]string, error) {
	if a == nil || a.vault == nil || a.store == nil {
		return nil, errors.New("本地密钥不可用")
	}
	origin := credOrigin(rawURL)
	if origin == "" {
		return nil, nil
	}
	rows, err := a.store.db.Query(`SELECT name, value_enc FROM site_headers WHERE origin=?`, origin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, enc string
		if err := rows.Scan(&name, &enc); err != nil {
			return nil, err
		}
		plain, err := a.vault.decryptAD(siteHeaderAD(origin, name), enc)
		if err != nil {
			return nil, err
		}
		if plain != "" {
			out = append(out, plain)
		}
	}
	return out, rows.Err()
}

func (a *App) ClearSiteHeaders(rawURL string) error {
	origin := credOrigin(rawURL)
	if origin == "" || a.store == nil {
		return nil
	}
	if _, err := a.store.db.Exec(`DELETE FROM site_headers WHERE origin=?`, origin); err != nil {
		return err
	}
	a.BeginHarvestGeneration(origin)
	return nil
}

func (a *App) ClearAllSiteHeaders() error {
	if a.store == nil {
		return nil
	}
	if _, err := a.store.db.Exec(`DELETE FROM site_headers`); err != nil {
		return err
	}
	if _, err := a.store.db.Exec(`UPDATE site_header_gens SET generation=generation+1, started_at=?`, now()); err != nil {
		return err
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	hs.gen = map[string]int64{}
	hs.pending = map[string]harvestHop{}
	hs.mu.Unlock()
	return nil
}

func (s *Store) siteHeaderPlaintextExists(token string) bool {
	if token == "" {
		return false
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM site_headers WHERE instr(value_enc, ?)>0`, token).Scan(&n)
	return n > 0
}
