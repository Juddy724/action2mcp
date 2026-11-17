package login

import (
	"action2mcp/internal/credential"
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

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

func (a *Service) ensureHarvest() *harvestState {
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.harvest == nil {
		a.harvest = &harvestState{gen: map[string]int64{}, pending: map[string]harvestHop{}}
	}
	return a.harvest
}

func (a *Service) BeginHarvestGeneration(rawURL string) int64 {
	origin := credential.Origin(rawURL)
	if origin == "" || a.db == nil {
		return 0
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	defer hs.mu.Unlock()
	var gen int64
	err := a.db.QueryRow(`INSERT INTO site_header_gens(origin, generation, started_at)
VALUES(?,1,?)
ON CONFLICT(origin) DO UPDATE SET generation=generation+1, started_at=excluded.started_at
RETURNING generation`, origin, now()).Scan(&gen)
	if err != nil {
		return 0
	}
	hs.gen[origin] = gen
	return gen
}

func (a *Service) harvestGeneration(origin string) int64 {
	hs := a.ensureHarvest()
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if g, ok := hs.gen[origin]; ok {
		return g
	}
	var gen int64
	if a.db != nil {
		_ = a.db.QueryRow(`SELECT generation FROM site_header_gens WHERE origin=?`, origin).Scan(&gen)
	}
	hs.gen[origin] = gen
	return gen
}

func (a *Service) InvalidateHarvestGeneration(rawURL string) {
	origin := credential.Origin(rawURL)
	if origin == "" || a.db == nil {
		return
	}
	a.BeginHarvestGeneration(origin)
	// Bump again after a tombstone write so late events of the old gen cannot land.
}

func (a *Service) TrackHarvestHop(requestKey, rawURL string) {
	origin := credential.Origin(rawURL)
	if origin == "" || requestKey == "" {
		return
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.pending[requestKey] = harvestHop{origin: origin, generation: a.peekGenLocked(hs, origin), url: rawURL}
}

func (a *Service) peekGenLocked(hs *harvestState, origin string) int64 {
	if g, ok := hs.gen[origin]; ok {
		return g
	}
	var gen int64
	if a.db != nil {
		_ = a.db.QueryRow(`SELECT generation FROM site_header_gens WHERE origin=?`, origin).Scan(&gen)
	}
	hs.gen[origin] = gen
	return gen
}

func (a *Service) ForgetHarvestHop(requestKey string) {
	if requestKey == "" {
		return
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	delete(hs.pending, requestKey)
	hs.mu.Unlock()
}

// HarvestRequestHeader stores a credential request header if the hop is uniquely bound.
func (a *Service) HarvestRequestHeader(requestKey, rawURL, name, value string) error {
	if a == nil || a.vault == nil || a.db == nil {
		return errors.New("本地密钥不可用")
	}
	name = credential.HeaderKey(name)
	if name == "" || value == "" || name == "cookie" || name == "authorization" {
		return nil
	}
	if !credential.IsCredHeader(name) {
		return nil
	}
	origin := credential.Origin(rawURL)
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
			if rawURL != "" && credential.Origin(rawURL) != hop.origin {
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
	enc, err := a.vault.EncryptSiteHeader(origin, name, value)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`INSERT INTO site_headers(origin, name, value_enc, generation, updated_at)
VALUES(?,?,?,?,?)
ON CONFLICT(origin, name) DO UPDATE SET
 value_enc=CASE WHEN excluded.generation>=site_headers.generation THEN excluded.value_enc ELSE site_headers.value_enc END,
 generation=CASE WHEN excluded.generation>=site_headers.generation THEN excluded.generation ELSE site_headers.generation END,
 updated_at=CASE WHEN excluded.generation>=site_headers.generation THEN excluded.updated_at ELSE site_headers.updated_at END`,
		origin, name, enc, gen, now())
	return err
}

func (a *Service) GetSiteHeader(rawURL, name string) (string, error) {
	if a == nil || a.vault == nil || a.db == nil {
		return "", errors.New("本地密钥不可用")
	}
	origin := credential.Origin(rawURL)
	name = credential.HeaderKey(name)
	if origin == "" || name == "" {
		return "", fmt.Errorf("站点缺少请求头 %s，请在登录中心登录该网站后再试", name)
	}
	var enc string
	var gen int64
	err := a.db.QueryRow(`SELECT value_enc, generation FROM site_headers WHERE origin=? AND name=?`, origin, name).Scan(&enc, &gen)
	if err == sql.ErrNoRows || (err == nil && enc == "") {
		return "", fmt.Errorf("站点缺少请求头 %s，请在登录中心登录该网站后再试", name)
	}
	if err != nil {
		return "", errors.New("无法读取站点请求头")
	}
	plain, err := a.vault.DecryptSiteHeader(origin, name, enc)
	if err != nil {
		return "", err
	}
	if plain == "" {
		return "", fmt.Errorf("站点缺少请求头 %s，请在登录中心登录该网站后再试", name)
	}
	return plain, nil
}

// SiteHeaderSecrets returns decrypted header values for secret matching. Fail closed on decrypt errors.
func (a *Service) SiteHeaderSecrets(rawURL string) ([]string, error) {
	if a == nil || a.vault == nil || a.db == nil {
		return nil, errors.New("本地密钥不可用")
	}
	origin := credential.Origin(rawURL)
	if origin == "" {
		return nil, nil
	}
	rows, err := a.db.Query(`SELECT name, value_enc FROM site_headers WHERE origin=?`, origin)
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
		plain, err := a.vault.DecryptSiteHeader(origin, name, enc)
		if err != nil {
			return nil, err
		}
		if plain != "" {
			out = append(out, plain)
		}
	}
	return out, rows.Err()
}

func (a *Service) ClearSiteHeaders(rawURL string) error {
	origin := credential.Origin(rawURL)
	if origin == "" || a.db == nil {
		return nil
	}
	if _, err := a.db.Exec(`DELETE FROM site_headers WHERE origin=?`, origin); err != nil {
		return err
	}
	a.BeginHarvestGeneration(origin)
	return nil
}

func (a *Service) ClearAllSiteHeaders() error {
	if a.db == nil {
		return nil
	}
	if _, err := a.db.Exec(`DELETE FROM site_headers`); err != nil {
		return err
	}
	if _, err := a.db.Exec(`UPDATE site_header_gens SET generation=generation+1, started_at=?`, now()); err != nil {
		return err
	}
	hs := a.ensureHarvest()
	hs.mu.Lock()
	hs.gen = map[string]int64{}
	hs.pending = map[string]harvestHop{}
	hs.mu.Unlock()
	return nil
}
