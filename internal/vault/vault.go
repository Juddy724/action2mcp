package vault

import (
	"action2mcp/internal/credential"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- 配置管理（vault） ----------
//
// Values are AES-GCM encrypted at rest with a random key kept in data/secret.key (0600).
// They are resolved server-side for {{cfg.NAME}} / {{secret.NAME}} placeholders and are
// never part of anything returned to the AI (schemas, results, errors), logs or exports.

type VaultItem struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`  // secret | plain
	Value     string `json:"value"` // plain: the value; secret: "" (use reveal)
	HasValue  bool   `json:"has_value"`
	Masked    string `json:"masked,omitempty"`
	Site      string `json:"site"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

const Mask = "******"

type Vault struct {
	db   *sql.DB
	aead cipher.AEAD

	mu    sync.RWMutex
	cache map[string]vaultEntry // name -> decrypted
}

type vaultEntry struct {
	typ, value, site string
}

func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("密钥文件 %s 已损坏（不要手动修改它）", filepath.Base(path))
		}
		if runtime.GOOS != "windows" {
			if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0o600 {
				os.Chmod(path, 0o600)
			}
		}
		return k, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func OpenVault(db *sql.DB, keyPath string) (*Vault, error) {
	k, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	v := &Vault{db: db, aead: aead}
	if err := v.reload(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *Vault) seal(name, plain string) string {
	nonce := make([]byte, v.aead.NonceSize())
	rand.Read(nonce)
	ct := v.aead.Seal(nil, nonce, []byte(plain), []byte(name))
	return "v1:" + base64.StdEncoding.EncodeToString(append(nonce, ct...))
}

func (v *Vault) open(name, enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, "v1:"))
	if err != nil || len(raw) < v.aead.NonceSize() {
		return "", errors.New("配置值无法解密")
	}
	ns := v.aead.NonceSize()
	pt, err := v.aead.Open(nil, raw[:ns], raw[ns:], []byte(name))
	if err != nil {
		return "", errors.New("配置值无法解密（secret.key 是否被替换？）")
	}
	return string(pt), nil
}

func (v *Vault) encryptAD(ad, plain string) (string, error) {
	if v == nil || v.aead == nil {
		return "", errors.New("本地密钥不可用")
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := v.aead.Seal(nil, nonce, []byte(plain), []byte(ad))
	return "v1:" + base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

func (v *Vault) decryptAD(ad, enc string) (string, error) {
	if v == nil || v.aead == nil {
		return "", errors.New("本地密钥不可用")
	}
	if enc == "" {
		return "", errors.New("站点请求头无法解密")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(enc, "v1:"))
	if err != nil || len(raw) < v.aead.NonceSize() {
		return "", errors.New("站点请求头无法解密")
	}
	ns := v.aead.NonceSize()
	pt, err := v.aead.Open(nil, raw[:ns], raw[ns:], []byte(ad))
	if err != nil {
		return "", errors.New("站点请求头无法解密（secret.key 是否被替换？）")
	}
	return string(pt), nil
}

func (v *Vault) reload() error {
	rows, err := v.db.Query(`SELECT name,type,value_enc,site FROM vault`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]vaultEntry{}
	for rows.Next() {
		var n, t, e, s string
		rows.Scan(&n, &t, &e, &s)
		pv, err := v.open(n, e)
		if err != nil {
			continue
		}
		m[n] = vaultEntry{typ: t, value: pv, site: s}
	}
	v.mu.Lock()
	v.cache = m
	v.mu.Unlock()
	return nil
}

func maskOf(s string) string {
	if s == "" {
		return ""
	}
	return Mask
}

// List returns all items; secret values are never included.
func (v *Vault) List() []VaultItem {
	rows, err := v.db.Query(`SELECT id,name,type,site,note,created_at,updated_at FROM vault ORDER BY site,name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []VaultItem{}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for rows.Next() {
		var it VaultItem
		rows.Scan(&it.ID, &it.Name, &it.Type, &it.Site, &it.Note, &it.CreatedAt, &it.UpdatedAt)
		e := v.cache[it.Name]
		it.HasValue = e.value != ""
		if it.Type == "plain" {
			it.Value = e.value
		} else {
			it.Masked = maskOf(e.value)
		}
		out = append(out, it)
	}
	return out
}

func (v *Vault) GetByID(id int64) (*VaultItem, error) {
	for _, it := range v.List() {
		if it.ID == id {
			return &it, nil
		}
	}
	return nil, errors.New("配置项不存在")
}

// Reveal returns the plain value of one item (console only, localhost only).
func (v *Vault) Reveal(id int64) (string, error) {
	it, err := v.GetByID(id)
	if err != nil {
		return "", err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cache[it.Name].value, nil
}

// Save creates or updates an item. For updates an empty value with keepValue keeps the old one.
func (v *Vault) Save(it *VaultItem, value string, keepValue bool) error {
	it.Name = strings.TrimSpace(it.Name)
	if !credential.ValidName(it.Name) {
		return errors.New("配置名只能包含英文字母、数字和下划线（最长 64 位），例如 zentao_password")
	}
	if it.Type != "plain" {
		it.Type = "secret"
	}
	it.Site = credential.NormalizeOrigin(it.Site)
	if !keepValue && value != "" {
		it.Note = strings.TrimSpace(strings.ReplaceAll(it.Note, "（待填写）", ""))
	}
	ts := vaultNow()
	if it.ID == 0 {
		var exists int
		v.db.QueryRow(`SELECT COUNT(*) FROM vault WHERE name=?`, it.Name).Scan(&exists)
		if exists > 0 {
			return fmt.Errorf("已经有名为 %s 的配置项了", it.Name)
		}
		r, err := v.db.Exec(`INSERT INTO vault(name,type,value_enc,site,note,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
			it.Name, it.Type, v.seal(it.Name, value), it.Site, it.Note, ts, ts)
		if err != nil {
			return err
		}
		it.ID, _ = r.LastInsertId()
	} else {
		var oldName, oldEnc string
		if err := v.db.QueryRow(`SELECT name,value_enc FROM vault WHERE id=?`, it.ID).Scan(&oldName, &oldEnc); err != nil {
			return errors.New("配置项不存在")
		}
		if keepValue && value == "" {
			pv, _ := v.open(oldName, oldEnc)
			value = pv
		}
		if _, err := v.db.Exec(`UPDATE vault SET name=?,type=?,value_enc=?,site=?,note=?,updated_at=? WHERE id=?`,
			it.Name, it.Type, v.seal(it.Name, value), it.Site, it.Note, ts, it.ID); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("已经有名为 %s 的配置项了", it.Name)
			}
			return err
		}
	}
	return v.reload()
}

// Upsert sets a value by name (used when saving a recorded login).
func (v *Vault) Upsert(name, typ, value, site, note string) error {
	var id int64
	v.db.QueryRow(`SELECT id FROM vault WHERE name=?`, name).Scan(&id)
	it := &VaultItem{ID: id, Name: name, Type: typ, Site: site, Note: note}
	if id != 0 {
		// keep the existing note if none given
		if note == "" {
			v.db.QueryRow(`SELECT note FROM vault WHERE id=?`, id).Scan(&it.Note)
		}
	}
	return v.Save(it, value, false)
}

// EnsureName creates an empty placeholder item (used by import) if it does not exist yet.
func (v *Vault) EnsureName(name, typ, site, note string) bool {
	if _, ok := v.Lookup(name); ok || !credential.ValidName(name) {
		return false
	}
	var n int
	v.db.QueryRow(`SELECT COUNT(*) FROM vault WHERE name=?`, name).Scan(&n)
	if n > 0 {
		return false
	}
	return v.Save(&VaultItem{Name: name, Type: typ, Site: site, Note: note}, "", false) == nil
}

func (v *Vault) Delete(id int64) error {
	_, err := v.db.Exec(`DELETE FROM vault WHERE id=?`, id)
	v.reload()
	return err
}

// Lookup returns the value by name.
func (v *Vault) Lookup(name string) (string, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	e, ok := v.cache[name]
	if !ok {
		return "", false
	}
	return e.value, true
}

func (v *Vault) TypeOf(name string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.cache[name].typ
}

// ForSite returns item names bound to a site origin.
func (v *Vault) ForSite(origin string) map[string]SiteValue {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := map[string]SiteValue{}
	for n, e := range v.cache {
		if e.site != "" && credential.SameSite(e.site, origin) {
			out[n] = SiteValue{Type: e.typ, Value: e.value}
		}
	}
	return out
}

// FindByValue returns the name of a secret item holding exactly this value.
func (v *Vault) FindByValue(val string) string {
	if val == "" {
		return ""
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	names := []string{}
	for n, e := range v.cache {
		if e.value == val {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

// Resolve implements {{cfg.NAME}} / {{secret.NAME}}.
func (v *Vault) Resolve(ref string) (string, error) {
	_, name, _ := strings.Cut(ref, ".")
	val, ok := v.Lookup(name)
	if !ok {
		return "", fmt.Errorf("配置项「%s」不存在，请在控制台「配置管理」里添加", name)
	}
	if val == "" {
		return "", fmt.Errorf("配置项「%s」还没有填写值，请在控制台「配置管理」里填写", name)
	}
	return val, nil
}

// secretVariants lists every secret value (and common encodings) for scrubbing, longest first.
func (v *Vault) SecretVariants() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	set := map[string]bool{}
	for _, e := range v.cache {
		// Generic Scrub keeps the conservative pre-0.5.1 threshold; the recording
		// analysis path filters these variants with crossFieldLiteral itself.
		if e.typ != "secret" || len(e.value) < 3 {
			continue
		}
		s := e.value
		jb, _ := json.Marshal(s)
		for _, x := range []string{s, url.QueryEscape(s), url.PathEscape(s), strings.Trim(string(jb), `"`), html.EscapeString(s),
			base64.StdEncoding.EncodeToString([]byte(s))} {
			if len(x) >= 3 {
				set[x] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for x := range set {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// Scrub replaces any secret value in s with ******. Encoding-aware forms
// (URL, JSON, HTML, standard and URL-safe base64, with or without padding)
// are matched as substrings so AI-visible text cannot leak a known secret.
func (v *Vault) Scrub(s string) string {
	return ScrubSecretText(s, v, nil)
}

// ToRefs replaces raw secret values inside a template with {{secret.NAME}} so they are never stored in a tool.
func (v *Vault) ToRefs(s string) string {
	if v == nil || s == "" {
		return s
	}
	v.mu.RLock()
	type pair struct{ val, name string }
	ps := []pair{}
	for n, e := range v.cache {
		if e.typ == "secret" && len(e.value) >= 3 {
			ps = append(ps, pair{e.value, n})
			if q := url.QueryEscape(e.value); q != e.value {
				ps = append(ps, pair{q, n})
			}
		}
	}
	v.mu.RUnlock()
	sort.Slice(ps, func(i, j int) bool { return len(ps[i].val) > len(ps[j].val) })
	for _, p := range ps {
		s = strings.ReplaceAll(s, p.val, "{{secret."+p.name+"}}")
	}
	return s
}

// SiteValue is a copied credential binding, not a reference to the vault cache.
type SiteValue struct {
	Type  string
	Value string
}

// SecretValues returns an isolated snapshot for recording-template substitution.
// It never exposes the cache, lock, encryption key or plain configuration values.
func (v *Vault) SecretValues() map[string]string {
	out := map[string]string{}
	if v == nil {
		return out
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for name, e := range v.cache {
		if e.typ == "secret" && e.value != "" {
			out[name] = e.value
		}
	}
	return out
}

func (v *Vault) EncryptSiteHeader(origin, name, value string) (string, error) {
	return v.encryptAD(siteHeaderAD(origin, name), value)
}

func (v *Vault) DecryptSiteHeader(origin, name, encrypted string) (string, error) {
	return v.decryptAD(siteHeaderAD(origin, name), encrypted)
}

func vaultNow() string { return time.Now().Format("2006-01-02 15:04:05") }
