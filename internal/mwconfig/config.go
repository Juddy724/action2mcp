package mwconfig

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/execution"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type MWConfig struct {
	Host          string                     `json:"host"`
	Port          int                        `json:"port"`
	User          string                     `json:"user"`
	PasswordRef   string                     `json:"password_ref"` // name of a secret in 配置管理 (never the value)
	Database      string                     `json:"database"`     // MySQL default db / Redis db index / RabbitMQ vhost
	Addrs         string                     `json:"addrs"`        // Kafka brokers / RocketMQ namesrv / Redis cluster nodes / sentinels (comma separated)
	MQKind        string                     `json:"mq_kind"`      // rocketmq | kafka | rabbitmq
	RedisMode     string                     `json:"redis_mode"`   // standalone | cluster | sentinel
	MasterName    string                     `json:"master_name"`
	TLS           bool                       `json:"tls"`
	TLSSkipVerify bool                       `json:"tls_skip_verify"`
	SASL          string                     `json:"sasl"`        // Kafka: PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
	BrokerAddr    string                     `json:"broker_addr"` // RocketMQ broker used for creating topics
	Perms         map[string]bool            `json:"perms"`
	AllowedDBs    []string                   `json:"allowed_dbs"`
	AllowedTables []string                   `json:"allowed_tables"`
	KeyPrefixes   []string                   `json:"key_prefixes"`
	Topics        []string                   `json:"topics"`
	URL           string                     `json:"url,omitempty"`         // WebSocket address template, wss://…
	WSMessages    []string                   `json:"ws_messages,omitempty"` // text frames; {{command}} or {{sql}}
	CommandAllow  []string                   `json:"command_allow"`         // pod_exec allowlist, applied to each pipeline stage; empty = unrestricted. No omitempty: [] must survive a save.
	MaxRows       int                        `json:"max_rows"`
	MaxResultKB   int                        `json:"max_result_kb"`
	TimeoutSec    int                        `json:"timeout_sec"`
	RequireWhere  *bool                      `json:"require_where,omitempty"`
	Description   string                     `json:"description"`
	WSMode        string                     `json:"ws_mode,omitempty"`  // terminal (default) | sql_console
	Approval      string                     `json:"approval,omitempty"` // sql_console only: off | always (default always)
	SQLPath       string                     `json:"sql_path,omitempty"`
	WSHeaders     map[string]string          `json:"ws_headers,omitempty"`
	Datasources   []MWDatasource             `json:"datasources,omitempty"`
	DSFieldPaths  map[string]string          `json:"ds_field_paths,omitempty"`
	SQLDefaults   MWSQLDefaults              `json:"sql_defaults"`
	WSCollect     *execution.WSCollectConfig `json:"ws_collect,omitempty"`
	WSAuth        *execution.WSAuthConfig    `json:"ws_auth,omitempty"`
}

type Middleware struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"` // mysql | redis | mq
	Config    MWConfig `json:"config"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`

	pwOverride *string // console "测试连接" with a typed, not yet saved password
}

type permDef struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
	Hint    string `json:"hint"`
}

var MWPermDefs = map[string][]permDef{
	"mysql": {
		{"select", "查", true, "SELECT / SHOW / DESCRIBE / EXPLAIN"},
		{"insert", "增", false, "INSERT / REPLACE"},
		{"update", "改", false, "UPDATE、SELECT … FOR UPDATE、REPLACE 和 ON DUPLICATE KEY UPDATE"},
		{"delete", "删", false, "DELETE / TRUNCATE"},
		{"ddl", "DDL", false, "CREATE / ALTER / DROP 表、索引、视图、库"},
	},
	"redis": {
		{"read", "读", true, "GET / HGETALL / LRANGE / SCAN 等"},
		{"write", "写", false, "SET / HSET / LPUSH / EXPIRE 等"},
		{"delete", "删", false, "DEL / HDEL / LPOP / SREM 等"},
		{"script", "脚本", false, "EVAL / EVALSHA（脚本可以访问任意 key，谨慎开启）"},
	},
	"mq": {
		{"consume", "查看消息", true, "列出 Topic、查看最近的消息（不提交消费位点）"},
		{"send", "发送", false, "向 Topic / 队列发送消息"},
		{"admin", "管理", false, "创建 Topic / 队列"},
	},
	"websocket": {
		{"log", "查日志", true, "pod_read_log：只执行 tail 查看文件末尾"},
		{"exec", "执行命令", false, "pod_exec：在远端 shell 执行命令。开启后还受「允许的命令」约束，管道的每一段也要在列表里；留空则不限制"},
	},
}

var MWSQLConsolePerms = []permDef{
	{"select", "查", true, "ws_sql_query：只读 SELECT，必须带 LIMIT、必须走索引、最多 200 行"},
	{"describe", "查表结构", false, "ws_sql_query：DESCRIBE / DESC / SHOW [FULL] COLUMNS / SHOW INDEX / SHOW CREATE TABLE"},
	{"list_tables", "查表列表", false, "ws_sql_query：SHOW [FULL] TABLES [FROM db] [LIKE '...']，列出数据库中的表名"},
}

func MWPermsOf(m *Middleware) []permDef {
	if m != nil && m.Type == "websocket" && m.Config.IsSQLConsole() {
		return MWSQLConsolePerms
	}
	if m != nil {
		return MWPermDefs[m.Type]
	}
	return nil
}

var MWTypeLabel = map[string]string{"mysql": "MySQL / OceanBase", "redis": "Redis", "mq": "消息队列", "websocket": "WebSocket"}

var MQKindLabel = map[string]string{"rocketmq": "RocketMQ", "kafka": "Kafka", "rabbitmq": "RabbitMQ"}

func PermLabel(typ, key string) string {
	for _, d := range MWPermDefs[typ] {
		if d.Key == key {
			return d.Label
		}
	}
	for _, d := range MWSQLConsolePerms {
		if d.Key == key {
			return d.Label
		}
	}
	return key
}

var mwNameRe = regexp.MustCompile(`^[\p{L}\p{N}_\-\.]{1,40}$`)

func cleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '，' || r == ' ' }) {
			p = strings.TrimSpace(p)
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// cleanLines keeps non-empty lines. Unlike cleanList it does not split on commas or spaces,
// so a JSON frame stays intact.
func cleanLines(in []string) []string {
	out := []string{}
	for _, s := range in {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

func joinHostPort(h string, p int) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]:" + strconv.Itoa(p)
	}
	return h + ":" + strconv.Itoa(p)
}

func (c *MWConfig) EffectiveMaxRows() int {
	if c.MaxRows <= 0 {
		return 200
	}
	if c.MaxRows > 10000 {
		return 10000
	}
	return c.MaxRows
}

func (c *MWConfig) EffectiveMaxResultBytes() int {
	if c.MaxResultKB <= 0 {
		return 256 * 1024
	}
	if c.MaxResultKB > 8192 {
		return 8192 * 1024
	}
	return c.MaxResultKB * 1024
}

func (c *MWConfig) EffectiveTimeoutSec() int {
	if c.TimeoutSec <= 0 {
		return 15
	}
	if c.TimeoutSec > 300 {
		return 300
	}
	return c.TimeoutSec
}

func (c *MWConfig) requireWhereEnabled() bool { return c.RequireWhere == nil || *c.RequireWhere }

func (m *Middleware) KindLabel() string {
	if m.Type == "websocket" && m.Config.IsSQLConsole() {
		return "WebSocket · SQL 控制台"
	}
	if m.Type == "mq" {
		return MQKindLabel[m.Config.MQKind]
	}
	return MWTypeLabel[m.Type]
}

// normalize validates and fills defaults.
func (m *Middleware) Normalize() error {
	m.Name = strings.TrimSpace(m.Name)
	if !mwNameRe.MatchString(m.Name) {
		return errors.New("中间件名称只能包含中文、字母、数字、下划线、短横线和点（最长 40 个字），例如「订单库」")
	}
	if _, ok := MWPermDefs[m.Type]; !ok {
		return errors.New("中间件类型必须是 mysql、redis、mq 或 websocket")
	}
	if m.Type == "websocket" {
		mode := strings.TrimSpace(m.Config.WSMode)
		if mode != "" && mode != WSModeTerminal && mode != WSModeSQLConsole {
			return errors.New("WebSocket 模式只能是 terminal（终端）或 sql_console（SQL 控制台）")
		}
	}
	if m.Type != "websocket" || !m.Config.IsSQLConsole() {
		m.Config.Approval = ""
	}
	c := &m.Config
	c.Host = strings.TrimSpace(c.Host)
	c.User = strings.TrimSpace(c.User)
	c.Database = strings.TrimSpace(c.Database)
	c.Addrs = strings.Join(cleanList([]string{c.Addrs}), ",")
	c.AllowedDBs = cleanList(c.AllowedDBs)
	c.AllowedTables = cleanList(c.AllowedTables)
	c.KeyPrefixes = cleanList(c.KeyPrefixes)
	c.Topics = cleanList(c.Topics)
	if c.PasswordRef != "" && !credential.ValidName(c.PasswordRef) {
		return errors.New("密码引用的配置名无效")
	}
	if c.Perms == nil {
		c.Perms = map[string]bool{}
	}
	clean := map[string]bool{}
	for _, d := range MWPermsOf(m) {
		v, ok := c.Perms[d.Key]
		if !ok {
			v = d.Default
		}
		clean[d.Key] = v
	}
	c.Perms = clean
	switch m.Type {
	case "mysql":
		if c.Host == "" {
			return errors.New("请填写数据库地址")
		}
		if c.Port == 0 {
			c.Port = 3306
		}
	case "redis":
		if c.RedisMode == "" {
			c.RedisMode = "standalone"
		}
		if c.RedisMode != "standalone" && c.RedisMode != "cluster" && c.RedisMode != "sentinel" {
			return errors.New("Redis 模式只能是 standalone / cluster / sentinel")
		}
		if c.RedisMode == "standalone" && c.Host == "" {
			return errors.New("请填写 Redis 地址")
		}
		if c.RedisMode != "standalone" && c.Addrs == "" {
			return errors.New("集群 / 哨兵模式请填写节点地址列表")
		}
		if c.RedisMode == "sentinel" && c.MasterName == "" {
			return errors.New("哨兵模式请填写 master 名称")
		}
		if c.Port == 0 {
			c.Port = 6379
		}
		if c.Database != "" {
			var n int
			if _, err := fmt.Sscanf(c.Database, "%d", &n); err != nil || n < 0 || n > 255 {
				return errors.New("Redis 库编号必须是 0-255 的数字")
			}
		}
	case "mq":
		if _, ok := MQKindLabel[c.MQKind]; !ok {
			return errors.New("请选择消息队列类型：RocketMQ / Kafka / RabbitMQ")
		}
		switch c.MQKind {
		case "rabbitmq":
			if c.Host == "" {
				return errors.New("请填写 RabbitMQ 地址")
			}
			if c.Port == 0 {
				c.Port = 5672
				if c.TLS {
					c.Port = 5671
				}
			}
		default:
			if c.Addrs == "" && c.Host != "" {
				p := c.Port
				if p == 0 {
					p = map[string]int{"rocketmq": 9876, "kafka": 9092}[c.MQKind]
				}
				c.Addrs = joinHostPort(c.Host, p)
			}
			if c.Addrs == "" {
				return errors.New(map[string]string{"rocketmq": "请填写 NameServer 地址", "kafka": "请填写 Broker 地址"}[c.MQKind])
			}
		}
	case "websocket":
		if c.IsSQLConsole() {
			return NormalizeSQLConsole(m)
		}
		c.URL = strings.TrimSpace(c.URL)
		if c.URL == "" {
			return errors.New("请填写 WebSocket 地址")
		}
		if !strings.HasPrefix(c.URL, "ws://") && !strings.HasPrefix(c.URL, "wss://") {
			return errors.New("WebSocket 地址必须以 ws:// 或 wss:// 开头")
		}
		c.WSMessages = cleanLines(c.WSMessages)
		if len(c.WSMessages) == 0 {
			c.WSMessages = defaultWSMessages()
		}
		if !strings.Contains(strings.Join(c.WSMessages, "\n"), "{{command}}") {
			return errors.New("发送的文本帧里要有 {{command}}，调用时会替换成要执行的命令")
		}
		if c.CommandAllow == nil {
			c.CommandAllow = []string{"tail", "head", "ls", "cat", "grep", "sed", "pwd"}
		} else {
			c.CommandAllow = cleanList(c.CommandAllow)
		}
		if c.TimeoutSec <= 0 {
			c.TimeoutSec = 30
		}
	}
	return nil
}

// OverridePassword attaches a typed, unsaved console password for one connection test.
// The override is never serialized and does not change the stored PasswordRef.
func (m *Middleware) OverridePassword(pw string) { m.pwOverride = &pw }

// PasswordOverride reports the unsaved console test password, if one was supplied.
func (m *Middleware) PasswordOverride() (string, bool) {
	if m.pwOverride == nil {
		return "", false
	}
	return *m.pwOverride, true
}

func NewSecretName() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "mw_" + hex.EncodeToString(b) + "_password"
}
