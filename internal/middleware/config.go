package middleware

import (
	"encoding/json"
	"fmt"
)

// Config is the native-driver connection and policy snapshot, not a persistence model.
type Config struct {
	Host          string          `json:"host"`
	Port          int             `json:"port"`
	User          string          `json:"user"`
	PasswordRef   string          `json:"password_ref"` // name of a secret in 配置管理 (never the value)
	Database      string          `json:"database"`     // MySQL default db / Redis db index / RabbitMQ vhost
	Addrs         string          `json:"addrs"`        // Kafka brokers / RocketMQ namesrv / Redis cluster nodes / sentinels (comma separated)
	MQKind        string          `json:"mq_kind"`      // rocketmq | kafka | rabbitmq
	RedisMode     string          `json:"redis_mode"`   // standalone | cluster | sentinel
	MasterName    string          `json:"master_name"`
	TLS           bool            `json:"tls"`
	TLSSkipVerify bool            `json:"tls_skip_verify"`
	SASL          string          `json:"sasl"`        // Kafka: PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
	BrokerAddr    string          `json:"broker_addr"` // RocketMQ broker used for creating topics
	Perms         map[string]bool `json:"perms"`
	AllowedDBs    []string        `json:"allowed_dbs"`
	AllowedTables []string        `json:"allowed_tables"`
	KeyPrefixes   []string        `json:"key_prefixes"`
	Topics        []string        `json:"topics"`
	MaxRows       int
	MaxResultKB   int
	TimeoutSec    int
	RequireWhere  *bool
}

func (c *Config) maxRows() int {
	if c.MaxRows <= 0 {
		return 200
	}
	if c.MaxRows > 10000 {
		return 10000
	}
	return c.MaxRows
}
func (c *Config) maxResultBytes() int {
	if c.MaxResultKB <= 0 {
		return 256 * 1024
	}
	if c.MaxResultKB > 8192 {
		return 8192 * 1024
	}
	return c.MaxResultKB * 1024
}
func (c *Config) timeoutSec() int {
	if c.TimeoutSec <= 0 {
		return 15
	}
	if c.TimeoutSec > 300 {
		return 300
	}
	return c.TimeoutSec
}
func (c *Config) requireWhere() bool { return c.RequireWhere == nil || *c.RequireWhere }
func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
func argStr(args map[string]any, k string) string {
	switch v := args[k].(type) {
	case string:
		return v
	case nil:
		return ""
	case float64:
		return fmt.Sprint(v)
	}
	b, _ := json.Marshal(args[k])
	return string(b)
}
func argInt(args map[string]any, k string, def int) int {
	switch v := args[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}
