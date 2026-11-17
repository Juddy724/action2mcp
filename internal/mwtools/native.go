package mwtools

import (
	"action2mcp/internal/middleware"
	"action2mcp/internal/mwconfig"
	"encoding/json"
)

type nativeObserver struct{ call *mwCall }

// nativeTarget keeps browser/site/login dependencies out of native drivers.
func (a *Service) nativeTarget(m *mwconfig.Middleware) *middleware.Target {
	return &middleware.Target{ID: m.ID, Name: m.Name, Type: m.Type, CacheConfig: js(m.Config),
		Password: func() (string, error) { return a.Password(m) },
		Config: middleware.Config{
			Host:          m.Config.Host,
			Port:          m.Config.Port,
			User:          m.Config.User,
			PasswordRef:   m.Config.PasswordRef,
			Database:      m.Config.Database,
			Addrs:         m.Config.Addrs,
			MQKind:        m.Config.MQKind,
			RedisMode:     m.Config.RedisMode,
			MasterName:    m.Config.MasterName,
			TLS:           m.Config.TLS,
			TLSSkipVerify: m.Config.TLSSkipVerify,
			SASL:          m.Config.SASL,
			BrokerAddr:    m.Config.BrokerAddr,
			Perms:         m.Config.Perms,
			AllowedDBs:    m.Config.AllowedDBs,
			AllowedTables: m.Config.AllowedTables,
			KeyPrefixes:   m.Config.KeyPrefixes,
			Topics:        m.Config.Topics,
			MaxRows:       m.Config.MaxRows,
			MaxResultKB:   m.Config.MaxResultKB,
			TimeoutSec:    m.Config.TimeoutSec,
			RequireWhere:  m.Config.RequireWhere,
		}}
}

func (o nativeObserver) Require(action string, permissions ...string) (string, bool) {
	o.call.action = action
	return o.call.need(permissions...)
}

func (o nativeObserver) Block(action, message string) string {
	o.call.action = action
	return o.call.blocked(message)
}

func (o nativeObserver) Complete(action, result string, err error) (string, bool) {
	o.call.action = action
	return o.call.done(result, err)
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
