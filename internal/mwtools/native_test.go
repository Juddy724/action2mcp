package mwtools

import (
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/vault"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNativeTargetMapsDriverSnapshotWithoutChangingCacheConfig(t *testing.T) {
	a, _ := testService(t)
	requireWhere := false
	override := "typed-unsaved-password"
	m := &mwconfig.Middleware{ID: 17, Name: "native", Type: "mysql", Config: mwconfig.MWConfig{
		Host: "host", Port: 13306, User: "reader", PasswordRef: "ref", Database: "shop", Addrs: "broker:9092", MQKind: "kafka", RedisMode: "sentinel", MasterName: "primary",
		TLS: true, TLSSkipVerify: true, SASL: "PLAIN", BrokerAddr: "broker:10911", Perms: map[string]bool{"select": true}, AllowedDBs: []string{"shop"}, AllowedTables: []string{"shop.orders"}, KeyPrefixes: []string{"order:"}, Topics: []string{"order*"},
		MaxRows: 70, MaxResultKB: 80, TimeoutSec: 40, RequireWhere: &requireWhere,
		// Even unrelated persisted settings participated in the old cache key.
		WSHeaders: map[string]string{"X-Test": "{{secret.ref}}"}, Description: "keep-entire-config",
	}}
	m.OverridePassword(override)
	native := a.nativeTarget(m)
	if native.ID != m.ID || native.Name != m.Name || native.Type != m.Type || native.CacheConfig != js(m.Config) {
		t.Fatal("target identity or full configuration changed")
	}
	source, destination := reflect.ValueOf(m.Config), reflect.ValueOf(native.Config)
	for i := 0; i < destination.NumField(); i++ {
		field := destination.Type().Field(i).Name
		if !reflect.DeepEqual(destination.Field(i).Interface(), source.FieldByName(field).Interface()) {
			t.Errorf("native mapping dropped %s", field)
		}
	}
	password, err := native.Password()
	if err != nil || password != override {
		t.Fatalf("unsaved password resolution changed: %v", err)
	}
}

func TestNativeObserverPreservesPermissionAuditAndScrubbing(t *testing.T) {
	a, fx := testService(t)
	secret := "native-secret-" + privateTestValue(t)
	if err := fx.vault.Upsert("native_password", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	m := &mwconfig.Middleware{Name: "native-db", Type: "mysql", Config: mwconfig.MWConfig{PasswordRef: "native_password", Perms: map[string]bool{"select": true}}}
	c := &mwCall{a: a, m: m, tool: "db_query", client: "test-native", start: time.Now()}
	observer := nativeObserver{c}
	if _, ok := observer.Require("UPDATE shop.orders", "update"); ok {
		t.Fatal("permission denial disappeared")
	}
	entries := fx.store.ListAudit(m.Name, 10)
	if len(entries) != 1 || entries[0].Allowed || entries[0].Action != "UPDATE shop.orders" || entries[0].Perm != mwconfig.PermLabel("mysql", "update") {
		t.Fatalf("denial audit changed: %+v", entries)
	}
	if _, ok := observer.Require("SELECT * FROM shop.orders", "select"); !ok {
		t.Fatal("enabled permission denied")
	}
	text, isError := observer.Complete("SELECT * FROM shop.orders", "value="+secret, nil)
	if isError || strings.Contains(text, secret) || !strings.Contains(text, vault.Mask) {
		t.Fatal("successful driver result bypassed scrubbing")
	}
	text, isError = observer.Complete("SELECT * FROM shop.orders", "", errors.New("driver echoed "+secret))
	if !isError || strings.Contains(text, secret) || !strings.Contains(text, vault.Mask) {
		t.Fatal("driver error bypassed scrubbing")
	}
	entries = fx.store.ListAudit(m.Name, 10)
	if len(entries) != 3 || !entries[0].Allowed || entries[0].Action != "SELECT * FROM shop.orders" || strings.Contains(entries[0].Result, secret) {
		t.Fatalf("completion audit changed: %+v", entries)
	}
}
