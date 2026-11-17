package mwconfig

import "testing"

// Legacy sql_defaults env keys are captured privately on decode, then cleared by promotion.
func TestDecodeCapturesAndPromotesLegacySQLDefaults(t *testing.T) {
	raw := `{"url":"ws://127.0.0.1:9/ws","ws_mode":"sql_console","ws_messages":["execute {\"data\":{\"sql\":\"{{sql}}\"}}"],"sql_defaults":{"space_code":"spc_alpha","env_id":70007,"env_type":"TEST","db_type":"mysql"},"datasources":[{"alias":"default","ds_id":90001,"env_id":1,"env_type":"PROD"}],"max_rows":200,"timeout_sec":15,"perms":{"select":true}}`
	c, err := DecodeMWConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if IsEmptyJSONValue(c.SQLDefaults.legacyEnvID) || c.SQLDefaults.legacyEnvType != "TEST" {
		t.Fatalf("expected to capture legacy defaults, got %+v", c.SQLDefaults)
	}
	if !SQLConsoleEnvNeedsPromote(c) {
		t.Fatal("legacy defaults alone must require promotion")
	}
	ApplySQLConsoleEnvPromotion(&c)
	if !IsEmptyJSONValue(c.SQLDefaults.legacyEnvID) || c.SQLDefaults.legacyEnvType != "" || SQLConsoleEnvNeedsPromote(c) {
		t.Fatalf("promotion kept legacy keys: %+v", c.SQLDefaults)
	}
}
