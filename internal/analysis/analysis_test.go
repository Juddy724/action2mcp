package analysis

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/recording"
	"strings"
	"testing"
)

func TestRecSecurityParameterizeParsedValues(t *testing.T) {
	q := &recording.Request{ReqHeaders: map[string]string{"Content-Type": "application/json"}, ReqBody: `{"credentials":{"value":123},"password":"secret","known":"{{secret.existing}}","normal":99,"enabled":true}`}
	tool := &execution.Tool{URL: "https://example.com/?token=123", Body: q.ReqBody}
	if err := parameterizeRawSecrets(tool, q); err != nil {
		t.Fatal(err)
	}
	body := decodeRec(t, tool.Body)
	if body["known"] != "{{secret.existing}}" || body["normal"] != float64(99) || body["enabled"] != true {
		t.Fatalf("typed values or refs changed: %s", tool.Body)
	}
	if body["credentials"].(map[string]any)["value"] == float64(123) {
		t.Fatal("sensitive numeric field not parameterized")
	}
	for _, p := range tool.Params {
		if p.Default != "" || !p.Required {
			t.Fatalf("secret parameter kept default: %+v", p)
		}
	}
}

func TestMaskAndParseLogin(t *testing.T) {
	q := &recording.Request{Method: "POST", URL: "http://b.local/login", ReqBody: "account=alice&password=p%40ss&csrf_token=t1"}
	lf := parseLogin(q)
	if lf == nil || lf.userVal != "alice" || lf.passVal != "p@ss" || lf.csrfKey != "csrf_token" {
		t.Fatalf("%+v", lf)
	}
	if m := MaskSecrets(q.ReqBody); strings.Contains(m, "p%40ss") || !strings.Contains(m, "account=alice") {
		t.Fatal(m)
	}
	if m := MaskSecrets(`{"userName":"a","passWord":"xyz"}`); strings.Contains(m, "xyz") {
		t.Fatal(m)
	}
	if IsLoginRequest(&recording.Request{Method: "POST", ReqBody: `{"q":"x"}`}) {
		t.Fatal("not login")
	}
}
