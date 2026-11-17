package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

func TestWSPrepareDoesNotDial(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := testWSEngine(fake)

	tool := wsTestTool(fake.wsURL(s.URL), "{{header.sso-epctoken}}")

	p, err := a.Prepare(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10"})
	if err != nil {
		t.Fatal(err)
	}
	if p.wsSQL != "SELECT id FROM t WHERE id=1 LIMIT 10" {
		t.Fatalf("sql=%s", p.wsSQL)
	}
	if strings.Contains(p.Preview.Body, fake.token) || strings.Contains(strings.Join(p.wsMessages, ""), fake.token) {
		t.Fatal("preview leaked token")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.conns != 0 || fake.business != 0 {
		t.Fatalf("dialed before send: conns=%d biz=%d", fake.conns, fake.business)
	}
}

func TestWSSendExplainThenBusiness(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := testWSEngine(fake)

	tool := wsTestTool(fake.wsURL(s.URL), "{{header.sso-epctoken}}")

	res, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeSuccess {
		t.Fatalf("outcome=%s err=%s body=%s", res.Outcome, res.Error, res.Body)
	}
	if strings.Contains(res.Body, fake.token) {
		t.Fatal("result leaked token")
	}
	if !strings.Contains(res.Body, `"name":"id"`) {
		t.Fatalf("columns missing: %s", res.Body)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.explain != 1 || fake.business != 1 || fake.conns != 2 {
		t.Fatalf("explain=%d business=%d conns=%d msgs=%v", fake.explain, fake.business, fake.conns, fake.all)
	}
	joined := strings.Join(fake.all, "\n")
	if !strings.Contains(joined, fake.token) {
		t.Fatalf("server did not receive harvested token: %v", fake.all)
	}
	if strings.Contains(joined, "{{header.") {
		t.Fatalf("unresolved placeholder sent: %v", fake.all)
	}
}

func TestWSGuardRejectsSendsNothing(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := testWSEngine(fake)

	tool := wsTestTool(fake.wsURL(s.URL), "{{header.sso-epctoken}}")

	for _, sql := range []string{
		"SELECT id FROM t",
		"SELECT id FROM t LIMIT 201",
		"INSERT INTO t VALUES (1)",
		"SELECT SLEEP(1) FROM t LIMIT 1",
		"SELECT `sum`(id) FROM t LIMIT 1",
		"SELECT * FROM t AS `<derived2>` LIMIT 1",
		"SELECT id FROM t WHERE id>0 /*!99999 LIMIT 1 */",
	} {
		_, err := a.Prepare(tool, map[string]any{"sql": sql})
		if err == nil {
			t.Fatalf("prepare accepted %s", sql)
		}
	}
	// Send-time reject: type=ALL after prepare of a valid SQL
	fake.typeALL = true
	res, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeGuardRejected {
		t.Fatalf("outcome=%s err=%s", res.Outcome, res.Error)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.business != 0 {
		t.Fatalf("business messages=%d %v", fake.business, fake.all)
	}
}

func TestWSTruncationAndMaxRows(t *testing.T) {
	fake := newCountingWS(250)
	s := fake.start(t)
	a := testWSEngine(fake)

	tool := wsTestTool(fake.wsURL(s.URL), "{{header.sso-epctoken}}")
	tool.Config.SQLGuard.MaxRows = 10

	if _, err := a.Prepare(tool, map[string]any{"sql": "SELECT id FROM t LIMIT 200"}); err == nil {
		t.Fatal("LIMIT 200 should fail max_rows=10")
	}
	res, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t LIMIT 10"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || !strings.Contains(res.Body, "只返回前 10 行") {
		t.Fatalf("truncation: %+v %s", res.Truncated, res.Body)
	}
	var payload map[string]any
	json.Unmarshal([]byte(res.Body), &payload)
	rows, _ := payload["rows"].([]any)
	if len(rows) != 10 {
		t.Fatalf("rows=%d", len(rows))
	}
	if res.Outcome != OutcomeSuccess {
		t.Fatalf("outcome=%s", res.Outcome)
	}
}

type countingWS struct {
	mu              sync.Mutex
	conns           int
	messages        []string
	all             []string
	explain         int
	business        int
	upgrader        websocket.Upgrader
	token           string
	failToken       string
	rows            int
	typeALL         bool
	handshakeCookie string
	businessCols    []any
	businessRows    []any
	failBusiness    string
}

func newCountingWS(rows int) *countingWS {
	return &countingWS{upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}, rows: rows, token: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}
func wsTestTool(url, tokenRef string) *Tool {
	return &Tool{
		Name: "console_sql", Title: "SQL", Method: "WS", URL: url, Approval: "always",
		Params: []domain.Param{{Name: "sql", Type: "string", Required: true}},
		Config: ToolConfig{
			Messages: []string{`execute {"data":{"sql":"{{sql}}","spaceCode":"s","dsId":1,"envId":2,"envType":"PROD","dbType":"mysql"},"token":"` + tokenRef + `"}`},
			SQLGuard: &SQLGuardConfig{Enabled: true, Param: "sql", Path: "data.sql", MaxRows: 200},
			Collect:  &WSCollectConfig{ResultCmd: "execResult", CloseCmds: []string{"close"}, SuccessPath: "data.success", DonePath: "data.done", MessagePath: "data.message", TimeoutMS: 5000, MaxBytes: 65536},
			Auth:     &WSAuthConfig{RetryRelogin: true, FailMessageMatch: DefaultAuthKeywords()},
		},
	}
}
func (c *countingWS) start(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(c.ServeHTTP))
	t.Cleanup(s.Close)
	return s
}
func (c *countingWS) wsURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}
func (c *countingWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := c.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	c.mu.Lock()
	c.conns++
	c.handshakeCookie = r.Header.Get("Cookie")
	c.mu.Unlock()
	_, data, err := conn.ReadMessage()
	if err != nil {
		return
	}
	msg := string(data)
	c.mu.Lock()
	c.messages = append(c.messages, msg)
	c.all = append(c.all, msg)
	c.mu.Unlock()
	_, tail, ok := SplitCommandJSON(msg)
	sql := ""
	token := ""
	if ok {
		var v any
		json.Unmarshal([]byte(tail), &v)
		if s, err := ExtractJSONString(msg, "data.sql"); err == nil {
			sql = s
		}
		if m, ok := v.(map[string]any); ok {
			if t, ok := m["token"].(string); ok {
				token = t
			}
		}
	}
	if c.failToken != "" && token == c.failToken {
		writeExec(conn, false, "token expired: "+token, nil, nil, 0)
		return
	}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "EXPLAIN ") {
		c.mu.Lock()
		c.explain++
		c.mu.Unlock()
		cols := []any{
			map[string]any{"field": "C_1", "title": "id"},
			map[string]any{"field": "C_2", "title": "select_type"},
			map[string]any{"field": "C_3", "title": "table"},
			map[string]any{"field": "C_4", "title": "type"},
			map[string]any{"field": "C_5", "title": "key"},
			map[string]any{"field": "C_6", "title": "possible_keys"},
			map[string]any{"field": "C_7", "title": "Extra"},
		}
		typ := "ref"
		key := "PRIMARY"
		if c.typeALL {
			typ = "ALL"
			key = ""
		}
		rows := []any{map[string]any{"C_1": "1", "C_2": "SIMPLE", "C_3": "t", "C_4": typ, "C_5": key, "C_6": "PRIMARY", "C_7": ""}}
		writeExec(conn, true, "", cols, rows, 1)
		return
	}
	c.mu.Lock()
	c.business++
	fail := c.failBusiness
	cols := c.businessCols
	rows := c.businessRows
	n := c.rows
	c.mu.Unlock()
	if fail != "" {
		writeExec(conn, false, fail, nil, nil, 0)
		return
	}
	if len(cols) == 0 {
		cols = []any{map[string]any{"field": "C_1", "title": "id"}, map[string]any{"field": "C_2", "title": "name"}}
	}
	if n == 0 {
		n = 2
	}
	if rows == nil {
		rows = []any{}
		for i := 0; i < n; i++ {
			rows = append(rows, map[string]any{"C_1": i + 1, "C_2": "r"})
		}
	} else {
		n = len(rows)
	}
	writeExec(conn, true, "", cols, rows, n)
}
func testWSEngine(fake *countingWS) *Engine {
	return New(Options{Vault: &vault.Vault{}, Cookies: func(string) ([]Cookie, string) { return nil, "" }, Header: func(string, string) (string, error) { return fake.token, nil }})
}

func writeExec(conn *websocket.Conn, success bool, message string, cols, rows []any, count int) {
	if success {
		payload, _ := json.Marshal(map[string]any{
			"data": map[string]any{"success": true, "done": true, "elapsed": 1, "executeResult": map[string]any{
				"success": true, "hasResult": true, "result": map[string]any{"columns": cols, "result": rows, "count": count},
			}},
		})
		conn.WriteMessage(websocket.TextMessage, append([]byte("execResList "), []byte(`{"data":["ok"]}`)...))
		conn.WriteMessage(websocket.TextMessage, append([]byte("execResQueryId "), []byte(`{"data":{"startTime":"t"}}`)...))
		conn.WriteMessage(websocket.TextMessage, append([]byte("execResult "), payload...))
		conn.WriteMessage(websocket.TextMessage, []byte("close {}"))
		return
	}
	payload, _ := json.Marshal(map[string]any{"data": map[string]any{"success": false, "done": false, "message": message}})
	conn.WriteMessage(websocket.TextMessage, append([]byte("execResult "), payload...))
	conn.WriteMessage(websocket.TextMessage, []byte("close {}"))
}
