package execution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

func ParseRecJSON(body string) (any, error) {
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("incomplete or trailing JSON")
	}
	return v, nil
}

var syntheticTableRe = regexp.MustCompile(`(?i)^<(derived|subquery|union)\d+>$`)

func jsonPath(v any, path string) (any, bool) {
	cur := v
	if path == "" {
		return cur, true
	}
	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		found := false
		for k, val := range m {
			if k == p {
				cur = val
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return cur, true
}

func CompactJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimSpace(buf.Bytes())
}
