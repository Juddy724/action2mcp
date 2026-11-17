package approval

import (
	"reflect"
	"testing"
)

func TestApprovalWholeParamReplacement(t *testing.T) {
	for _, tc := range []struct{ original, edit any }{
		{`{"note":"old","retained":true}`, `{"note":"new"}`},
		{"note=old&retained=visible", "note=new"},
		{map[string]any{"note": "old", "retained": true}, map[string]any{"note": "new"}},
		{[]any{"old", "retained"}, []any{"new"}},
		{map[string]any{"note": "old"}, ` {"note":"new","id":" 123 "} `},
	} {
		original := map[string]any{"label": tc.original, "untouched": "original"}
		merged, err := EditArgs(original, map[string]any{"label": tc.edit}, func(string, any) bool { return false })
		if err != nil || !reflect.DeepEqual(merged["label"], tc.edit) || merged["untouched"] != "original" {
			t.Fatal("whole-parameter replacement retained a subpath or rewrote submitted text")
		}
	}
}
