package result

import (
	"reflect"
	"strings"
	"testing"
)

func TestPresentationOnlyMutatesPresentationProjection(t *testing.T) {
	headers := map[string]string{"cOnTeNt-TyPe": "application/json", "X-Test": "preserved"}
	wantHeaders := map[string]string{"cOnTeNt-TyPe": "application/json", "X-Test": "preserved"}
	response := Response{Status: 200, Body: `{"success":false,"message":"failed"}`, Headers: headers}
	Present(Config{}, &response)
	if response.Outcome != outcomeBusinessError || response.Status != 200 || !reflect.DeepEqual(response.Headers, wantHeaders) || !reflect.DeepEqual(headers, wantHeaders) || headers["X-Test"] != "preserved" {
		t.Fatalf("projection changed transport metadata or missed business error: %+v", response)
	}
	before := response
	response.Outcome = "auth_error"
	Present(Config{ResultFormat: "raw"}, &response)
	if response.Body != before.Body || response.Outcome != "auth_error" {
		t.Fatal("presentation overwrote a prior non-success outcome")
	}
	Present(Config{}, nil)
}

func TestPresentationDetectFalseAndRawRemainIndependent(t *testing.T) {
	off := false
	raw := `{"success":false,"message":"not an error when disabled"}`
	response := Response{Status: 200, Body: raw, Headers: map[string]string{"Content-Type": "application/json"}}
	Present(Config{DetectFailure: &off}, &response)
	if response.Body != raw || response.Outcome != "" {
		t.Fatal("explicit false no longer disables failure classification")
	}
	response = Response{Status: 200, Body: `<!DOCTYPE html><html><head><script>alert('denied');location.href='/';</script></head><body></body></html>`, Headers: map[string]string{"Content-Type": "text/html"}}
	Present(Config{ResultFormat: " raw "}, &response)
	if response.Outcome != outcomeBusinessError || !strings.Contains(response.Body, "denied") {
		t.Fatal("raw format disabled failure detection")
	}
}
