package execution

import (
	"action2mcp/internal/vault"
	"testing"
)

func TestLimitedLexicalScanUnicodeKey(t *testing.T) {
	secret := "UnicodeLimitSecret-R7"
	body := wrapApprovalJSONDepth(`{"\u0070assword":"`+secret+`"}`, vault.MaxDecodeDepth+1)
	analysis := analyzeApprovalTemplate(&Tool{Body: body, Headers: map[string]string{"Content-Type": "application/json"}})
	if !analysis.limitedBody {
		t.Fatal("expected the escaped-key template to hit the analysis limit")
	}
	for _, value := range analysis.values {
		if value == secret {
			return
		}
	}
	t.Fatal("limited scan missed a unicode-escaped sensitive key")
}

func TestLimitedTemplateAnalysisSnapshot(t *testing.T) {
	secret := "LimitSecretValue-R7/deep"
	body := wrapApprovalJSONDepth(`{"password":"`+secret+`"}`, vault.MaxDecodeDepth+1)
	analysis := analyzeApprovalTemplate(&Tool{Body: body, Headers: map[string]string{"Content-Type": "application/json"}})
	if !analysis.limitedBody {
		t.Fatal("expected the nested template to hit the analysis limit")
	}
	found := false
	for _, value := range analysis.values {
		if value == secret {
			found = true
		}
	}
	if !found {
		t.Fatal("limited analysis did not collect the sensitive literal")
	}

}
