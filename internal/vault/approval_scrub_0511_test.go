package vault_test

import (
	"action2mcp/internal/vault"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Realistic MCP-sized HTML body: about 66 KiB, with entities and percent
// sequences that produce several decoded views (the Zentao-page shape).
func largeScrubBody() string {
	return strings.Repeat("<div class=\"detail\">Bug 描述 &amp; 步骤 a%20b</div>\n", 1200)
}

func cookieLikeSecrets(n int) []string {
	out := make([]string, n)
	for i := 0; i < n; i++ {
		// 20+ characters, above minSecretScrubLen; fake values only.
		out[i] = fmt.Sprintf("cookieval%02dXYZabcdef", i)
	}
	return out
}

func TestScrubSecretTextLargeBodyNoMatchUnchanged(t *testing.T) {
	body := largeScrubBody()
	if len(body) < 60*1024 {
		t.Fatalf("fixture too small: %d", len(body))
	}
	for _, n := range []int{5, 20, 50} {
		got := vault.ScrubSecretText(body, nil, cookieLikeSecrets(n))
		if got != body {
			if got == vault.Mask {
				t.Fatalf("%d values fail-closed a body with no secrets (len=%d)", n, len(body))
			}
			t.Fatalf("%d values changed a body that contains none of them", n)
		}
	}
}

func TestScrubSecretTextLargeBodyMasksEncodedForms(t *testing.T) {
	// A value that actually changes under each encoding, so we can see
	// that every variant is masked and the surrounding page stays readable.
	secret := `cookieVal/00XY&ab"c def`
	if len(secret) < vault.MinSecretScrubLen {
		t.Fatal("fixture shorter than the scrub floor")
	}
	jb, err := json.Marshal(secret)
	if err != nil {
		t.Fatal(err)
	}
	jsonEscaped := string(jb[1 : len(jb)-1])
	forms := []struct {
		name, value string
	}{
		{"raw", secret},
		{"query", url.QueryEscape(secret)},
		{"path", url.PathEscape(secret)},
		{"html", html.EscapeString(secret)},
		{"b64", base64.StdEncoding.EncodeToString([]byte(secret))},
		{"b64url", base64.URLEncoding.EncodeToString([]byte(secret))},
		{"json", jsonEscaped},
	}
	// Dedup forms that collapse to the same spelling so the expected
	// mask count stays exact.
	type emb struct{ name, value string }
	var embedded []emb
	seen := map[string]bool{}
	var inserts []string
	for _, f := range forms {
		if seen[f.value] {
			continue
		}
		seen[f.value] = true
		embedded = append(embedded, emb{f.name, f.value})
		inserts = append(inserts, "<!--"+f.name+"-->"+f.value+"<!--/"+f.name+"-->")
	}

	page := largeScrubBody()
	// Plant the encodings near the front, middle and (for the first form)
	// also after a block of entities, so decoded-view matches still map
	// back onto the original spans.
	mid := len(page) / 2
	body := strings.Join(inserts, "\n") + "\n" + page[:mid] + "\nVISIBLE-MIDDLE\n" + page[mid:]
	// One extra raw occurrence later in the page.
	body += "\nTAIL=" + secret + ";END\n"

	got := vault.ScrubSecretText(body, nil, []string{secret})
	if got == vault.Mask {
		t.Fatal("fail-closed the whole body")
	}
	if got == body {
		t.Fatal("no masking happened")
	}
	if strings.Contains(got, secret) {
		t.Fatal("raw secret still present")
	}
	for _, e := range embedded {
		if strings.Contains(got, e.value) {
			t.Fatalf("%s form %q still present", e.name, e.value)
		}
		open, close := "<!--"+e.name+"-->", "<!--/"+e.name+"-->"
		want := open + vault.Mask + close
		if !strings.Contains(got, want) {
			t.Fatalf("expected exact span mask for %s, got around: %q", e.name, snippetAround(got, open, 80))
		}
	}
	if !strings.Contains(got, "TAIL="+vault.Mask+";END") {
		t.Fatalf("tail raw occurrence not masked exactly: %q", snippetAround(got, "TAIL=", 40))
	}
	// The rest of the page must stay readable.
	for _, want := range []string{"Bug 描述", "步骤", "VISIBLE-MIDDLE", `<div class="detail">`} {
		if !strings.Contains(got, want) {
			t.Fatalf("readable page text %q was lost", want)
		}
	}
	if strings.Count(got, vault.Mask) < len(embedded)+1 {
		t.Fatalf("too few masks: %d, embedded forms %d", strings.Count(got, vault.Mask), len(embedded))
	}
}

func TestScrubSecretTextLargeBodyFiftyValuesPerformance(t *testing.T) {
	body := largeScrubBody()
	values := cookieLikeSecrets(50)
	// Plant a handful of secrets so the matcher does real replacement work.
	body = values[0] + "\n" + body + "\n" + url.QueryEscape(values[1]) + "\n" +
		base64.StdEncoding.EncodeToString([]byte(values[2])) + "\n"

	start := time.Now()
	got := vault.ScrubSecretText(body, nil, values)
	elapsed := time.Since(start)
	if got == vault.Mask {
		t.Fatalf("fail-closed in %s", elapsed)
	}
	if strings.Contains(got, values[0]) || strings.Contains(got, values[1]) {
		t.Fatal("planted secrets were not masked")
	}
	if !strings.Contains(got, "Bug 描述") {
		t.Fatal("page body was lost")
	}
	if elapsed > time.Second {
		t.Fatalf("60KiB × 50 values took %s, want well under 1s", elapsed)
	}
	t.Logf("scrubSecretText 60KiB × 50 values: %s", elapsed)
}

func snippetAround(s, marker string, n int) string {
	i := strings.Index(s, marker)
	if i < 0 {
		if len(s) < n {
			return s
		}
		return s[:n]
	}
	end := i + n
	if end > len(s) {
		end = len(s)
	}
	return s[i:end]
}

func BenchmarkScrubSecretTextLargeBody50(b *testing.B) {
	body := largeScrubBody()
	values := cookieLikeSecrets(50)
	body = values[0] + "\n" + body + "\n" + url.QueryEscape(values[7]) + "\n"
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := vault.ScrubSecretText(body, nil, values)
		if got == vault.Mask {
			b.Fatal("fail-closed")
		}
	}
}
