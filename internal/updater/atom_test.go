package updater

import "testing"

func TestParseAtomNotes(t *testing.T) {
	feed := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <link rel="alternate" type="text/html" href="https://github.com/o/r/releases/tag/v0.6.3"/>
    <content type="html">&lt;ol&gt;
&lt;li&gt;新增版本检测。&lt;/li&gt;
&lt;li&gt;优化 &lt;code&gt;登录&lt;/code&gt; &amp;amp; 审批。&lt;/li&gt;
&lt;/ol&gt;</content>
  </entry>
  <entry>
    <link rel="alternate" type="text/html" href="https://github.com/o/r/releases/tag/v0.6.2"/>
    <content type="html">&lt;ul&gt;&lt;li&gt;old&lt;/li&gt;&lt;/ul&gt;</content>
  </entry>
</feed>`)
	got := parseAtomNotes(feed, "v0.6.3")
	want := "1. 新增版本检测。\n2. 优化 登录 & 审批。"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := parseAtomNotes(feed, "v0.6.2"); got != "• old" {
		t.Fatalf("ul got %q", got)
	}
	if got := parseAtomNotes(feed, "v9.9.9"); got != "" {
		t.Fatalf("missing tag got %q", got)
	}
}
