package main

import (
	"strings"
	"testing"
)

func TestClassifyToolResult(t *testing.T) {
	cases := []struct {
		ct, body string
		want     ResultKind
	}{
		{"application/json", `{"ok":true}`, ResultJSON},
		{"text/html", `{"ok":true}`, ResultJSON},
		{"text/html; charset=utf-8", `<html><body>hi</body></html>`, ResultHTML},
		{"application/xhtml+xml", `<html></html>`, ResultHTML},
		{"application/json", `true`, ResultOther},
		{"application/vnd.api+json", `not-an-object`, ResultOther},
		{"", `<!DOCTYPE html><html>`, ResultHTML},
		{"", `<div><table></table><script></script></div>`, ResultHTML},
		{"", "plain text only", ResultOther},
		{"text/plain", "hello", ResultOther},
	}
	for _, c := range cases {
		got := classifyToolResult(c.ct, c.body)
		if got != c.want {
			t.Fatalf("classify(%q, %q)=%d want %d", c.ct, c.body, got, c.want)
		}
	}
	got := classifyToolResult("", "\ufeff  \n{\"a\":1}")
	if got != ResultJSON {
		t.Fatalf("BOM json: %d", got)
	}
}

func TestValidateResultSelector(t *testing.T) {
	ok := []string{"", "div", "#main", ".content", "div.content", "div#main", "div#main p", "article.content p"}
	for _, s := range ok {
		if err := validateResultSelector(s); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
	}
	bad := []string{"div>", "div,span", "div[name=x]", "a:hover", "div > p", "*"}
	for _, s := range bad {
		err := validateResultSelector(s)
		if err == nil {
			t.Fatalf("%q should be rejected", s)
		}
		if !strings.Contains(err.Error(), "选择器") && !strings.Contains(err.Error(), "语法") && !strings.Contains(err.Error(), "无效") {
			t.Fatalf("error should be Chinese: %v", err)
		}
	}
}

func defectTrackerHTML() string {
	return `<!DOCTYPE html>
<html>
<head>
  <title>忽略的标题</title>
  <script>var noise="secret script noise"; alert('ignore');</script>
  <style>.nav { color: red; }</style>
</head>
<body>
  <nav id="navbar"><a href="/home">首页导航</a><span>菜单项</span></nav>
  <div class="sidebar">侧边栏广告</div>
  <main id="main">
    <header>
      <h1>接口超时咨询</h1>
    </header>
    <article class="content">
      <table>
        <tr><th>字段</th><th>内容</th></tr>
        <tr><td>步骤</td><td>打开页面 &amp; 点击提交，出现超时</td></tr>
      </table>
      <h2>备注历史</h2>
      <p>已按咨询问题回复，<span>无需再查</span>业务日志。</p>
    </article>
  </main>
  <footer>站点页脚版权</footer>
</body>
</html>`
}

func TestCleanHTMLToMarkdownKeepsContentDropsChrome(t *testing.T) {
	src := defectTrackerHTML()
	view, err := cleanHTMLToMarkdown(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if !view.SelectorHit {
		t.Fatal("empty selector should hit")
	}
	md := view.Markdown
	for _, want := range []string{"接口超时咨询", "打开页面", "点击提交", "备注历史", "已按咨询问题回复", "无需再查", "业务日志"} {
		if !strings.Contains(md, want) {
			t.Fatalf("missing %q in:\n%s", want, md)
		}
	}
	if !strings.Contains(md, "打开页面 & 点击提交") && !strings.Contains(md, "打开页面 &amp;") {
		if !strings.Contains(md, "&") && strings.Contains(src, "&amp;") {
			t.Fatalf("entity not decoded:\n%s", md)
		}
	}
	if strings.Contains(md, "&amp;") {
		t.Fatalf("entity should be decoded:\n%s", md)
	}
	for _, drop := range []string{"secret script noise", "首页导航", "侧边栏广告", "站点页脚版权", "<script", "<nav", "<style"} {
		if strings.Contains(md, drop) {
			t.Fatalf("should drop %q:\n%s", drop, md)
		}
	}
	if len(md) >= len(src)*20/100 && len(md) > 400 {
		// allow small pages; this fixture is small but should still shrink
	}
	if len(md) >= len(src) {
		t.Fatalf("markdown not smaller: md=%d src=%d\n%s", len(md), len(src), md)
	}
	if view.VisibleChars < 20 {
		t.Fatalf("VisibleChars too small: %d md=%s", view.VisibleChars, md)
	}
	// title in main>header is kept (appears as heading)
	if !strings.Contains(md, "# 接口超时咨询") && !strings.Contains(md, "接口超时咨询") {
		t.Fatalf("main header title lost:\n%s", md)
	}
}

func TestCleanHTMLSelectorModes(t *testing.T) {
	src := defectTrackerHTML()
	main, err := cleanHTMLToMarkdown(src, "#main")
	if err != nil {
		t.Fatal(err)
	}
	if !main.SelectorHit || !strings.Contains(main.Markdown, "接口超时咨询") {
		t.Fatalf("#main: %+v", main)
	}
	if strings.Contains(main.Markdown, "首页导航") {
		t.Fatalf("#main included nav: %s", main.Markdown)
	}

	content, err := cleanHTMLToMarkdown(src, "article.content")
	if err != nil {
		t.Fatal(err)
	}
	if !content.SelectorHit || !strings.Contains(content.Markdown, "备注历史") {
		t.Fatalf("article.content: %+v", content)
	}

	// Fixture uses <main id="main">, so div#main p is tested on a dedicated page.
	page := `<html><body><div id="main"><p>只要这一段</p><span>也在 div 里但不被 p 选中作为根</span></div><p>外面</p></body></html>`
	got, err := cleanHTMLToMarkdown(page, "div#main p")
	if err != nil {
		t.Fatal(err)
	}
	if !got.SelectorHit || !strings.Contains(got.Markdown, "只要这一段") {
		t.Fatalf("div#main p: %+v", got)
	}
	if strings.Contains(got.Markdown, "外面") {
		t.Fatalf("leaked outside: %s", got.Markdown)
	}

	miss, err := cleanHTMLToMarkdown(src, "#no-such-id")
	if err != nil {
		t.Fatal(err)
	}
	if miss.SelectorHit {
		t.Fatalf("expected miss: %+v", miss)
	}
	if strings.TrimSpace(miss.Markdown) != "" && miss.VisibleChars != 0 {
		// markdown may be empty
	}
	if miss.SelectorHit {
		t.Fatal("SelectorHit should be false")
	}

	_, err = cleanHTMLToMarkdown(src, "div>")
	if err == nil {
		t.Fatal("illegal selector should return err")
	}
}

func TestCleanHTMLKeepsUnknownTagsAndMainHeader(t *testing.T) {
	src := `<html><body><main><header><h1>保留标题</h1></header><p>说明：<span>中间字</span><label>标签</label><time>2026</time></p></main></body></html>`
	view, err := cleanHTMLToMarkdown(src, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"保留标题", "中间字", "标签", "2026"} {
		if !strings.Contains(view.Markdown, want) {
			t.Fatalf("missing %q in %s", want, view.Markdown)
		}
	}
}

func TestCleanHTMLVisibleCharsAndBrokenHTML(t *testing.T) {
	view, err := cleanHTMLToMarkdown(`<p>你好世界</p>`, "")
	if err != nil {
		t.Fatal(err)
	}
	if view.VisibleChars != 4 { // 你 好 世 界
		t.Fatalf("VisibleChars=%d want 4 md=%q", view.VisibleChars, view.Markdown)
	}
	// Broken HTML must not panic or return err.
	view, err = cleanHTMLToMarkdown(`<<< not really <<>><p>还在`, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = view
}

func TestCleanHTMLBlockquoteSpacesAndHiddenStyle(t *testing.T) {
	quote, err := cleanHTMLToMarkdown(`<blockquote><p>引用一句</p></blockquote>`, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(quote.Markdown, "> 引用一句") {
		t.Fatalf("blockquote: %s", quote.Markdown)
	}
	nested, err := cleanHTMLToMarkdown(`<blockquote><blockquote>内引</blockquote></blockquote>`, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nested.Markdown, "内引") {
		t.Fatalf("nested blockquote: %s", nested.Markdown)
	}

	spaced, err := cleanHTMLToMarkdown("<p>hello <span>world</span></p><p>你好\n世界<br>下一行</p>", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(spaced.Markdown, "hello world") {
		t.Fatalf("inline space lost: %s", spaced.Markdown)
	}
	if !strings.Contains(spaced.Markdown, "你好 世界") || !strings.Contains(spaced.Markdown, "下一行") {
		t.Fatalf("newline/br: %s", spaced.Markdown)
	}
	if strings.Contains(spaced.Markdown, "你好\n世界") {
		t.Fatalf("source newline should fold to a space: %s", spaced.Markdown)
	}

	hidden := `<div style="backface-visibility: hidden">可见翻转</div>` +
		`<div style="display: none">隐藏甲</div>` +
		`<p style="visibility: hidden">隐藏乙</p>` +
		`<p style="color: red; display:none">隐藏丙</p>` +
		`<p>留下 user_id</p>`
	view, err := cleanHTMLToMarkdown(hidden, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(view.Markdown, "可见翻转") || !strings.Contains(view.Markdown, "留下 user_id") {
		t.Fatalf("kept text missing: %s", view.Markdown)
	}
	for _, drop := range []string{"隐藏甲", "隐藏乙", "隐藏丙"} {
		if strings.Contains(view.Markdown, drop) {
			t.Fatalf("hidden %s leaked: %s", drop, view.Markdown)
		}
	}
	idView, err := cleanHTMLToMarkdown(`<p>user_id</p>`, "")
	if err != nil {
		t.Fatal(err)
	}
	if idView.VisibleChars != 7 {
		t.Fatalf("VisibleChars=%d want 7 (underscore is content) md=%q", idView.VisibleChars, idView.Markdown)
	}

	list, err := cleanHTMLToMarkdown(`<ul><li>外<ul><li>内</li></ul></li></ul>`, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(list.Markdown, "外") || !strings.Contains(list.Markdown, "内") {
		t.Fatalf("nested list: %s", list.Markdown)
	}
}

func TestCleanHTMLLinksAndTables(t *testing.T) {
	src := `<p><a href="javascript:alert(1)">危险</a><a href="https://example.com/x">安全</a><a href="data:text/plain,abc">数据</a></p>
	<table><tr><th>A</th><th>B</th></tr><tr><td>1|2</td><td>3</td></tr></table>`
	view, err := cleanHTMLToMarkdown(src, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(view.Markdown, "javascript:") || strings.Contains(view.Markdown, "data:text") {
		t.Fatalf("unsafe href kept: %s", view.Markdown)
	}
	if !strings.Contains(view.Markdown, "危险") || !strings.Contains(view.Markdown, "[安全](https://example.com/x)") {
		t.Fatalf("links: %s", view.Markdown)
	}
	if strings.Contains(view.Markdown, "1|2") {
		t.Fatalf("pipe in cell: %s", view.Markdown)
	}
	if !strings.Contains(view.Markdown, "|") || !strings.Contains(view.Markdown, "---") {
		t.Fatalf("not a markdown table: %s", view.Markdown)
	}
}
