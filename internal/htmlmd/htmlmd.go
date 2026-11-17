// Package htmlmd classifies tool bodies and cleans HTML into compact Markdown.
// It does not know about tools, approvals, or the console.
package htmlmd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

type ResultKind int

const (
	ResultOther ResultKind = iota
	ResultJSON
	ResultHTML
)

type HTMLView struct {
	Markdown     string
	VisibleChars int
	SelectorHit  bool
}

func ClassifyToolResult(contentType, body string) ResultKind {
	trim := strings.TrimSpace(strings.TrimPrefix(body, "\ufeff"))
	if jsonObjectOrArray(trim) {
		return ResultJSON
	}
	ct := strings.ToLower(contentType)
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return ResultHTML
	}
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "+json") {
		return ResultOther
	}
	if sniffHTML(trim) {
		return ResultHTML
	}
	return ResultOther
}

func jsonObjectOrArray(s string) bool {
	if s == "" {
		return false
	}
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return false
	}
	switch v.(type) {
	case map[string]any, []any:
		return true
	default:
		return false
	}
}

func sniffHTML(s string) bool {
	low := strings.ToLower(s)
	if strings.HasPrefix(low, "<!doctype html") || strings.HasPrefix(low, "<html") {
		return true
	}
	head := low
	if len(head) > 1024 {
		head = head[:1024]
	}
	tags := 0
	for _, t := range []string{"<head", "<body", "<div", "<table", "<script"} {
		if strings.Contains(head, t) {
			tags++
		}
	}
	return tags >= 2
}

type cssSimple struct {
	tag, id, class string
}

func ValidateResultSelector(selector string) error {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil
	}
	_, err := parseCSSSelector(selector)
	return err
}

func parseCSSSelector(s string) ([]cssSimple, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if strings.ContainsAny(s, ",>[]+~:*()") || strings.Contains(s, "[") || strings.Contains(s, "]") {
		return nil, fmt.Errorf("CSS 选择器不支持该语法（仅支持标签、#id、.class、tag.class 和空格后代）：%s", s)
	}
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return nil, fmt.Errorf("CSS 选择器无效")
	}
	out := make([]cssSimple, 0, len(parts))
	for _, p := range parts {
		item, err := parseCSSSimple(p)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func parseCSSSimple(p string) (cssSimple, error) {
	var it cssSimple
	rest := p
	if rest == "" {
		return it, fmt.Errorf("CSS 选择器无效")
	}
	if rest[0] != '#' && rest[0] != '.' {
		i := cssIdentLen(rest)
		if i == 0 {
			return it, fmt.Errorf("CSS 选择器无效：%s", p)
		}
		it.tag = rest[:i]
		rest = rest[i:]
	}
	for rest != "" {
		switch rest[0] {
		case '#':
			rest = rest[1:]
			i := cssIdentLen(rest)
			if i == 0 || it.id != "" {
				return it, fmt.Errorf("CSS 选择器无效：%s", p)
			}
			it.id = rest[:i]
			rest = rest[i:]
		case '.':
			rest = rest[1:]
			i := cssIdentLen(rest)
			if i == 0 || it.class != "" {
				return it, fmt.Errorf("CSS 选择器无效：%s", p)
			}
			it.class = rest[:i]
			rest = rest[i:]
		default:
			return it, fmt.Errorf("CSS 选择器无效：%s", p)
		}
	}
	if it.tag == "" && it.id == "" && it.class == "" {
		return it, fmt.Errorf("CSS 选择器无效：%s", p)
	}
	return it, nil
}

func cssIdentLen(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for i, r := range s {
		ok := r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsDigit(r)
		if i == 0 && unicode.IsDigit(r) {
			return 0
		}
		if !ok {
			break
		}
		n = i + utf8.RuneLen(r)
	}
	return n
}

func CleanHTMLToMarkdown(src, selector string) (HTMLView, error) {
	sel := strings.TrimSpace(selector)
	var chain []cssSimple
	var err error
	if sel != "" {
		chain, err = parseCSSSelector(sel)
		if err != nil {
			return HTMLView{}, err
		}
	}
	root, perr := html.Parse(strings.NewReader(src))
	if perr != nil || root == nil {
		// Spec: parse errors do not return err and do not panic.
		return HTMLView{SelectorHit: sel == ""}, nil
	}
	var targets []*html.Node
	if sel == "" {
		targets = []*html.Node{root}
	} else {
		collectSelectorMatches(root, chain, &targets)
	}
	view := HTMLView{SelectorHit: sel == "" || len(targets) > 0}
	parts := []string{}
	for _, n := range targets {
		parts = append(parts, strings.TrimSpace(renderMarkdown(n, ancestorProtect(n), 0)))
	}
	md := strings.TrimSpace(strings.Join(parts, "\n\n"))
	md = collapseBlankLines(md)
	view.Markdown = md
	view.VisibleChars = CountVisibleMarkdown(md)
	return view, nil
}

func collectSelectorMatches(n *html.Node, chain []cssSimple, out *[]*html.Node) {
	if n == nil {
		return
	}
	if n.Type == html.ElementNode && nodeMatchesChain(n, chain) {
		*out = append(*out, n)
		// Still walk children? Multiple matches "in document order".
		// A descendant of a match may also match (e.g. "div" matching nested divs).
		// That's correct CSS behavior.
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectSelectorMatches(c, chain, out)
	}
}

func nodeMatchesChain(n *html.Node, chain []cssSimple) bool {
	if len(chain) == 0 {
		return false
	}
	// Last simple must match n; earlier simples must match some ancestor, in order.
	if !nodeMatchesSimple(n, chain[len(chain)-1]) {
		return false
	}
	cur := n.Parent
	for i := len(chain) - 2; i >= 0; i-- {
		found := false
		for cur != nil {
			if cur.Type == html.ElementNode && nodeMatchesSimple(cur, chain[i]) {
				cur = cur.Parent
				found = true
				break
			}
			cur = cur.Parent
		}
		if !found {
			return false
		}
	}
	return true
}

func nodeMatchesSimple(n *html.Node, s cssSimple) bool {
	if n == nil || n.Type != html.ElementNode {
		return false
	}
	if s.tag != "" && !strings.EqualFold(n.Data, s.tag) {
		return false
	}
	if s.id != "" && !strings.EqualFold(attr(n, "id"), s.id) {
		return false
	}
	if s.class != "" && !hasClassToken(n, s.class) {
		return false
	}
	return true
}

func hasClassToken(n *html.Node, class string) bool {
	for _, tok := range strings.Fields(attr(n, "class")) {
		if strings.EqualFold(tok, class) {
			return true
		}
	}
	return false
}

func attr(n *html.Node, name string) string {
	if n == nil {
		return ""
	}
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

func hasAttr(n *html.Node, name string) bool {
	if n == nil {
		return false
	}
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return true
		}
	}
	return false
}

var chromeClassTokens = map[string]bool{
	"nav": true, "navbar": true, "navigation": true,
	"menubar": true, "sidebar": true,
	"breadcrumb": true, "breadcrumbs": true,
}

func ancestorProtect(n *html.Node) bool {
	for p := n; p != nil; p = p.Parent {
		if isProtectContainer(p) {
			return true
		}
	}
	return false
}

func isProtectContainer(n *html.Node) bool {
	if n == nil || n.Type != html.ElementNode {
		return false
	}
	if strings.EqualFold(n.Data, "main") || strings.EqualFold(n.Data, "article") {
		return true
	}
	if strings.EqualFold(attr(n, "role"), "main") {
		return true
	}
	id := strings.ToLower(strings.TrimSpace(attr(n, "id")))
	return id == "main" || id == "content"
}

func isDropped(n *html.Node, inProtect bool) bool {
	if n == nil {
		return true
	}
	if n.Type == html.CommentNode {
		return true
	}
	if n.Type != html.ElementNode {
		return false
	}
	tag := strings.ToLower(n.Data)
	switch tag {
	case "script", "style", "noscript", "svg", "iframe", "template", "link", "meta", "object", "embed":
		return true
	}
	if tag == "input" && strings.EqualFold(attr(n, "type"), "hidden") {
		return true
	}
	if hasAttr(n, "hidden") {
		return true
	}
	if strings.EqualFold(attr(n, "aria-hidden"), "true") {
		return true
	}
	if styleHides(attr(n, "style")) {
		return true
	}
	role := strings.ToLower(attr(n, "role"))
	if role == "navigation" || role == "banner" || role == "contentinfo" || role == "menu" {
		return true
	}
	if tag == "nav" {
		return true
	}
	if (tag == "header" || tag == "footer") && !inProtect {
		return true
	}
	if hasChromeToken(n) {
		return true
	}
	return false
}

func hasChromeToken(n *html.Node) bool {
	vals := strings.Fields(attr(n, "id"))
	vals = append(vals, strings.Fields(attr(n, "class"))...)
	for _, tok := range vals {
		if chromeClassTokens[strings.ToLower(tok)] {
			return true
		}
	}
	return false
}

func styleHides(style string) bool {
	// Match the declarations, not a substring. "backface-visibility:hidden"
	// contains "visibility:hidden" but does not hide the element.
	var b strings.Builder
	b.Grow(len(style))
	for _, r := range style {
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	compact := b.String()
	return cssHiddenDecl(compact, "display:none") || cssHiddenDecl(compact, "visibility:hidden")
}

func cssHiddenDecl(compact, decl string) bool {
	if strings.HasPrefix(compact, decl) {
		return true
	}
	return strings.Contains(compact, ";"+decl)
}

func renderMarkdown(n *html.Node, inProtect bool, listDepth int) string {
	if n == nil || isDropped(n, inProtect) {
		return ""
	}
	if n.Type == html.DocumentNode || (n.Type == html.ElementNode && strings.EqualFold(n.Data, "html")) {
		return renderChildren(n, inProtect || isProtectContainer(n), listDepth)
	}
	if n.Type == html.TextNode {
		// Pure whitespace between blocks is not content. Keep edge spaces
		// when the node also has words, so "hello <b>world</b>" stays apart.
		if strings.TrimSpace(n.Data) == "" {
			return ""
		}
		return collapseWS(n.Data)
	}
	if n.Type != html.ElementNode {
		return renderChildren(n, inProtect, listDepth)
	}
	protect := inProtect || isProtectContainer(n)
	tag := strings.ToLower(n.Data)
	switch tag {
	case "head", "title":
		return ""
	case "br":
		return "\n"
	case "hr":
		return "\n\n---\n\n"
	case "h1", "h2", "h3", "h4", "h5", "h6":
		level := int(tag[1] - '0')
		text := strings.TrimSpace(renderInline(n, protect))
		if text == "" {
			return ""
		}
		return "\n\n" + strings.Repeat("#", level) + " " + text + "\n\n"
	case "p":
		text := strings.TrimSpace(renderInline(n, protect))
		if text == "" {
			return ""
		}
		return "\n\n" + text + "\n\n"
	case "blockquote":
		inner := strings.TrimSpace(renderChildren(n, protect, listDepth))
		if inner == "" {
			return ""
		}
		lines := strings.Split(inner, "\n")
		for i, ln := range lines {
			lines[i] = "> " + ln
		}
		return "\n\n" + strings.Join(lines, "\n") + "\n\n"
	case "pre":
		return "\n\n" + renderPre(n) + "\n\n"
	case "code":
		// If parent is pre, handled there.
		if n.Parent != nil && n.Parent.Type == html.ElementNode && strings.EqualFold(n.Parent.Data, "pre") {
			return rawText(n)
		}
		return "`" + strings.ReplaceAll(rawText(n), "`", "'") + "`"
	case "ul", "ol":
		if listDepth > 0 {
			// Nested list: downgrade to text.
			return " " + strings.TrimSpace(renderInline(n, protect)) + " "
		}
		return "\n\n" + renderList(n, protect, tag == "ol") + "\n\n"
	case "li":
		return strings.TrimSpace(renderInline(n, protect))
	case "table":
		if listDepth > 0 {
			return " " + strings.TrimSpace(renderInline(n, protect)) + " "
		}
		return "\n\n" + renderTable(n, protect) + "\n\n"
	case "a":
		return renderAnchor(n, protect)
	case "img":
		return renderImage(n)
	case "strong", "b":
		t := strings.TrimSpace(renderInline(n, protect))
		if t == "" {
			return ""
		}
		return "**" + t + "**"
	case "em", "i":
		t := strings.TrimSpace(renderInline(n, protect))
		if t == "" {
			return ""
		}
		return "*" + t + "*"
	case "div", "section", "article", "main", "body", "span", "label", "button", "font", "time", "small",
		"header", "footer", "figure", "figcaption", "aside", "summary", "details", "center":
		if isBlockish(tag) {
			inner := strings.TrimSpace(renderChildren(n, protect, listDepth))
			if inner == "" {
				return ""
			}
			return "\n\n" + inner + "\n\n"
		}
		return renderInline(n, protect)
	case "tr", "thead", "tbody", "tfoot", "td", "th", "caption", "colgroup", "col":
		return renderInline(n, protect)
	default:
		return renderChildren(n, protect, listDepth)
	}
}

func isBlockish(tag string) bool {
	switch tag {
	case "div", "section", "article", "main", "body", "header", "footer", "figure", "figcaption", "aside", "details", "center":
		return true
	}
	return false
}

func renderChildren(n *html.Node, inProtect bool, listDepth int) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.WriteString(renderMarkdown(c, inProtect, listDepth))
	}
	return b.String()
}

func renderInline(n *html.Node, inProtect bool) string {
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if isDropped(c, inProtect) {
			continue
		}
		if c.Type == html.TextNode {
			b.WriteString(collapseWS(c.Data))
			continue
		}
		if c.Type == html.ElementNode {
			tag := strings.ToLower(c.Data)
			switch tag {
			case "br":
				b.WriteByte('\n')
			case "img":
				b.WriteString(renderImage(c))
			case "a":
				b.WriteString(renderAnchor(c, inProtect))
			case "strong", "b":
				t := strings.TrimSpace(renderInline(c, inProtect))
				if t != "" {
					b.WriteString("**" + t + "**")
				}
			case "em", "i":
				t := strings.TrimSpace(renderInline(c, inProtect))
				if t != "" {
					b.WriteString("*" + t + "*")
				}
			case "code":
				b.WriteString("`" + strings.ReplaceAll(rawText(c), "`", "'") + "`")
			case "pre":
				b.WriteString(" " + rawText(c) + " ")
			case "ul", "ol", "table":
				// nested structures inside inline: downgrade
				b.WriteString(" " + strings.TrimSpace(rawText(c)) + " ")
			default:
				b.WriteString(renderInline(c, inProtect || isProtectContainer(c)))
			}
		}
	}
	return squeezeInline(b.String())
}

func renderAnchor(n *html.Node, inProtect bool) string {
	text := strings.TrimSpace(renderInline(n, inProtect))
	href := strings.TrimSpace(attr(n, "href"))
	low := strings.ToLower(href)
	if href == "" || strings.HasPrefix(low, "javascript:") || strings.HasPrefix(low, "data:") {
		return text
	}
	if text == "" {
		text = href
	}
	return "[" + text + "](" + href + ")"
}

func renderImage(n *html.Node) string {
	src := strings.TrimSpace(attr(n, "src"))
	alt := strings.TrimSpace(attr(n, "alt"))
	if src == "" && alt == "" {
		return ""
	}
	if alt == "" {
		alt = srcFileName(src)
	}
	return "![" + alt + "](" + src + ")"
}

func srcFileName(src string) string {
	src = strings.TrimSpace(src)
	if i := strings.LastIndexAny(src, "/\\"); i >= 0 && i+1 < len(src) {
		return src[i+1:]
	}
	return src
}

func renderPre(n *html.Node) string {
	text := rawText(n)
	// If a single child is <code>, still raw text.
	ticks := 3
	longest := 0
	cur := 0
	for _, r := range text {
		if r == '`' {
			cur++
			if cur > longest {
				longest = cur
			}
		} else {
			cur = 0
		}
	}
	if longest+1 > ticks {
		ticks = longest + 1
	}
	fence := strings.Repeat("`", ticks)
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return fence + "\n" + text + fence
}

func renderList(n *html.Node, inProtect bool, ordered bool) string {
	var lines []string
	i := 1
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode || !strings.EqualFold(c.Data, "li") {
			continue
		}
		if isDropped(c, inProtect) {
			continue
		}
		item := strings.TrimSpace(renderInline(c, inProtect))
		// Nested lists inside li are downgraded inside renderInline.
		if item == "" {
			item = strings.TrimSpace(rawText(c))
		}
		if ordered {
			lines = append(lines, strconv.Itoa(i)+". "+item)
			i++
		} else {
			lines = append(lines, "- "+item)
		}
	}
	return strings.Join(lines, "\n")
}

func renderTable(n *html.Node, inProtect bool) string {
	// Nested tables: if this table is inside another table, caller already
	// downgraded. Here, nested table children are flattened to text in cells.
	rows := collectTableRows(n, inProtect)
	if len(rows) == 0 {
		return strings.TrimSpace(renderInline(n, inProtect))
	}
	cols := len(rows[0])
	for i := range rows {
		if len(rows[i]) < cols {
			for len(rows[i]) < cols {
				rows[i] = append(rows[i], "")
			}
		} else if len(rows[i]) > cols {
			tail := strings.Join(rows[i][cols-1:], " ")
			rows[i] = append(rows[i][:cols-1], tail)
		}
		for j := range rows[i] {
			rows[i][j] = strings.ReplaceAll(rows[i][j], "|", " ")
			rows[i][j] = strings.ReplaceAll(rows[i][j], "\n", " ")
			rows[i][j] = collapseWS(rows[i][j])
			rows[i][j] = strings.TrimSpace(rows[i][j])
		}
	}
	var b strings.Builder
	writeMDRow := func(cells []string) {
		b.WriteByte('|')
		for _, c := range cells {
			b.WriteByte(' ')
			b.WriteString(c)
			b.WriteString(" |")
		}
		b.WriteByte('\n')
	}
	writeMDRow(rows[0])
	b.WriteByte('|')
	for range rows[0] {
		b.WriteString(" --- |")
	}
	b.WriteByte('\n')
	for _, r := range rows[1:] {
		writeMDRow(r)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func collectTableRows(n *html.Node, inProtect bool) [][]string {
	var rows [][]string
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node == nil || isDropped(node, inProtect) {
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "table") && node != n {
			// Nested table: skip structure, do not emit a nested markdown table.
			return
		}
		if node.Type == html.ElementNode && strings.EqualFold(node.Data, "tr") {
			var cells []string
			for c := node.FirstChild; c != nil; c = c.NextSibling {
				if c.Type != html.ElementNode {
					continue
				}
				tag := strings.ToLower(c.Data)
				if tag != "td" && tag != "th" {
					continue
				}
				if isDropped(c, inProtect) {
					cells = append(cells, "")
					continue
				}
				cells = append(cells, strings.TrimSpace(renderInline(c, inProtect)))
			}
			if len(cells) > 0 {
				rows = append(rows, cells)
			}
			return
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return rows
}

func rawText(n *html.Node) string {
	if n == nil {
		return ""
	}
	if n.Type == html.TextNode {
		return n.Data
	}
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			tag := strings.ToLower(c.Data)
			if tag == "script" || tag == "style" {
				continue
			}
		}
		b.WriteString(rawText(c))
	}
	return b.String()
}

// collapseWS folds every run of unicode whitespace, including newlines, into
// a single space. A whitespace-only string becomes one space so inline
// neighbors ("hello <span>world</span>") stay separated. <br> is a real
// newline inserted by the caller and is not passed through here.
func collapseWS(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	if space {
		b.WriteByte(' ')
	}
	return b.String()
}

func squeezeInline(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r == '\n' {
			b.WriteByte('\n')
			space = false
			continue
		}
		if unicode.IsSpace(r) {
			if b.Len() > 0 && !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		b.WriteRune(r)
		space = false
	}
	return b.String()
}

func collapseBlankLines(s string) string {
	s = strings.TrimSpace(s)
	re := regexp.MustCompile(`\n{3,}`)
	return re.ReplaceAllString(s, "\n\n")
}

// CountVisibleMarkdown counts characters the empty-page fallback treats as content.
func CountVisibleMarkdown(md string) int {
	s := md
	// Fenced code: keep contents, drop fences.
	s = regexp.MustCompile("(?m)^`{3,}.*$").ReplaceAllString(s, "")
	// Images ![alt](url) -> alt
	s = regexp.MustCompile(`!\[([^\]]*)\]\([^)]*\)`).ReplaceAllString(s, "$1")
	// Links [text](url) -> text
	s = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`).ReplaceAllString(s, "$1")
	// Headings, emphasis, lists, tables, blockquotes, hr, inline code ticks
	s = regexp.MustCompile(`(?m)^#{1,6}\s+`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?m)^>\s?`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?m)^(?:[-*]|\d+\.)\s+`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?m)^\s*\|`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?m)\|?\s*---+\s*\|?`).ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "|", " ")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "__", "")
	s = strings.ReplaceAll(s, "*", "")
	s = strings.ReplaceAll(s, "`", "")
	n := 0
	for _, r := range s {
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n
}
