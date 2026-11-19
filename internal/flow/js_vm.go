package flow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// jsUndefined marks an undefined JS value distinct from Go nil (JS null).
type jsUndefined struct{}

var undefinedVal = jsUndefined{}

type jsArray struct {
	elems []any
}

type jsRegex struct {
	pattern string
	flags   string
	re      *regexp.Regexp
}

func compileJSRegex(pattern, flags string) (*jsRegex, error) {
	prefix := ""
	if strings.ContainsRune(flags, 'i') {
		prefix += "i"
	}
	if strings.ContainsRune(flags, 'm') {
		prefix += "m"
	}
	if strings.ContainsRune(flags, 's') {
		prefix += "s"
	}
	goPat := pattern
	if prefix != "" {
		goPat = "(?" + prefix + ")" + pattern
	}
	re, err := regexp.Compile(goPat)
	if err != nil {
		return nil, fmt.Errorf("正则表达式 /%s/%s 无效：%w", pattern, flags, err)
	}
	return &jsRegex{pattern: pattern, flags: flags, re: re}, nil
}

func asJSElems(v any) ([]any, bool) {
	switch x := v.(type) {
	case *jsArray:
		if x == nil {
			return nil, false
		}
		return x.elems, true
	case []any:
		return x, true
	default:
		return nil, false
	}
}

type jsFunction struct {
	name   string
	params []string
	body   *jsBlockStmt
	expr   jsExpr // non-nil for expression-body arrow functions
	env    *jsEnv
}

type jsBuiltin func(thisVal any, args []any) (any, error)

type jsEnv struct {
	parent *jsEnv
	vars   map[string]any
}

func newJSEnv(parent *jsEnv) *jsEnv {
	return &jsEnv{parent: parent, vars: map[string]any{}}
}

func (e *jsEnv) get(name string) (any, bool) {
	for cur := e; cur != nil; cur = cur.parent {
		if v, ok := cur.vars[name]; ok {
			return v, true
		}
	}
	return nil, false
}

func (e *jsEnv) set(name string, val any) {
	for cur := e; cur != nil; cur = cur.parent {
		if _, ok := cur.vars[name]; ok {
			cur.vars[name] = val
			return
		}
	}
	e.vars[name] = val
}

func (e *jsEnv) define(name string, val any) {
	e.vars[name] = val
}

// ---------- Lexer ----------

type tokKind int

const (
	tkEOF tokKind = iota
	tkIdent
	tkNumber
	tkString
	tkTemplate // simple or interpolated handled via parts
	tkRegex
	tkPunct
)

type token struct {
	kind tokKind
	val  string
	pos  int
}

func tokenizeJS(src string) ([]token, error) {
	var out []token
	i := 0
	n := len(src)
	for i < n {
		r, w := utf8.DecodeRuneInString(src[i:])
		if unicode.IsSpace(r) {
			i += w
			continue
		}
		// Line comment
		if i+1 < n && src[i] == '/' && src[i+1] == '/' {
			i += 2
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		// Block comment
		if i+1 < n && src[i] == '/' && src[i+1] == '*' {
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, errors.New("未闭合的多行注释 /*")
			}
			i += 2 + end + 2
			continue
		}
		// Regex literal /pattern/flags
		if src[i] == '/' && prevAllowsRegex(out) {
			start := i
			i++
			var pat strings.Builder
			inClass := false
			closed := false
			for i < n {
				c := src[i]
				if c == '\n' || c == '\r' {
					break
				}
				if c == '\\' && i+1 < n {
					pat.WriteByte(c)
					pat.WriteByte(src[i+1])
					i += 2
					continue
				}
				if c == '[' {
					inClass = true
					pat.WriteByte(c)
					i++
					continue
				}
				if c == ']' && inClass {
					inClass = false
					pat.WriteByte(c)
					i++
					continue
				}
				if c == '/' && !inClass {
					i++
					closed = true
					break
				}
				r2, w2 := utf8.DecodeRuneInString(src[i:])
				pat.WriteRune(r2)
				i += w2
			}
			if !closed {
				return nil, errors.New("未闭合的正则表达式字面量")
			}
			flagStart := i
			for i < n && ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z')) {
				i++
			}
			out = append(out, token{kind: tkRegex, val: pat.String() + "\x00" + src[flagStart:i], pos: start})
			continue
		}
		// String literals
		if src[i] == '"' || src[i] == '\'' || src[i] == '`' {
			quote := src[i]
			start := i
			i++
			var sb strings.Builder
			closed := false
			for i < n {
				c := src[i]
				if c == '\\' && i+1 < n {
					i++
					esc := src[i]
					i++
					switch esc {
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case 't':
						sb.WriteByte('\t')
					case '\\':
						sb.WriteByte('\\')
					case '"':
						sb.WriteByte('"')
					case '\'':
						sb.WriteByte('\'')
					case '`':
						sb.WriteByte('`')
					default:
						sb.WriteByte(esc)
					}
					continue
				}
				if c == quote {
					i++
					closed = true
					break
				}
				r, w := utf8.DecodeRuneInString(src[i:])
				sb.WriteRune(r)
				i += w
			}
			if !closed {
				return nil, errors.New("未闭合的字符串字面量")
			}
			kind := tkString
			if quote == '`' {
				kind = tkTemplate
			}
			out = append(out, token{kind: kind, val: sb.String(), pos: start})
			continue
		}
		// Numbers
		if (src[i] >= '0' && src[i] <= '9') || (src[i] == '.' && i+1 < n && src[i+1] >= '0' && src[i+1] <= '9') {
			start := i
			if src[i] == '0' && i+1 < n && (src[i+1] == 'x' || src[i+1] == 'X') {
				i += 2
				for i < n && strings.ContainsRune("0123456789abcdefABCDEF_", rune(src[i])) {
					i++
				}
			} else {
				for i < n && ((src[i] >= '0' && src[i] <= '9') || src[i] == '.' || src[i] == '_') {
					i++
				}
				if i < n && (src[i] == 'e' || src[i] == 'E') {
					i++
					if i < n && (src[i] == '+' || src[i] == '-') {
						i++
					}
					for i < n && src[i] >= '0' && src[i] <= '9' {
						i++
					}
				}
			}
			numStr := strings.ReplaceAll(src[start:i], "_", "")
			out = append(out, token{kind: tkNumber, val: numStr, pos: start})
			continue
		}
		// Identifiers / keywords
		if isIdentStart(r) {
			start := i
			i += w
			for i < n {
				r2, w2 := utf8.DecodeRuneInString(src[i:])
				if !isIdentPart(r2) {
					break
				}
				i += w2
			}
			out = append(out, token{kind: tkIdent, val: src[start:i], pos: start})
			continue
		}
		// Multi-char operators
		start := i
		matched := ""
		for _, op := range []string{"===", "!==", "...", "=>", "??", "?.", "&&", "||", "==", "!=", "<=", ">=", "++", "--", "+=", "-=", "*=", "/="} {
			if strings.HasPrefix(src[i:], op) {
				matched = op
				break
			}
		}
		if matched != "" {
			i += len(matched)
			out = append(out, token{kind: tkPunct, val: matched, pos: start})
			continue
		}
		out = append(out, token{kind: tkPunct, val: string(src[i]), pos: start})
		i++
	}
	out = append(out, token{kind: tkEOF, pos: n})
	return out, nil
}

func isIdentStart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return isIdentStart(r) || unicode.IsDigit(r)
}

func prevAllowsRegex(out []token) bool {
	if len(out) == 0 {
		return true
	}
	prev := out[len(out)-1]
	switch prev.kind {
	case tkNumber, tkString, tkTemplate, tkRegex:
		return false
	case tkIdent:
		switch prev.val {
		case "return", "throw", "case", "typeof", "in", "of", "new", "delete", "void", "else", "do":
			return true
		default:
			return false
		}
	case tkPunct:
		switch prev.val {
		case ")", "]", "}", "++", "--":
			return false
		default:
			return true
		}
	default:
		return true
	}
}

// ---------- AST ----------

type jsStmt interface{ isStmt() }
type jsExpr interface{ isExpr() }

type jsBlockStmt struct{ stmts []jsStmt }
type jsExprStmt struct{ expr jsExpr }
type jsReturnStmt struct{ expr jsExpr }
type jsBreakStmt struct{}
type jsContinueStmt struct{}
type jsThrowStmt struct{ expr jsExpr }
type jsVarDecl struct {
	names []string
	kind  string // "" | "obj" | "arr"
	init  jsExpr
}
type jsVarStmt struct{ decls []jsVarDecl }
type jsFuncDecl struct {
	name   string
	params []string
	body   *jsBlockStmt
}
type jsIfStmt struct {
	cond jsExpr
	then jsStmt
	els  jsStmt
}
type jsWhileStmt struct {
	cond jsExpr
	body jsStmt
}
type jsForStmt struct {
	init jsStmt
	cond jsExpr
	post jsExpr
	body jsStmt
}
type jsForIterStmt struct {
	name string
	of   bool // true: for..of, false: for..in
	iter jsExpr
	body jsStmt
}
type jsTryStmt struct {
	tryBlock   *jsBlockStmt
	catchName  string
	catchBlock *jsBlockStmt
	finallyBlk *jsBlockStmt
}

func (*jsBlockStmt) isStmt()   {}
func (*jsExprStmt) isStmt()    {}
func (*jsReturnStmt) isStmt()  {}
func (*jsBreakStmt) isStmt()   {}
func (*jsContinueStmt) isStmt() {}
func (*jsThrowStmt) isStmt()   {}
func (*jsVarStmt) isStmt()     {}
func (*jsFuncDecl) isStmt()    {}
func (*jsIfStmt) isStmt()      {}
func (*jsWhileStmt) isStmt()   {}
func (*jsForStmt) isStmt()     {}
func (*jsForIterStmt) isStmt() {}
func (*jsTryStmt) isStmt()     {}

type jsLitExpr struct{ val any }
type jsTemplateExpr struct{ raw string }
type jsIdentExpr struct{ name string }
type jsArrayExpr struct {
	elems  []jsExpr
	spread []bool
}
type jsObjProp struct {
	key    string
	val    jsExpr
	spread bool
}
type jsObjExpr struct{ props []jsObjProp }
type jsFuncExpr struct {
	name   string
	params []string
	body   *jsBlockStmt
	expr   jsExpr
}
type jsUnaryExpr struct {
	op   string
	expr jsExpr
}
type jsUpdateExpr struct {
	op     string
	prefix bool
	target jsExpr
}
type jsBinaryExpr struct {
	op          string
	left, right jsExpr
}
type jsAssignExpr struct {
	op          string // "=" | "+=" | "-=" | "*=" | "/="
	left, right jsExpr
}
type jsTernaryExpr struct {
	cond, thenExpr, elseExpr jsExpr
}
type jsMemberExpr struct {
	obj      jsExpr
	prop     string
	index    jsExpr // non-nil for obj[index]
	optional bool
}
type jsCallExpr struct {
	callee jsExpr
	args   []jsExpr
	spread []bool
}
type jsNewExpr struct {
	callee jsExpr
	args   []jsExpr
}

func (*jsLitExpr) isExpr()      {}
func (*jsTemplateExpr) isExpr() {}
func (*jsIdentExpr) isExpr()    {}
func (*jsArrayExpr) isExpr()    {}
func (*jsObjExpr) isExpr()      {}
func (*jsFuncExpr) isExpr()     {}
func (*jsUnaryExpr) isExpr()    {}
func (*jsUpdateExpr) isExpr()   {}
func (*jsBinaryExpr) isExpr()   {}
func (*jsAssignExpr) isExpr()   {}
func (*jsTernaryExpr) isExpr()  {}
func (*jsMemberExpr) isExpr()   {}
func (*jsCallExpr) isExpr()     {}
func (*jsNewExpr) isExpr()      {}

// ---------- Parser ----------

type jsParser struct {
	toks []token
	pos  int
}

func (p *jsParser) peek() token {
	if p.pos >= len(p.toks) {
		return token{kind: tkEOF}
	}
	return p.toks[p.pos]
}

func (p *jsParser) peekAt(off int) token {
	idx := p.pos + off
	if idx < 0 || idx >= len(p.toks) {
		return token{kind: tkEOF}
	}
	return p.toks[idx]
}

func (p *jsParser) next() token {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *jsParser) match(kind tokKind, val string) bool {
	t := p.peek()
	if t.kind == kind && (val == "" || t.val == val) {
		p.pos++
		return true
	}
	return false
}

func (p *jsParser) expect(kind tokKind, val string) (token, error) {
	t := p.peek()
	if t.kind != kind || (val != "" && t.val != val) {
		return t, fmt.Errorf("JS 语法错误：期望 %q，实际遇到 %q", val, t.val)
	}
	p.pos++
	return t, nil
}

func (p *jsParser) skipSemicolons() {
	for p.match(tkPunct, ";") {
	}
}

func (p *jsParser) parseProgram() (*jsBlockStmt, error) {
	var stmts []jsStmt
	for p.peek().kind != tkEOF {
		p.skipSemicolons()
		if p.peek().kind == tkEOF {
			break
		}
		st, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if st != nil {
			stmts = append(stmts, st)
		}
	}
	return &jsBlockStmt{stmts: stmts}, nil
}

func (p *jsParser) parseBlock() (*jsBlockStmt, error) {
	if _, err := p.expect(tkPunct, "{"); err != nil {
		return nil, err
	}
	var stmts []jsStmt
	for p.peek().kind != tkEOF && !(p.peek().kind == tkPunct && p.peek().val == "}") {
		p.skipSemicolons()
		if p.peek().kind == tkPunct && p.peek().val == "}" {
			break
		}
		st, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		if st != nil {
			stmts = append(stmts, st)
		}
	}
	if _, err := p.expect(tkPunct, "}"); err != nil {
		return nil, err
	}
	return &jsBlockStmt{stmts: stmts}, nil
}

func (p *jsParser) parseStmt() (jsStmt, error) {
	t := p.peek()
	if t.kind == tkPunct && t.val == "{" {
		return p.parseBlock()
	}
	if t.kind == tkPunct && t.val == ";" {
		p.next()
		return nil, nil
	}
	if t.kind == tkIdent {
		switch t.val {
		case "var", "let", "const":
			return p.parseVarStmt(true)
		case "function":
			return p.parseFuncDecl()
		case "return":
			p.next()
			if p.match(tkPunct, ";") || p.peek().kind == tkEOF || (p.peek().kind == tkPunct && p.peek().val == "}") {
				return &jsReturnStmt{}, nil
			}
			// Check if return is on a separate line with nothing after? Usually users end statements with ; or } or next stmt.
			// Still parse expr unless next token starts a statement on a new line? No, standard JS: parse expr.
			ex, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			p.match(tkPunct, ";")
			return &jsReturnStmt{expr: ex}, nil
		case "if":
			p.next()
			if _, err := p.expect(tkPunct, "("); err != nil {
				return nil, err
			}
			cond, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
			thenSt, err := p.parseStmt()
			if err != nil {
				return nil, err
			}
			var elseSt jsStmt
			if p.match(tkIdent, "else") {
				elseSt, err = p.parseStmt()
				if err != nil {
					return nil, err
				}
			}
			return &jsIfStmt{cond: cond, then: thenSt, els: elseSt}, nil
		case "while":
			p.next()
			if _, err := p.expect(tkPunct, "("); err != nil {
				return nil, err
			}
			cond, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
			body, err := p.parseStmt()
			if err != nil {
				return nil, err
			}
			return &jsWhileStmt{cond: cond, body: body}, nil
		case "for":
			return p.parseForStmt()
		case "break":
			p.next()
			p.match(tkPunct, ";")
			return &jsBreakStmt{}, nil
		case "continue":
			p.next()
			p.match(tkPunct, ";")
			return &jsContinueStmt{}, nil
		case "throw":
			p.next()
			ex, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			p.match(tkPunct, ";")
			return &jsThrowStmt{expr: ex}, nil
		case "try":
			return p.parseTryStmt()
		}
	}
	ex, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	p.match(tkPunct, ";")
	return &jsExprStmt{expr: ex}, nil
}

func (p *jsParser) parseVarStmt(eatSemi bool) (jsStmt, error) {
	p.next() // var | let | const
	var decls []jsVarDecl
	for {
		var decl jsVarDecl
		if p.match(tkPunct, "{") {
			decl.kind = "obj"
			for !(p.peek().kind == tkPunct && p.peek().val == "}") {
				id, err := p.expect(tkIdent, "")
				if err != nil {
					return nil, err
				}
				decl.names = append(decl.names, id.val)
				if !p.match(tkPunct, ",") {
					break
				}
			}
			if _, err := p.expect(tkPunct, "}"); err != nil {
				return nil, err
			}
		} else if p.match(tkPunct, "[") {
			decl.kind = "arr"
			for !(p.peek().kind == tkPunct && p.peek().val == "]") {
				id, err := p.expect(tkIdent, "")
				if err != nil {
					return nil, err
				}
				decl.names = append(decl.names, id.val)
				if !p.match(tkPunct, ",") {
					break
				}
			}
			if _, err := p.expect(tkPunct, "]"); err != nil {
				return nil, err
			}
		} else {
			id, err := p.expect(tkIdent, "")
			if err != nil {
				return nil, err
			}
			decl.names = []string{id.val}
		}
		if p.match(tkPunct, "=") {
			init, err := p.parseAssignExpr()
			if err != nil {
				return nil, err
			}
			decl.init = init
		}
		decls = append(decls, decl)
		if !p.match(tkPunct, ",") {
			break
		}
	}
	if eatSemi {
		p.match(tkPunct, ";")
	}
	return &jsVarStmt{decls: decls}, nil
}

func (p *jsParser) parseParamList() ([]string, error) {
	if _, err := p.expect(tkPunct, "("); err != nil {
		return nil, err
	}
	var params []string
	for !(p.peek().kind == tkPunct && p.peek().val == ")") {
		if p.peek().kind == tkEOF {
			return nil, errors.New("未闭合的参数列表")
		}
		id, err := p.expect(tkIdent, "")
		if err != nil {
			return nil, err
		}
		params = append(params, id.val)
		if p.match(tkPunct, "=") {
			// Skip/consume default value expression if present (unused default ignored cleanly)
			if _, err := p.parseAssignExpr(); err != nil {
				return nil, err
			}
		}
		if !p.match(tkPunct, ",") {
			break
		}
	}
	if _, err := p.expect(tkPunct, ")"); err != nil {
		return nil, err
	}
	return params, nil
}

func (p *jsParser) parseFuncDecl() (jsStmt, error) {
	p.next() // function
	id, err := p.expect(tkIdent, "")
	if err != nil {
		return nil, err
	}
	params, err := p.parseParamList()
	if err != nil {
		return nil, err
	}
	body, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	return &jsFuncDecl{name: id.val, params: params, body: body}, nil
}

func (p *jsParser) parseForStmt() (jsStmt, error) {
	p.next() // for
	if _, err := p.expect(tkPunct, "("); err != nil {
		return nil, err
	}
	// Check `for (var/let/const x of/in expr)` or `for (x of/in expr)`
	if p.peek().kind == tkIdent && (p.peek().val == "var" || p.peek().val == "let" || p.peek().val == "const") {
		if p.peekAt(1).kind == tkIdent && p.peekAt(2).kind == tkIdent && (p.peekAt(2).val == "of" || p.peekAt(2).val == "in") {
			p.next()
			name := p.next().val
			kw := p.next().val
			iterExpr, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
			body, err := p.parseStmt()
			if err != nil {
				return nil, err
			}
			return &jsForIterStmt{name: name, of: kw == "of", iter: iterExpr, body: body}, nil
		}
	} else if p.peek().kind == tkIdent && p.peekAt(1).kind == tkIdent && (p.peekAt(1).val == "of" || p.peekAt(1).val == "in") {
		name := p.next().val
		kw := p.next().val
		iterExpr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkPunct, ")"); err != nil {
			return nil, err
		}
		body, err := p.parseStmt()
		if err != nil {
			return nil, err
		}
		return &jsForIterStmt{name: name, of: kw == "of", iter: iterExpr, body: body}, nil
	}

	var init jsStmt
	var err error
	if !p.match(tkPunct, ";") {
		if p.peek().kind == tkIdent && (p.peek().val == "var" || p.peek().val == "let" || p.peek().val == "const") {
			init, err = p.parseVarStmt(false)
		} else {
			ex, eerr := p.parseExpr()
			err = eerr
			init = &jsExprStmt{expr: ex}
		}
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkPunct, ";"); err != nil {
			return nil, err
		}
	}
	var cond jsExpr
	if !p.match(tkPunct, ";") {
		cond, err = p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkPunct, ";"); err != nil {
			return nil, err
		}
	}
	var post jsExpr
	if !p.match(tkPunct, ")") {
		post, err = p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkPunct, ")"); err != nil {
			return nil, err
		}
	}
	body, err := p.parseStmt()
	if err != nil {
		return nil, err
	}
	return &jsForStmt{init: init, cond: cond, post: post, body: body}, nil
}

func (p *jsParser) parseTryStmt() (jsStmt, error) {
	p.next() // try
	tb, err := p.parseBlock()
	if err != nil {
		return nil, err
	}
	st := &jsTryStmt{tryBlock: tb}
	if p.match(tkIdent, "catch") {
		if p.match(tkPunct, "(") {
			id, err := p.expect(tkIdent, "")
			if err != nil {
				return nil, err
			}
			st.catchName = id.val
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
		}
		cb, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		st.catchBlock = cb
	}
	if p.match(tkIdent, "finally") {
		fb, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		st.finallyBlk = fb
	}
	return st, nil
}

func (p *jsParser) parseExpr() (jsExpr, error) {
	return p.parseAssignExpr()
}

func (p *jsParser) parseAssignExpr() (jsExpr, error) {
	// Arrow function detection: `x => ...` or `(a, b) => ...` or `() => ...`
	if p.looksLikeArrow() {
		return p.parseArrowFunc()
	}
	lhs, err := p.parseTernaryExpr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind == tkPunct {
		op := p.peek().val
		if op == "=" || op == "+=" || op == "-=" || op == "*=" || op == "/=" {
			p.next()
			rhs, err := p.parseAssignExpr()
			if err != nil {
				return nil, err
			}
			return &jsAssignExpr{op: op, left: lhs, right: rhs}, nil
		}
	}
	return lhs, nil
}

func (p *jsParser) looksLikeArrow() bool {
	if p.peek().kind == tkIdent && p.peekAt(1).kind == tkPunct && p.peekAt(1).val == "=>" {
		return true
	}
	if p.peek().kind == tkPunct && p.peek().val == "(" {
		depth := 0
		for i := 0; i < 64; i++ {
			t := p.peekAt(i)
			if t.kind == tkEOF {
				return false
			}
			if t.kind == tkPunct && t.val == "(" {
				depth++
			} else if t.kind == tkPunct && t.val == ")" {
				depth--
				if depth == 0 {
					nxt := p.peekAt(i + 1)
					return nxt.kind == tkPunct && nxt.val == "=>"
				}
			}
		}
	}
	return false
}

func (p *jsParser) parseArrowFunc() (jsExpr, error) {
	var params []string
	if p.peek().kind == tkIdent {
		params = []string{p.next().val}
	} else {
		var err error
		params, err = p.parseParamList()
		if err != nil {
			return nil, err
		}
	}
	if _, err := p.expect(tkPunct, "=>"); err != nil {
		return nil, err
	}
	if p.peek().kind == tkPunct && p.peek().val == "{" {
		blk, err := p.parseBlock()
		if err != nil {
			return nil, err
		}
		return &jsFuncExpr{params: params, body: blk}, nil
	}
	ex, err := p.parseAssignExpr()
	if err != nil {
		return nil, err
	}
	return &jsFuncExpr{params: params, expr: ex}, nil
}

func (p *jsParser) parseTernaryExpr() (jsExpr, error) {
	cond, err := p.parseNullishOr()
	if err != nil {
		return nil, err
	}
	if p.match(tkPunct, "?") {
		th, err := p.parseAssignExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tkPunct, ":"); err != nil {
			return nil, err
		}
		el, err := p.parseAssignExpr()
		if err != nil {
			return nil, err
		}
		return &jsTernaryExpr{cond: cond, thenExpr: th, elseExpr: el}, nil
	}
	return cond, nil
}

func (p *jsParser) parseNullishOr() (jsExpr, error) {
	left, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	for p.match(tkPunct, "??") {
		right, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: "??", left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseOr() (jsExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.match(tkPunct, "||") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: "||", left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseAnd() (jsExpr, error) {
	left, err := p.parseEq()
	if err != nil {
		return nil, err
	}
	for p.match(tkPunct, "&&") {
		right, err := p.parseEq()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: "&&", left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseEq() (jsExpr, error) {
	left, err := p.parseRel()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tkPunct && (p.peek().val == "==" || p.peek().val == "!=" || p.peek().val == "===" || p.peek().val == "!==") {
		op := p.next().val
		right, err := p.parseRel()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseRel() (jsExpr, error) {
	left, err := p.parseAdd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tkPunct && (p.peek().val == "<" || p.peek().val == "<=" || p.peek().val == ">" || p.peek().val == ">=") {
		op := p.next().val
		right, err := p.parseAdd()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseAdd() (jsExpr, error) {
	left, err := p.parseMul()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tkPunct && (p.peek().val == "+" || p.peek().val == "-") {
		op := p.next().val
		right, err := p.parseMul()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseMul() (jsExpr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tkPunct && (p.peek().val == "*" || p.peek().val == "/" || p.peek().val == "%") {
		op := p.next().val
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &jsBinaryExpr{op: op, left: left, right: right}
	}
	return left, nil
}

func (p *jsParser) parseUnary() (jsExpr, error) {
	if p.peek().kind == tkPunct && (p.peek().val == "!" || p.peek().val == "-" || p.peek().val == "+") {
		op := p.next().val
		ex, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &jsUnaryExpr{op: op, expr: ex}, nil
	}
	if p.peek().kind == tkPunct && (p.peek().val == "++" || p.peek().val == "--") {
		op := p.next().val
		ex, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &jsUpdateExpr{op: op, prefix: true, target: ex}, nil
	}
	if p.peek().kind == tkIdent && p.peek().val == "typeof" {
		p.next()
		ex, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &jsUnaryExpr{op: "typeof", expr: ex}, nil
	}
	if p.peek().kind == tkIdent && p.peek().val == "new" {
		p.next()
		callee, err := p.parseMember(false)
		if err != nil {
			return nil, err
		}
		var args []jsExpr
		if p.match(tkPunct, "(") {
			for !(p.peek().kind == tkPunct && p.peek().val == ")") {
				a, err := p.parseAssignExpr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				if !p.match(tkPunct, ",") {
					break
				}
			}
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
		}
		return &jsNewExpr{callee: callee, args: args}, nil
	}
	ex, err := p.parseMember(true)
	if err != nil {
		return nil, err
	}
	if p.peek().kind == tkPunct && (p.peek().val == "++" || p.peek().val == "--") {
		op := p.next().val
		return &jsUpdateExpr{op: op, prefix: false, target: ex}, nil
	}
	return ex, nil
}

func (p *jsParser) parseMember(allowCall bool) (jsExpr, error) {
	ex, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		if p.match(tkPunct, ".") {
			id := p.next()
			if id.kind != tkIdent {
				return nil, fmt.Errorf("JS 语法错误：`.` 后面期望属性名，实际遇到 %q", id.val)
			}
			ex = &jsMemberExpr{obj: ex, prop: id.val}
			continue
		}
		if p.match(tkPunct, "?.") {
			if p.match(tkPunct, "[") {
				idx, err := p.parseExpr()
				if err != nil {
					return nil, err
				}
				if _, err := p.expect(tkPunct, "]"); err != nil {
					return nil, err
				}
				ex = &jsMemberExpr{obj: ex, index: idx, optional: true}
				continue
			}
			id := p.next()
			if id.kind != tkIdent {
				return nil, fmt.Errorf("JS 语法错误：`?.` 后面期望属性名，实际遇到 %q", id.val)
			}
			ex = &jsMemberExpr{obj: ex, prop: id.val, optional: true}
			continue
		}
		if p.match(tkPunct, "[") {
			idx, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkPunct, "]"); err != nil {
				return nil, err
			}
			ex = &jsMemberExpr{obj: ex, index: idx}
			continue
		}
		if allowCall && p.match(tkPunct, "(") {
			var args []jsExpr
			var spread []bool
			for !(p.peek().kind == tkPunct && p.peek().val == ")") {
				isSp := p.match(tkPunct, "...")
				a, err := p.parseAssignExpr()
				if err != nil {
					return nil, err
				}
				args = append(args, a)
				spread = append(spread, isSp)
				if !p.match(tkPunct, ",") {
					break
				}
			}
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
			ex = &jsCallExpr{callee: ex, args: args, spread: spread}
			continue
		}
		break
	}
	return ex, nil
}

func (p *jsParser) parsePrimary() (jsExpr, error) {
	t := p.peek()
	switch t.kind {
	case tkNumber:
		p.next()
		if strings.HasPrefix(t.val, "0x") || strings.HasPrefix(t.val, "0X") {
			v, err := strconv.ParseInt(t.val[2:], 16, 64)
			if err != nil {
				return nil, err
			}
			return &jsLitExpr{val: float64(v)}, nil
		}
		if !strings.ContainsAny(t.val, ".eE") {
			if iv, err := strconv.ParseInt(t.val, 10, 64); err == nil {
				return &jsLitExpr{val: iv}, nil
			}
		}
		fv, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return nil, err
		}
		return &jsLitExpr{val: fv}, nil
	case tkString:
		p.next()
		return &jsLitExpr{val: t.val}, nil
	case tkTemplate:
		p.next()
		return &jsTemplateExpr{raw: t.val}, nil
	case tkRegex:
		p.next()
		pat, flags, _ := strings.Cut(t.val, "\x00")
		rx, err := compileJSRegex(pat, flags)
		if err != nil {
			return nil, err
		}
		return &jsLitExpr{val: rx}, nil
	case tkIdent:
		p.next()
		switch t.val {
		case "true":
			return &jsLitExpr{val: true}, nil
		case "false":
			return &jsLitExpr{val: false}, nil
		case "null":
			return &jsLitExpr{val: nil}, nil
		case "undefined":
			return &jsLitExpr{val: undefinedVal}, nil
		case "function":
			name := ""
			if p.peek().kind == tkIdent {
				name = p.next().val
			}
			params, err := p.parseParamList()
			if err != nil {
				return nil, err
			}
			body, err := p.parseBlock()
			if err != nil {
				return nil, err
			}
			return &jsFuncExpr{name: name, params: params, body: body}, nil
		default:
			return &jsIdentExpr{name: t.val}, nil
		}
	case tkPunct:
		switch t.val {
		case "(":
			p.next()
			ex, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tkPunct, ")"); err != nil {
				return nil, err
			}
			return ex, nil
		case "[":
			p.next()
			var elems []jsExpr
			var spread []bool
			for !(p.peek().kind == tkPunct && p.peek().val == "]") {
				if p.peek().kind == tkEOF {
					return nil, errors.New("未闭合的数组字面量")
				}
				isSp := p.match(tkPunct, "...")
				ex, err := p.parseAssignExpr()
				if err != nil {
					return nil, err
				}
				elems = append(elems, ex)
				spread = append(spread, isSp)
				if !p.match(tkPunct, ",") {
					break
				}
			}
			if _, err := p.expect(tkPunct, "]"); err != nil {
				return nil, err
			}
			return &jsArrayExpr{elems: elems, spread: spread}, nil
		case "{":
			p.next()
			var props []jsObjProp
			for !(p.peek().kind == tkPunct && p.peek().val == "}") {
				if p.peek().kind == tkEOF {
					return nil, errors.New("未闭合的对象字面量")
				}
				if p.match(tkPunct, "...") {
					ex, err := p.parseAssignExpr()
					if err != nil {
						return nil, err
					}
					props = append(props, jsObjProp{spread: true, val: ex})
					if !p.match(tkPunct, ",") {
						break
					}
					continue
				}
				kTok := p.next()
				var key string
				switch kTok.kind {
				case tkIdent, tkString, tkNumber:
					key = kTok.val
				default:
					return nil, fmt.Errorf("JS 语法错误：无效的对象属性名 %q", kTok.val)
				}
				if p.match(tkPunct, ":") {
					val, err := p.parseAssignExpr()
					if err != nil {
						return nil, err
					}
					props = append(props, jsObjProp{key: key, val: val})
				} else if kTok.kind == tkIdent && p.peek().kind == tkPunct && p.peek().val == "(" {
					params, err := p.parseParamList()
					if err != nil {
						return nil, err
					}
					body, err := p.parseBlock()
					if err != nil {
						return nil, err
					}
					props = append(props, jsObjProp{key: key, val: &jsFuncExpr{name: key, params: params, body: body}})
				} else if kTok.kind == tkIdent {
					props = append(props, jsObjProp{key: key, val: &jsIdentExpr{name: key}})
				} else {
					return nil, fmt.Errorf("JS 语法错误：对象属性 %q 缺少 ':'", key)
				}
				if !p.match(tkPunct, ",") {
					break
				}
			}
			if _, err := p.expect(tkPunct, "}"); err != nil {
				return nil, err
			}
			return &jsObjExpr{props: props}, nil
		}
	}
	return nil, fmt.Errorf("JS 语法错误：意外的符号 %q", t.val)
}

// ---------- Interpreter ----------

type jsSignalKind int

const (
	sigNone jsSignalKind = iota
	sigReturn
	sigBreak
	sigContinue
)

type jsSignal struct {
	kind jsSignalKind
	val  any
}

type jsVM struct {
	ctx      context.Context
	logs     []string
	callTool func(toolName string, args map[string]any) (any, error)
}

func runBuiltinJS(ctx context.Context, code string, inputMap map[string]any, stepsMap map[string]any, paramsMap map[string]any, callTool func(string, map[string]any) (any, error)) (any, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	toks, err := tokenizeJS(code)
	if err != nil {
		return nil, "", err
	}
	p := &jsParser{toks: toks}
	prog, err := p.parseProgram()
	if err != nil {
		return nil, "", err
	}

	vm := &jsVM{ctx: ctx, callTool: callTool}
	env := vm.newRootEnv(inputMap, stepsMap, paramsMap)

	lastVal, sig, err := vm.execBlock(prog, env, false)
	if err != nil {
		return nil, strings.Join(vm.logs, "\n"), err
	}

	var result any = lastVal
	if sig.kind == sigReturn {
		result = sig.val
	} else if fnVal, ok := env.get("main"); ok {
		if _, isFunc := fnVal.(*jsFunction); isFunc {
			res, callErr := vm.callFunc(fnVal, nil, []any{cloneAny(inputMap), cloneAny(stepsMap)})
			if callErr != nil {
				return nil, strings.Join(vm.logs, "\n"), callErr
			}
			result = res
		}
	}

	if _, isUndef := result.(jsUndefined); isUndef || result == nil {
		if len(vm.logs) > 0 {
			// Fallback to last logged JSON if script used console.log(...) without returning
			if parsed := parseScriptOutputJSON(vm.logs[len(vm.logs)-1]); parsed != nil {
				return toPureJSONValue(parsed), strings.Join(vm.logs, "\n"), nil
			}
		}
		return map[string]any{}, strings.Join(vm.logs, "\n"), nil
	}
	return toPureJSONValue(result), strings.Join(vm.logs, "\n"), nil
}

func cloneAny(v any) any {
	if v == nil {
		return map[string]any{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return normalizeJSONFloatToNum(out)
}

func normalizeJSONFloatToNum(v any) any {
	switch x := v.(type) {
	case float64:
		if x == math.Trunc(x) && x >= math.MinInt64 && x <= math.MaxInt64 {
			return int64(x)
		}
		return x
	case map[string]any:
		for k, val := range x {
			x[k] = normalizeJSONFloatToNum(val)
		}
		return x
	case []any:
		elems := make([]any, len(x))
		for i := range x {
			elems[i] = normalizeJSONFloatToNum(x[i])
		}
		return &jsArray{elems: elems}
	default:
		return v
	}
}

func toPureJSONValue(v any) any {
	switch x := v.(type) {
	case jsUndefined:
		return nil
	case int:
		return int64(x)
	case int64, float64, string, bool:
		return x
	case *jsArray:
		out := make([]any, 0, len(x.elems))
		for _, el := range x.elems {
			out = append(out, toPureJSONValue(el))
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, el := range x {
			out = append(out, toPureJSONValue(el))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if _, u := val.(jsUndefined); !u {
				out[k] = toPureJSONValue(val)
			}
		}
		return out
	default:
		return x
	}
}

func (vm *jsVM) newRootEnv(inputMap, stepsMap, paramsMap map[string]any) *jsEnv {
	env := newJSEnv(nil)
	inObj := cloneAny(inputMap)
	stObj := cloneAny(stepsMap)
	pmObj := cloneAny(paramsMap)
	env.define("input", inObj)
	env.define("steps", stObj)
	env.define("params", pmObj)
	env.define("ctx", map[string]any{"input": inObj, "params": pmObj, "steps": stObj})

	reservedGlobals := map[string]bool{
		"input": true, "steps": true, "params": true, "ctx": true,
		"console": true, "JSON": true, "Object": true, "Array": true,
		"Math": true, "String": true, "Number": true, "Boolean": true,
		"RegExp": true, "Date": true, "callTool": true, "parseInt": true,
		"parseFloat": true, "isNaN": true, "encodeURIComponent": true,
		"decodeURIComponent": true, "main": true,
	}
	if pm, ok := pmObj.(map[string]any); ok {
		for k, v := range pm {
			if k != "" && !reservedGlobals[k] {
				env.define(k, v)
			}
		}
	}

	env.define("callTool", jsBuiltin(func(_ any, args []any) (any, error) {
		if vm.callTool == nil {
			return nil, errors.New("当前脚本执行环境未启用 callTool")
		}
		if len(args) == 0 {
			return nil, errors.New("callTool 需要传入工具名称")
		}
		toolName := strings.TrimSpace(jsToString(args[0]))
		if toolName == "" {
			return nil, errors.New("callTool 工具名称不能为空")
		}
		callArgs := map[string]any{}
		if len(args) >= 2 && args[1] != nil && args[1] != undefinedVal {
			pure := toPureJSONValue(args[1])
			m, ok := pure.(map[string]any)
			if !ok {
				return nil, errors.New("callTool 第二个参数必须是对象")
			}
			callArgs = m
		}
		out, err := vm.callTool(toolName, callArgs)
		if err != nil {
			return nil, err
		}
		return cloneAny(out), nil
	}))

	env.define("RegExp", jsBuiltin(func(_ any, args []any) (any, error) {
		pat := ""
		flags := ""
		if len(args) >= 1 {
			if rx, ok := args[0].(*jsRegex); ok && rx != nil {
				pat = rx.pattern
				flags = rx.flags
			} else {
				pat = jsToString(args[0])
			}
		}
		if len(args) >= 2 && args[1] != undefinedVal {
			flags = jsToString(args[1])
		}
		return compileJSRegex(pat, flags)
	}))

	env.define("console", map[string]any{
		"log": jsBuiltin(func(_ any, args []any) (any, error) {
			parts := make([]string, len(args))
			for i, a := range args {
				switch v := a.(type) {
				case string:
					parts[i] = v
				case map[string]any, *jsArray, []any:
					if b, err := json.Marshal(toPureJSONValue(v)); err == nil {
						parts[i] = string(b)
					} else {
						parts[i] = jsToString(a)
					}
				default:
					parts[i] = jsToString(a)
				}
			}
			vm.logs = append(vm.logs, strings.Join(parts, " "))
			return undefinedVal, nil
		}),
	})

	env.define("JSON", map[string]any{
		"stringify": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return undefinedVal, nil
			}
			val := toPureJSONValue(args[0])
			var b []byte
			var err error
			if len(args) >= 3 && jsToNum(args[2]) > 0 {
				indent := strings.Repeat(" ", int(jsToNum(args[2])))
				b, err = json.MarshalIndent(val, "", indent)
			} else {
				b, err = json.Marshal(val)
			}
			if err != nil {
				return nil, err
			}
			return string(b), nil
		}),
		"parse": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return nil, errors.New("JSON.parse 缺少字符串参数")
			}
			var out any
			if err := json.Unmarshal([]byte(jsToString(args[0])), &out); err != nil {
				return nil, err
			}
			return normalizeJSONFloatToNum(out), nil
		}),
	})

	env.define("Object", map[string]any{
		"keys": jsBuiltin(func(_ any, args []any) (any, error) {
			m, ok := getArgMap(args, 0)
			if !ok {
				return &jsArray{elems: []any{}}, nil
			}
			out := make([]any, 0, len(m))
			for k := range m {
				out = append(out, k)
			}
			return &jsArray{elems: out}, nil
		}),
		"values": jsBuiltin(func(_ any, args []any) (any, error) {
			m, ok := getArgMap(args, 0)
			if !ok {
				return &jsArray{elems: []any{}}, nil
			}
			out := make([]any, 0, len(m))
			for _, v := range m {
				out = append(out, v)
			}
			return &jsArray{elems: out}, nil
		}),
		"entries": jsBuiltin(func(_ any, args []any) (any, error) {
			m, ok := getArgMap(args, 0)
			if !ok {
				return &jsArray{elems: []any{}}, nil
			}
			out := make([]any, 0, len(m))
			for k, v := range m {
				out = append(out, &jsArray{elems: []any{k, v}})
			}
			return &jsArray{elems: out}, nil
		}),
		"assign": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return map[string]any{}, nil
			}
			dst, ok := args[0].(map[string]any)
			if !ok {
				dst = map[string]any{}
			}
			for _, src := range args[1:] {
				if sm, ok := src.(map[string]any); ok {
					for k, v := range sm {
						dst[k] = v
					}
				}
			}
			return dst, nil
		}),
		"fromEntries": jsBuiltin(func(_ any, args []any) (any, error) {
			out := map[string]any{}
			if len(args) > 0 {
				if arr, ok := asJSElems(args[0]); ok {
					for _, item := range arr {
						if pair, ok := asJSElems(item); ok && len(pair) >= 2 {
							out[jsToString(pair[0])] = pair[1]
						}
					}
				}
			}
			return out, nil
		}),
	})

	env.define("Array", map[string]any{
		"isArray": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return false, nil
			}
			_, ok := asJSElems(args[0])
			return ok, nil
		}),
	})

	env.define("Math", map[string]any{
		"floor": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return math.NaN(), nil
			}
			return int64(math.Floor(jsToNum(args[0]))), nil
		}),
		"ceil": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return math.NaN(), nil
			}
			return int64(math.Ceil(jsToNum(args[0]))), nil
		}),
		"round": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return math.NaN(), nil
			}
			return int64(math.Round(jsToNum(args[0]))), nil
		}),
		"abs": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return math.NaN(), nil
			}
			return math.Abs(jsToNum(args[0])), nil
		}),
		"max": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return math.Inf(-1), nil
			}
			best := jsToNum(args[0])
			for _, a := range args[1:] {
				if v := jsToNum(a); v > best {
					best = v
				}
			}
			return normalizeNum(best), nil
		}),
		"min": jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return math.Inf(1), nil
			}
			best := jsToNum(args[0])
			for _, a := range args[1:] {
				if v := jsToNum(a); v < best {
					best = v
				}
			}
			return normalizeNum(best), nil
		}),
	})

	env.define("String", jsBuiltin(func(_ any, args []any) (any, error) {
		if len(args) == 0 {
			return "", nil
		}
		return jsToString(args[0]), nil
	}))
	env.define("Number", jsBuiltin(func(_ any, args []any) (any, error) {
		if len(args) == 0 {
			return int64(0), nil
		}
		return normalizeNum(jsToNum(args[0])), nil
	}))
	env.define("Boolean", jsBuiltin(func(_ any, args []any) (any, error) {
		if len(args) == 0 {
			return false, nil
		}
		return jsTruthy(args[0]), nil
	}))
	env.define("parseInt", jsBuiltin(func(_ any, args []any) (any, error) {
		if len(args) == 0 {
			return math.NaN(), nil
		}
		base := 10
		if len(args) >= 2 {
			b := int(jsToNum(args[1]))
			if b >= 2 && b <= 36 {
				base = b
			}
		}
		v, err := strconv.ParseInt(strings.TrimSpace(jsToString(args[0])), base, 64)
		if err != nil {
			return math.NaN(), nil
		}
		return v, nil
	}))
	env.define("parseFloat", jsBuiltin(func(_ any, args []any) (any, error) {
		if len(args) == 0 {
			return math.NaN(), nil
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(jsToString(args[0])), 64)
		if err != nil {
			return math.NaN(), nil
		}
		return v, nil
	}))
	env.define("encodeURIComponent", jsBuiltin(func(_ any, args []any) (any, error) {
		if len(args) == 0 {
			return "undefined", nil
		}
		return strings.ReplaceAll(urlQueryEscape(jsToString(args[0])), "+", "%20"), nil
	}))
	return env
}

func getArgMap(args []any, i int) (map[string]any, bool) {
	if i >= len(args) {
		return nil, false
	}
	m, ok := args[i].(map[string]any)
	return m, ok
}

func (vm *jsVM) execBlock(b *jsBlockStmt, env *jsEnv, childScope bool) (any, jsSignal, error) {
	scope := env
	if childScope {
		scope = newJSEnv(env)
	}
	// Hoist function declarations first
	for _, st := range b.stmts {
		if fd, ok := st.(*jsFuncDecl); ok {
			scope.define(fd.name, &jsFunction{name: fd.name, params: fd.params, body: fd.body, env: scope})
		}
	}
	var last any = undefinedVal
	for _, st := range b.stmts {
		if _, ok := st.(*jsFuncDecl); ok {
			continue
		}
		v, sig, err := vm.execStmt(st, scope)
		if err != nil {
			return nil, jsSignal{}, err
		}
		if sig.kind != sigNone {
			return v, sig, nil
		}
		last = v
	}
	return last, jsSignal{}, nil
}

func (vm *jsVM) execStmt(st jsStmt, env *jsEnv) (any, jsSignal, error) {
	if err := vm.ctx.Err(); err != nil {
		return nil, jsSignal{}, err
	}
	switch s := st.(type) {
	case *jsBlockStmt:
		return vm.execBlock(s, env, true)
	case *jsExprStmt:
		v, err := vm.evalExpr(s.expr, env)
		return v, jsSignal{}, err
	case *jsReturnStmt:
		var v any = undefinedVal
		if s.expr != nil {
			var err error
			v, err = vm.evalExpr(s.expr, env)
			if err != nil {
				return nil, jsSignal{}, err
			}
		}
		return v, jsSignal{kind: sigReturn, val: v}, nil
	case *jsBreakStmt:
		return undefinedVal, jsSignal{kind: sigBreak}, nil
	case *jsContinueStmt:
		return undefinedVal, jsSignal{kind: sigContinue}, nil
	case *jsThrowStmt:
		v, err := vm.evalExpr(s.expr, env)
		if err != nil {
			return nil, jsSignal{}, err
		}
		return nil, jsSignal{}, errors.New(jsToString(v))
	case *jsFuncDecl:
		env.define(s.name, &jsFunction{name: s.name, params: s.params, body: s.body, env: env})
		return undefinedVal, jsSignal{}, nil
	case *jsVarStmt:
		for _, d := range s.decls {
			var val any = undefinedVal
			if d.init != nil {
				var err error
				val, err = vm.evalExpr(d.init, env)
				if err != nil {
					return nil, jsSignal{}, err
				}
			}
			switch d.kind {
			case "obj":
				m, _ := val.(map[string]any)
				for _, n := range d.names {
					if m != nil {
						if fv, exists := m[n]; exists {
							env.define(n, fv)
							continue
						}
					}
					env.define(n, undefinedVal)
				}
			case "arr":
				arr, _ := asJSElems(val)
				for i, n := range d.names {
					if i < len(arr) {
						env.define(n, arr[i])
					} else {
						env.define(n, undefinedVal)
					}
				}
			default:
				if len(d.names) > 0 {
					env.define(d.names[0], val)
				}
			}
		}
		return undefinedVal, jsSignal{}, nil
	case *jsIfStmt:
		cv, err := vm.evalExpr(s.cond, env)
		if err != nil {
			return nil, jsSignal{}, err
		}
		if jsTruthy(cv) {
			return vm.execStmt(s.then, env)
		}
		if s.els != nil {
			return vm.execStmt(s.els, env)
		}
		return undefinedVal, jsSignal{}, nil
	case *jsWhileStmt:
		for {
			cv, err := vm.evalExpr(s.cond, env)
			if err != nil {
				return nil, jsSignal{}, err
			}
			if !jsTruthy(cv) {
				break
			}
			v, sig, err := vm.execStmt(s.body, env)
			if err != nil {
				return nil, jsSignal{}, err
			}
			if sig.kind == sigReturn {
				return v, sig, nil
			}
			if sig.kind == sigBreak {
				break
			}
		}
		return undefinedVal, jsSignal{}, nil
	case *jsForStmt:
		loopEnv := newJSEnv(env)
		if s.init != nil {
			if _, _, err := vm.execStmt(s.init, loopEnv); err != nil {
				return nil, jsSignal{}, err
			}
		}
		for {
			if s.cond != nil {
				cv, err := vm.evalExpr(s.cond, loopEnv)
				if err != nil {
					return nil, jsSignal{}, err
				}
				if !jsTruthy(cv) {
					break
				}
			}
			v, sig, err := vm.execStmt(s.body, loopEnv)
			if err != nil {
				return nil, jsSignal{}, err
			}
			if sig.kind == sigReturn {
				return v, sig, nil
			}
			if sig.kind == sigBreak {
				break
			}
			if s.post != nil {
				if _, err := vm.evalExpr(s.post, loopEnv); err != nil {
					return nil, jsSignal{}, err
				}
			}
		}
		return undefinedVal, jsSignal{}, nil
	case *jsForIterStmt:
		iv, err := vm.evalExpr(s.iter, env)
		if err != nil {
			return nil, jsSignal{}, err
		}
		loopEnv := newJSEnv(env)
		var items []any
		if s.of {
			if arr, ok := asJSElems(iv); ok {
				items = arr
			} else if str, ok := iv.(string); ok {
				for _, r := range str {
					items = append(items, string(r))
				}
			}
		} else {
			if m, ok := iv.(map[string]any); ok {
				for k := range m {
					items = append(items, k)
				}
			} else if arr, ok := asJSElems(iv); ok {
				for i := range arr {
					items = append(items, strconv.Itoa(i))
				}
			}
		}
		for _, item := range items {
			loopEnv.define(s.name, item)
			v, sig, err := vm.execStmt(s.body, loopEnv)
			if err != nil {
				return nil, jsSignal{}, err
			}
			if sig.kind == sigReturn {
				return v, sig, nil
			}
			if sig.kind == sigBreak {
				break
			}
		}
		return undefinedVal, jsSignal{}, nil
	case *jsTryStmt:
		v, sig, err := vm.execBlock(s.tryBlock, env, true)
		if err != nil && s.catchBlock != nil {
			ce := newJSEnv(env)
			if s.catchName != "" {
				ce.define(s.catchName, map[string]any{"message": err.Error()})
			}
			v, sig, err = vm.execBlock(s.catchBlock, ce, false)
		}
		if s.finallyBlk != nil {
			fv, fsig, ferr := vm.execBlock(s.finallyBlk, env, true)
			if ferr != nil {
				return nil, jsSignal{}, ferr
			}
			if fsig.kind != sigNone {
				return fv, fsig, nil
			}
		}
		return v, sig, err
	}
	return undefinedVal, jsSignal{}, nil
}

func (vm *jsVM) evalExpr(ex jsExpr, env *jsEnv) (any, error) {
	if err := vm.ctx.Err(); err != nil {
		return nil, err
	}
	switch e := ex.(type) {
	case *jsLitExpr:
		return e.val, nil
	case *jsTemplateExpr:
		return vm.evalTemplate(e.raw, env)
	case *jsIdentExpr:
		if v, ok := env.get(e.name); ok {
			return v, nil
		}
		return undefinedVal, nil
	case *jsArrayExpr:
		out := []any{}
		for i, el := range e.elems {
			v, err := vm.evalExpr(el, env)
			if err != nil {
				return nil, err
			}
			if i < len(e.spread) && e.spread[i] {
				if arr, ok := asJSElems(v); ok {
					out = append(out, arr...)
					continue
				}
			}
			out = append(out, v)
		}
		return &jsArray{elems: out}, nil
	case *jsObjExpr:
		out := map[string]any{}
		for _, prop := range e.props {
			v, err := vm.evalExpr(prop.val, env)
			if err != nil {
				return nil, err
			}
			if prop.spread {
				if sm, ok := v.(map[string]any); ok {
					for k, sv := range sm {
						out[k] = sv
					}
				}
				continue
			}
			out[prop.key] = v
		}
		return out, nil
	case *jsFuncExpr:
		return &jsFunction{name: e.name, params: e.params, body: e.body, expr: e.expr, env: env}, nil
	case *jsUnaryExpr:
		v, err := vm.evalExpr(e.expr, env)
		if err != nil {
			return nil, err
		}
		switch e.op {
		case "!":
			return !jsTruthy(v), nil
		case "-":
			return normalizeNum(-jsToNum(v)), nil
		case "+":
			return normalizeNum(jsToNum(v)), nil
		case "typeof":
			return jsTypeof(v), nil
		}
	case *jsUpdateExpr:
		cur, err := vm.evalExpr(e.target, env)
		if err != nil {
			return nil, err
		}
		delta := 1.0
		if e.op == "--" {
			delta = -1.0
		}
		nextVal := normalizeNum(jsToNum(cur) + delta)
		if err := vm.assignTarget(e.target, nextVal, env); err != nil {
			return nil, err
		}
		if e.prefix {
			return nextVal, nil
		}
		return cur, nil
	case *jsTernaryExpr:
		cv, err := vm.evalExpr(e.cond, env)
		if err != nil {
			return nil, err
		}
		if jsTruthy(cv) {
			return vm.evalExpr(e.thenExpr, env)
		}
		return vm.evalExpr(e.elseExpr, env)
	case *jsBinaryExpr:
		if e.op == "&&" {
			lv, err := vm.evalExpr(e.left, env)
			if err != nil {
				return nil, err
			}
			if !jsTruthy(lv) {
				return lv, nil
			}
			return vm.evalExpr(e.right, env)
		}
		if e.op == "||" {
			lv, err := vm.evalExpr(e.left, env)
			if err != nil {
				return nil, err
			}
			if jsTruthy(lv) {
				return lv, nil
			}
			return vm.evalExpr(e.right, env)
		}
		if e.op == "??" {
			lv, err := vm.evalExpr(e.left, env)
			if err != nil {
				return nil, err
			}
			if _, u := lv.(jsUndefined); !u && lv != nil {
				return lv, nil
			}
			return vm.evalExpr(e.right, env)
		}
		lv, err := vm.evalExpr(e.left, env)
		if err != nil {
			return nil, err
		}
		rv, err := vm.evalExpr(e.right, env)
		if err != nil {
			return nil, err
		}
		return evalBinaryOp(e.op, lv, rv)
	case *jsAssignExpr:
		rv, err := vm.evalExpr(e.right, env)
		if err != nil {
			return nil, err
		}
		if e.op != "=" {
			lv, err := vm.evalExpr(e.left, env)
			if err != nil {
				return nil, err
			}
			rv, err = evalBinaryOp(strings.TrimSuffix(e.op, "="), lv, rv)
			if err != nil {
				return nil, err
			}
		}
		if err := vm.assignTarget(e.left, rv, env); err != nil {
			return nil, err
		}
		return rv, nil
	case *jsMemberExpr:
		ov, err := vm.evalExpr(e.obj, env)
		if err != nil {
			return nil, err
		}
		if _, u := ov.(jsUndefined); u || ov == nil {
			if e.optional {
				return undefinedVal, nil
			}
			return nil, fmt.Errorf("无法读取 null 或 undefined 的属性")
		}
		key := e.prop
		if e.index != nil {
			iv, err := vm.evalExpr(e.index, env)
			if err != nil {
				return nil, err
			}
			return vm.readProperty(ov, iv), nil
		}
		return vm.readProperty(ov, key), nil
	case *jsCallExpr:
		var thisVal any = undefinedVal
		var fnVal any
		var err error
		if me, ok := e.callee.(*jsMemberExpr); ok {
			thisVal, err = vm.evalExpr(me.obj, env)
			if err != nil {
				return nil, err
			}
			if _, u := thisVal.(jsUndefined); u || thisVal == nil {
				if me.optional {
					return undefinedVal, nil
				}
				return nil, fmt.Errorf("无法在 null 或 undefined 上调用方法 %s", me.prop)
			}
			if me.index != nil {
				iv, err := vm.evalExpr(me.index, env)
				if err != nil {
					return nil, err
				}
				fnVal = vm.readProperty(thisVal, iv)
			} else {
				fnVal = vm.readProperty(thisVal, me.prop)
			}
		} else {
			fnVal, err = vm.evalExpr(e.callee, env)
			if err != nil {
				return nil, err
			}
		}
		var args []any
		for i, a := range e.args {
			av, err := vm.evalExpr(a, env)
			if err != nil {
				return nil, err
			}
			if i < len(e.spread) && e.spread[i] {
				if arr, ok := asJSElems(av); ok {
					args = append(args, arr...)
					continue
				}
			}
			args = append(args, av)
		}
		return vm.callFunc(fnVal, thisVal, args)
	case *jsNewExpr:
		// Support basic `new Array(...)` / `new Object()` / `new Date()`
		if id, ok := e.callee.(*jsIdentExpr); ok {
			var args []any
			for _, a := range e.args {
				av, err := vm.evalExpr(a, env)
				if err != nil {
					return nil, err
				}
				args = append(args, av)
			}
			switch id.name {
			case "Array":
				return &jsArray{elems: args}, nil
			case "Object":
				return map[string]any{}, nil
			case "RegExp":
				pat, flags := "", ""
				if len(args) >= 1 {
					if rx, ok := args[0].(*jsRegex); ok && rx != nil {
						pat, flags = rx.pattern, rx.flags
					} else {
						pat = jsToString(args[0])
					}
				}
				if len(args) >= 2 && args[1] != undefinedVal {
					flags = jsToString(args[1])
				}
				return compileJSRegex(pat, flags)
			case "Set":
				seen := map[string]bool{}
				out := []any{}
				if len(args) > 0 {
					if arr, ok := asJSElems(args[0]); ok {
						for _, item := range arr {
							k := jsToString(item)
							if !seen[k] {
								seen[k] = true
								out = append(out, item)
							}
						}
					}
				}
				box := &jsArray{elems: out}
				return map[string]any{
					"_items": box,
					"size":   int64(len(out)),
					"values": jsBuiltin(func(_ any, _ []any) (any, error) { return box, nil }),
				}, nil
			case "Error":
				msg := ""
				if len(args) > 0 {
					msg = jsToString(args[0])
				}
				return map[string]any{"message": msg}, nil
			}
		}
		return map[string]any{}, nil
	}
	return undefinedVal, nil
}

func (vm *jsVM) evalTemplate(raw string, env *jsEnv) (string, error) {
	if !strings.Contains(raw, "${") {
		return raw, nil
	}
	var sb strings.Builder
	i := 0
	for i < len(raw) {
		idx := strings.Index(raw[i:], "${")
		if idx < 0 {
			sb.WriteString(raw[i:])
			break
		}
		sb.WriteString(raw[i : i+idx])
		start := i + idx + 2
		depth := 1
		j := start
		for j < len(raw) && depth > 0 {
			if raw[j] == '{' {
				depth++
			} else if raw[j] == '}' {
				depth--
				if depth == 0 {
					break
				}
			}
			j++
		}
		if depth != 0 {
			return "", errors.New("模板字符串 ${...} 未闭合")
		}
		subToks, err := tokenizeJS(raw[start:j])
		if err != nil {
			return "", err
		}
		subParser := &jsParser{toks: subToks}
		subExpr, err := subParser.parseExpr()
		if err != nil {
			return "", err
		}
		v, err := vm.evalExpr(subExpr, env)
		if err != nil {
			return "", err
		}
		sb.WriteString(jsToString(v))
		i = j + 1
	}
	return sb.String(), nil
}

func (vm *jsVM) assignTarget(target jsExpr, val any, env *jsEnv) error {
	switch t := target.(type) {
	case *jsIdentExpr:
		env.set(t.name, val)
		return nil
	case *jsMemberExpr:
		ov, err := vm.evalExpr(t.obj, env)
		if err != nil {
			return err
		}
		if m, ok := ov.(map[string]any); ok {
			key := t.prop
			if t.index != nil {
				iv, err := vm.evalExpr(t.index, env)
				if err != nil {
					return err
				}
				key = jsToString(iv)
			}
			m[key] = val
			return nil
		}
		if box, ok := ov.(*jsArray); ok && t.index != nil {
			iv, err := vm.evalExpr(t.index, env)
			if err != nil {
				return err
			}
			idx := int(jsToNum(iv))
			if idx >= 0 {
				for len(box.elems) <= idx {
					box.elems = append(box.elems, undefinedVal)
				}
				box.elems[idx] = val
				return nil
			}
		}
		if arr, ok := ov.([]any); ok && t.index != nil {
			iv, err := vm.evalExpr(t.index, env)
			if err != nil {
				return err
			}
			idx := int(jsToNum(iv))
			if idx >= 0 && idx < len(arr) {
				arr[idx] = val
				return nil
			}
		}
		return errors.New("赋值目标不支持修改属性")
	}
	return errors.New("无效的赋值目标")
}

func (vm *jsVM) callFunc(fnVal any, thisVal any, args []any) (any, error) {
	switch f := fnVal.(type) {
	case jsBuiltin:
		return f(thisVal, args)
	case *jsFunction:
		callEnv := newJSEnv(f.env)
		for i, pName := range f.params {
			if i < len(args) {
				callEnv.define(pName, args[i])
			} else {
				callEnv.define(pName, undefinedVal)
			}
		}
		if f.expr != nil {
			return vm.evalExpr(f.expr, callEnv)
		}
		_, sig, err := vm.execBlock(f.body, callEnv, false)
		if err != nil {
			return nil, err
		}
		if sig.kind == sigReturn {
			return sig.val, nil
		}
		return undefinedVal, nil
	default:
		return nil, fmt.Errorf("尝试调用非函数类型 (%s)", jsTypeof(fnVal))
	}
}

func (vm *jsVM) readProperty(obj any, key any) any {
	ks := jsToString(key)
	switch o := obj.(type) {
	case map[string]any:
		if v, ok := o[ks]; ok {
			return v
		}
		return undefinedVal
	case *jsArray:
		if ks == "length" {
			return int64(len(o.elems))
		}
		if idx, err := strconv.Atoi(ks); err == nil && idx >= 0 && idx < len(o.elems) {
			return o.elems[idx]
		}
		return vm.arrayMethod(o, ks)
	case []any:
		return vm.readProperty(&jsArray{elems: o}, key)
	case *jsRegex:
		if o == nil {
			return undefinedVal
		}
		switch ks {
		case "source":
			return o.pattern
		case "flags":
			return o.flags
		case "global":
			return strings.ContainsRune(o.flags, 'g')
		case "ignoreCase":
			return strings.ContainsRune(o.flags, 'i')
		case "multiline":
			return strings.ContainsRune(o.flags, 'm')
		case "test":
			return jsBuiltin(func(_ any, args []any) (any, error) {
				if len(args) == 0 {
					return false, nil
				}
				return o.re.MatchString(jsToString(args[0])), nil
			})
		case "exec":
			return jsBuiltin(func(_ any, args []any) (any, error) {
				if len(args) == 0 {
					return nil, nil
				}
				m := o.re.FindStringSubmatch(jsToString(args[0]))
				if m == nil {
					return nil, nil
				}
				elems := make([]any, len(m))
				for i, v := range m {
					elems[i] = v
				}
				return &jsArray{elems: elems}, nil
			})
		}
		return undefinedVal
	case string:
		if ks == "length" {
			return int64(len([]rune(o)))
		}
		if idx, err := strconv.Atoi(ks); err == nil {
			rs := []rune(o)
			if idx >= 0 && idx < len(rs) {
				return string(rs[idx])
			}
		}
		return vm.stringMethod(o, ks)
	}
	return undefinedVal
}

func (vm *jsVM) arrayMethod(box *jsArray, name string) any {
	arr := box.elems
	switch name {
	case "map":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return nil, errors.New("map 需要回调函数")
			}
			out := make([]any, len(cur))
			for i, item := range cur {
				v, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this})
				if err != nil {
					return nil, err
				}
				out[i] = v
			}
			return &jsArray{elems: out}, nil
		})
	case "filter":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return nil, errors.New("filter 需要回调函数")
			}
			out := []any{}
			for i, item := range cur {
				v, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this})
				if err != nil {
					return nil, err
				}
				if jsTruthy(v) {
					out = append(out, item)
				}
			}
			return &jsArray{elems: out}, nil
		})
	case "find":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return nil, errors.New("find 需要回调函数")
			}
			for i, item := range cur {
				v, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this})
				if err != nil {
					return nil, err
				}
				if jsTruthy(v) {
					return item, nil
				}
			}
			return undefinedVal, nil
		})
	case "findIndex":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return int64(-1), nil
			}
			for i, item := range cur {
				v, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this})
				if err != nil {
					return nil, err
				}
				if jsTruthy(v) {
					return int64(i), nil
				}
			}
			return int64(-1), nil
		})
	case "some":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return false, nil
			}
			for i, item := range cur {
				v, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this})
				if err != nil {
					return nil, err
				}
				if jsTruthy(v) {
					return true, nil
				}
			}
			return false, nil
		})
	case "every":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return true, nil
			}
			for i, item := range cur {
				v, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this})
				if err != nil {
					return nil, err
				}
				if !jsTruthy(v) {
					return false, nil
				}
			}
			return true, nil
		})
	case "forEach":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return undefinedVal, nil
			}
			for i, item := range cur {
				if _, err := vm.callFunc(args[0], undefinedVal, []any{item, int64(i), this}); err != nil {
					return nil, err
				}
			}
			return undefinedVal, nil
		})
	case "reduce":
		return jsBuiltin(func(this any, args []any) (any, error) {
			cur, _ := asJSElems(this)
			if len(args) == 0 {
				return nil, errors.New("reduce 需要回调函数")
			}
			var acc any
			start := 0
			if len(args) >= 2 {
				acc = args[1]
			} else if len(cur) > 0 {
				acc = cur[0]
				start = 1
			}
			for i := start; i < len(cur); i++ {
				var err error
				acc, err = vm.callFunc(args[0], undefinedVal, []any{acc, cur[i], int64(i), this})
				if err != nil {
					return nil, err
				}
			}
			return acc, nil
		})
	case "join":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			sep := ","
			if len(args) > 0 {
				sep = jsToString(args[0])
			}
			parts := make([]string, len(arr))
			for i, item := range arr {
				if item == nil || item == undefinedVal {
					parts[i] = ""
				} else {
					parts[i] = jsToString(item)
				}
			}
			return strings.Join(parts, sep), nil
		})
	case "slice":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			start, end := 0, len(arr)
			if len(args) >= 1 {
				start = normSliceIdx(int(jsToNum(args[0])), len(arr))
			}
			if len(args) >= 2 {
				end = normSliceIdx(int(jsToNum(args[1])), len(arr))
			}
			if end < start {
				return &jsArray{elems: []any{}}, nil
			}
			out := make([]any, end-start)
			copy(out, arr[start:end])
			return &jsArray{elems: out}, nil
		})
	case "concat":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			out := append([]any{}, arr...)
			for _, a := range args {
				if more, ok := asJSElems(a); ok {
					out = append(out, more...)
				} else {
					out = append(out, a)
				}
			}
			return &jsArray{elems: out}, nil
		})
	case "includes":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return false, nil
			}
			for _, item := range arr {
				if jsStrictEqual(item, args[0]) {
					return true, nil
				}
			}
			return false, nil
		})
	case "indexOf":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return int64(-1), nil
			}
			for i, item := range arr {
				if jsStrictEqual(item, args[0]) {
					return int64(i), nil
				}
			}
			return int64(-1), nil
		})
	case "push":
		return jsBuiltin(func(this any, args []any) (any, error) {
			if b, ok := this.(*jsArray); ok && b != nil {
				b.elems = append(b.elems, args...)
				return int64(len(b.elems)), nil
			}
			return int64(len(arr) + len(args)), nil
		})
	case "pop":
		return jsBuiltin(func(this any, _ []any) (any, error) {
			if b, ok := this.(*jsArray); ok && b != nil && len(b.elems) > 0 {
				last := b.elems[len(b.elems)-1]
				b.elems = b.elems[:len(b.elems)-1]
				return last, nil
			}
			return undefinedVal, nil
		})
	}
	return undefinedVal
}

func (vm *jsVM) stringMethod(s string, name string) any {
	switch name {
	case "trim":
		return jsBuiltin(func(_ any, _ []any) (any, error) { return strings.TrimSpace(s), nil })
	case "toLowerCase":
		return jsBuiltin(func(_ any, _ []any) (any, error) { return strings.ToLower(s), nil })
	case "toUpperCase":
		return jsBuiltin(func(_ any, _ []any) (any, error) { return strings.ToUpper(s), nil })
	case "split":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) > 0 {
				if rx, ok := args[0].(*jsRegex); ok && rx != nil {
					parts := rx.re.Split(s, -1)
					out := make([]any, len(parts))
					for i, p := range parts {
						out[i] = p
					}
					return &jsArray{elems: out}, nil
				}
			}
			sep := ""
			if len(args) > 0 {
				sep = jsToString(args[0])
			}
			parts := strings.Split(s, sep)
			out := make([]any, len(parts))
			for i, p := range parts {
				out[i] = p
			}
			return &jsArray{elems: out}, nil
		})
	case "slice", "substring":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			rs := []rune(s)
			start, end := 0, len(rs)
			if len(args) >= 1 {
				start = normSliceIdx(int(jsToNum(args[0])), len(rs))
			}
			if len(args) >= 2 {
				end = normSliceIdx(int(jsToNum(args[1])), len(rs))
			}
			if end < start {
				return "", nil
			}
			return string(rs[start:end]), nil
		})
	case "includes":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return false, nil
			}
			return strings.Contains(s, jsToString(args[0])), nil
		})
	case "startsWith":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return false, nil
			}
			return strings.HasPrefix(s, jsToString(args[0])), nil
		})
	case "endsWith":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return false, nil
			}
			return strings.HasSuffix(s, jsToString(args[0])), nil
		})
	case "indexOf":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return int64(-1), nil
			}
			return int64(strings.Index(s, jsToString(args[0]))), nil
		})
	case "replace":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) < 2 {
				return s, nil
			}
			repl := jsToString(args[1])
			if rx, ok := args[0].(*jsRegex); ok && rx != nil {
				if strings.ContainsRune(rx.flags, 'g') {
					return rx.re.ReplaceAllString(s, repl), nil
				}
				loc := rx.re.FindStringSubmatchIndex(s)
				if loc == nil {
					return s, nil
				}
				expanded := rx.re.ExpandString(nil, repl, s, loc)
				return s[:loc[0]] + string(expanded) + s[loc[1]:], nil
			}
			return strings.Replace(s, jsToString(args[0]), repl, 1), nil
		})
	case "replaceAll":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) < 2 {
				return s, nil
			}
			repl := jsToString(args[1])
			if rx, ok := args[0].(*jsRegex); ok && rx != nil {
				return rx.re.ReplaceAllString(s, repl), nil
			}
			return strings.ReplaceAll(s, jsToString(args[0]), repl), nil
		})
	case "match":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return nil, nil
			}
			var rx *jsRegex
			var err error
			if r, ok := args[0].(*jsRegex); ok && r != nil {
				rx = r
			} else {
				rx, err = compileJSRegex(jsToString(args[0]), "")
				if err != nil {
					return nil, err
				}
			}
			if strings.ContainsRune(rx.flags, 'g') {
				all := rx.re.FindAllString(s, -1)
				if len(all) == 0 {
					return nil, nil
				}
				elems := make([]any, len(all))
				for i, v := range all {
					elems[i] = v
				}
				return &jsArray{elems: elems}, nil
			}
			m := rx.re.FindStringSubmatch(s)
			if m == nil {
				return nil, nil
			}
			elems := make([]any, len(m))
			for i, v := range m {
				elems[i] = v
			}
			return &jsArray{elems: elems}, nil
		})
	case "search":
		return jsBuiltin(func(_ any, args []any) (any, error) {
			if len(args) == 0 {
				return int64(0), nil
			}
			var rx *jsRegex
			var err error
			if r, ok := args[0].(*jsRegex); ok && r != nil {
				rx = r
			} else {
				rx, err = compileJSRegex(jsToString(args[0]), "")
				if err != nil {
					return nil, err
				}
			}
			loc := rx.re.FindStringIndex(s)
			if loc == nil {
				return int64(-1), nil
			}
			return int64(loc[0]), nil
		})
	}
	return undefinedVal
}

func normSliceIdx(idx, length int) int {
	if idx < 0 {
		idx = length + idx
	}
	if idx < 0 {
		return 0
	}
	if idx > length {
		return length
	}
	return idx
}

func jsTypeof(v any) string {
	switch v.(type) {
	case jsUndefined:
		return "undefined"
	case nil:
		return "object"
	case bool:
		return "boolean"
	case int, int64, float64:
		return "number"
	case string:
		return "string"
	case *jsFunction, jsBuiltin:
		return "function"
	default:
		return "object"
	}
}

func jsTruthy(v any) bool {
	switch x := v.(type) {
	case jsUndefined, nil:
		return false
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0 && !math.IsNaN(x)
	case string:
		return x != ""
	default:
		return true
	}
}

func jsToString(v any) string {
	switch x := v.(type) {
	case jsUndefined:
		return "undefined"
	case nil:
		return "null"
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		if b, err := json.Marshal(toPureJSONValue(x)); err == nil {
			return string(b)
		}
		return fmt.Sprint(x)
	}
}

func jsToNum(v any) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	case nil:
		return 0
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return math.NaN()
		}
		return f
	default:
		return math.NaN()
	}
}

func normalizeNum(f float64) any {
	if !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f) && f >= math.MinInt64 && f <= math.MaxInt64 {
		return int64(f)
	}
	return f
}

func jsStrictEqual(a, b any) bool {
	if a == nil && b == nil {
		return true
	}
	if _, ua := a.(jsUndefined); ua {
		_, ub := b.(jsUndefined)
		return ub
	}
	if _, ub := b.(jsUndefined); ub {
		return false
	}
	if jsIsNum(a) && jsIsNum(b) {
		return jsToNum(a) == jsToNum(b)
	}
	if sa, ok := a.(string); ok {
		sb, ok2 := b.(string)
		return ok2 && sa == sb
	}
	if ba, ok := a.(bool); ok {
		bb, ok2 := b.(bool)
		return ok2 && ba == bb
	}
	return false
}

func jsIsNum(v any) bool {
	switch v.(type) {
	case int, int64, float64:
		return true
	}
	return false
}

func evalBinaryOp(op string, l, r any) (any, error) {
	switch op {
	case "+":
		if _, ok := l.(string); ok {
			return jsToString(l) + jsToString(r), nil
		}
		if _, ok := r.(string); ok {
			return jsToString(l) + jsToString(r), nil
		}
		return normalizeNum(jsToNum(l) + jsToNum(r)), nil
	case "-":
		return normalizeNum(jsToNum(l) - jsToNum(r)), nil
	case "*":
		return normalizeNum(jsToNum(l) * jsToNum(r)), nil
	case "/":
		rv := jsToNum(r)
		if rv == 0 {
			return math.Inf(1), nil
		}
		return normalizeNum(jsToNum(l) / rv), nil
	case "%":
		li := int64(jsToNum(l))
		ri := int64(jsToNum(r))
		if ri == 0 {
			return math.NaN(), nil
		}
		return li % ri, nil
	case "===":
		return jsStrictEqual(l, r), nil
	case "!==":
		return !jsStrictEqual(l, r), nil
	case "==":
		if (l == nil || l == undefinedVal) && (r == nil || r == undefinedVal) {
			return true, nil
		}
		return jsStrictEqual(l, r) || (jsIsNum(l) != jsIsNum(r) && (jsIsNum(l) || jsIsNum(r)) && jsToNum(l) == jsToNum(r)), nil
	case "!=":
		eq, _ := evalBinaryOp("==", l, r)
		return !eq.(bool), nil
	case "<":
		if sa, ok := l.(string); ok {
			if sb, ok := r.(string); ok {
				return sa < sb, nil
			}
		}
		return jsToNum(l) < jsToNum(r), nil
	case "<=":
		if sa, ok := l.(string); ok {
			if sb, ok := r.(string); ok {
				return sa <= sb, nil
			}
		}
		return jsToNum(l) <= jsToNum(r), nil
	case ">":
		if sa, ok := l.(string); ok {
			if sb, ok := r.(string); ok {
				return sa > sb, nil
			}
		}
		return jsToNum(l) > jsToNum(r), nil
	case ">=":
		if sa, ok := l.(string); ok {
			if sb, ok := r.(string); ok {
				return sa >= sb, nil
			}
		}
		return jsToNum(l) >= jsToNum(r), nil
	}
	return undefinedVal, fmt.Errorf("不支持的操作符 %s", op)
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '!' || c == '~' || c == '*' || c == '\'' || c == '(' || c == ')' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
