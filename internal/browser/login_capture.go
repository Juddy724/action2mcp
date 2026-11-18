package browser

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

func normalizeOrigin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

const credBindingName = "__a2mCaptureCreds"

// CapturedCreds holds login credentials observed from DOM interactions in a login tab.
type CapturedCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
	LoginURL string `json:"login_url"`
}

type credPayload struct {
	U   string `json:"u"`
	P   string `json:"p"`
	URL string `json:"url"`
}

func mergeCapturedCreds(cur CapturedCreds, u, p, rawURL string) CapturedCreds {
	if u != "" {
		cur.Username = u
	}
	if p != "" {
		cur.Password = p
		if rawURL != "" {
			cur.LoginURL = rawURL
		}
	}
	return cur
}

func (bs *Session) recordCapturedBinding(sessionID, payload string) {
	if bs == nil || sessionID == "" || payload == "" {
		return
	}
	var pl credPayload
	if err := json.Unmarshal([]byte(payload), &pl); err != nil {
		return
	}
	bs.mu.Lock()
	if bs.captured == nil {
		bs.captured = map[string]CapturedCreds{}
	}
	bs.captured[sessionID] = mergeCapturedCreds(bs.captured[sessionID], pl.U, pl.P, pl.URL)
	bs.mu.Unlock()
}

// InstallLoginCapture installs a CDP binding and DOM listeners on t to capture username/password inputs.
func (t *Tab) InstallLoginCapture() error {
	if t == nil || t.bs == nil {
		return errors.New("登录窗口不可用")
	}
	if err := t.bs.call(t.session, "Page.enable", nil, nil); err != nil {
		return err
	}
	if err := t.bs.call(t.session, "Runtime.enable", nil, nil); err != nil {
		return err
	}
	if err := t.bs.call(t.session, "Runtime.addBinding", map[string]any{"name": credBindingName}, nil); err != nil {
		return err
	}
	if err := t.bs.call(t.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": loginCaptureJS}, nil); err != nil {
		return err
	}
	if err := t.bs.call(t.session, "Runtime.evaluate", map[string]any{"expression": loginCaptureJS}, nil); err != nil {
		debugf("install login capture evaluate: %v", err)
	}
	return nil
}

// ReadCapturedCreds returns captured login credentials for t, merging any live DOM fallback values.
func (t *Tab) ReadCapturedCreds() CapturedCreds {
	if t == nil || t.bs == nil {
		return CapturedCreds{}
	}
	t.bs.mu.Lock()
	cur := t.bs.captured[t.session]
	t.bs.mu.Unlock()

	var raw string
	if err := t.Eval(readLoginCaptureJS, &raw); err == nil && raw != "" {
		var snap credPayload
		if json.Unmarshal([]byte(raw), &snap) == nil {
			updated := cur
			if snap.P != "" {
				updated = mergeCapturedCreds(updated, snap.U, snap.P, snap.URL)
			} else if snap.U != "" && updated.Username == "" {
				updated.Username = snap.U
			}
			if updated != cur {
				cur = updated
				t.bs.mu.Lock()
				if t.bs.captured == nil {
					t.bs.captured = map[string]CapturedCreds{}
				}
				t.bs.captured[t.session] = cur
				t.bs.mu.Unlock()
			}
		}
	}
	return cur
}

func shouldDropOriginCookie(c Cookie, origin string, includeParentCookies bool) bool {
	origin = normalizeOrigin(origin)
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(c.Domain)), ".")
	if d == "" {
		return false
	}
	if d == host || strings.HasSuffix(d, "."+host) {
		return true
	}
	if includeParentCookies && strings.HasSuffix(host, "."+d) {
		return true
	}
	return false
}

// ClearOriginState clears localStorage, sessionStorage, and matching cookies for origin on the live browser.
func (bs *Session) ClearOriginState(origin string, includeParentCookies bool) {
	if bs == nil {
		return
	}
	origin = normalizeOrigin(origin)
	if origin == "" {
		return
	}
	bs.call("", "Storage.clearDataForOrigin", map[string]any{
		"origin":       origin,
		"storageTypes": "local_storage,session_storage",
	}, nil)
	cs, err := bs.Cookies()
	if err != nil {
		return
	}
	kept := make([]Cookie, 0, len(cs))
	dropped := 0
	for _, c := range cs {
		if shouldDropOriginCookie(c, origin, includeParentCookies) {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	if dropped > 0 {
		bs.call("", "Storage.clearCookies", nil, nil)
		bs.SetCookies(kept)
	}
}

// ClearOriginState clears matching cookies from the local repository and live browser (or queues for next launch).
func (a *Manager) ClearOriginState(origin string, includeParentCookies bool) {
	if a == nil {
		return
	}
	origin = normalizeOrigin(origin)
	if origin == "" {
		return
	}
	filterRepo := func() {
		if a.repo == nil {
			return
		}
		all := a.repo.AllCookies()
		kept := make([]Cookie, 0, len(all))
		for _, c := range all {
			if !shouldDropOriginCookie(c, origin, includeParentCookies) {
				kept = append(kept, c)
			}
		}
		a.repo.ReplaceCookies(kept)
	}

	filterRepo()

	a.mu.Lock()
	var bs *Session
	if a.browser != nil && a.browser.Alive() {
		bs = a.browser
	} else {
		a.recordPendingClear(origin, includeParentCookies)
	}
	a.mu.Unlock()

	if bs != nil {
		bs.ClearOriginState(origin, includeParentCookies)
		if !bs.Alive() {
			a.recordPendingClear(origin, includeParentCookies)
		}
		filterRepo()
	}
}

func (a *Manager) recordPendingClear(origin string, includeParentCookies bool) {
	a.clearMu.Lock()
	if a.pendingClears == nil {
		a.pendingClears = map[string]bool{}
	}
	a.pendingClears[origin] = a.pendingClears[origin] || includeParentCookies
	a.clearMu.Unlock()
}

func (a *Manager) drainPendingClears() map[string]bool {
	a.clearMu.Lock()
	out := a.pendingClears
	a.pendingClears = nil
	a.clearMu.Unlock()
	return out
}

const loginCaptureCoreJS = `
  var passSet = typeof WeakSet !== 'undefined' ? new WeakSet() : null;
  var codeRe = /(captcha|verify|vcode|checkcode|sms|otp|验证码|动态码)/i;
  var searchRe = /(search|query|keyword|搜索|查找)/i;
  var userRe = /(user|account|login|mail|phone|mobile|账号|帐号|用户名|手机|邮箱)/i;
  var allowedTypes = {'': 1, 'text': 1, 'email': 1, 'tel': 1, 'number': 1};

  function isPassAttr(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    var t = (el.getAttribute && el.getAttribute('type')) || el.type || '';
    return String(t).toLowerCase() === 'password';
  }

  function markPass(el) {
    if (!el || el.tagName !== 'INPUT') return;
    try { el.__a2mIsPass = true; } catch (e) {}
    if (passSet) passSet.add(el);
  }

  function markIfPass(el) {
    if (isPassAttr(el)) markPass(el);
  }

  function isPass(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    if (isPassAttr(el)) {
      markPass(el);
      return true;
    }
    return !!(el.__a2mIsPass || (passSet && passSet.has(el)));
  }

  function scan(root) {
    if (!root || !root.querySelectorAll) return;
    var inputs = root.querySelectorAll('input');
    for (var i = 0; i < inputs.length; i++) {
      markIfPass(inputs[i]);
    }
  }

  function isVisible(el) {
    if (!el || el.disabled) return false;
    var rawType = String((el.getAttribute && el.getAttribute('type')) || el.type || '').toLowerCase().trim();
    if (rawType === 'hidden') return false;
    if (typeof window !== 'undefined' && window.getComputedStyle) {
      var cs = window.getComputedStyle(el);
      if (cs && (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0')) return false;
    }
    if (el.offsetParent !== null || el.offsetWidth > 0 || el.offsetHeight > 0) return true;
    if (el.getClientRects && el.getClientRects().length > 0) return true;
    return false;
  }

  function attrText(el) {
    if (!el) return '';
    return [
      el.name || '',
      el.id || '',
      el.placeholder || '',
      (el.getAttribute && el.getAttribute('autocomplete')) || '',
      (el.getAttribute && el.getAttribute('aria-label')) || ''
    ].join(' ');
  }

  function isCandidateUserInput(el, passEl) {
    if (!el || el.tagName !== 'INPUT' || el === passEl || isPass(el)) return false;
    if (!isVisible(el)) return false;
    var rawType = String((el.getAttribute && el.getAttribute('type')) || el.type || '').toLowerCase().trim();
    if (!allowedTypes[rawType]) return false;
    if (codeRe.test(attrText(el))) return false;
    return true;
  }

  function precedes(a, b) {
    if (!a || !b || !a.compareDocumentPosition) return false;
    return !!(a.compareDocumentPosition(b) & 4);
  }

  function pickBestCandidate(cands, passEl) {
    var best = null;
    var bestScore = -1e9;
    for (var i = 0; i < cands.length; i++) {
      var el = cands[i];
      var rawType = String((el.getAttribute && el.getAttribute('type')) || el.type || '').toLowerCase().trim();
      var info = attrText(el) + ' ' + rawType;
      var score = 0;
      if (precedes(el, passEl)) score += 100;
      if (userRe.test(info)) score += 50;
      if (searchRe.test(info)) score -= 60;
      if (String(el.value || '').trim() !== '') score += 20;
      if (precedes(el, passEl)) score += i * 0.01;
      if (score > bestScore) {
        bestScore = score;
        best = el;
      }
    }
    return best;
  }

  function findUserForPass(passEl) {
    var scopes = [];
    if (passEl.form) scopes.push(passEl.form);
    if (passEl.closest) {
      var f = passEl.closest('form');
      if (f && scopes.indexOf(f) < 0) scopes.push(f);
      var cur = passEl.parentElement;
      while (cur && cur !== document.body && cur !== document.documentElement) {
        if (cur.matches && cur.matches('[class*="login"],[id*="login"],[class*="auth"],[class*="sign"],[class*="form"]')) {
          if (scopes.indexOf(cur) < 0) scopes.push(cur);
        }
        cur = cur.parentElement;
      }
    }
    if (document.body) scopes.push(document.body);
    scopes.push(document);

    for (var s = 0; s < scopes.length; s++) {
      var root = scopes[s];
      if (!root || !root.querySelectorAll) continue;
      var inputs = root.querySelectorAll('input');
      var cands = [];
      for (var i = 0; i < inputs.length; i++) {
        if (isCandidateUserInput(inputs[i], passEl)) cands.push(inputs[i]);
      }
      if (cands.length > 0) {
        var picked = pickBestCandidate(cands, passEl);
        if (picked) return String(picked.value || '').trim();
      }
    }
    return '';
  }

  function findPassState(target) {
    scan(document);
    if (target && isPass(target) && String(target.value || '') !== '') {
      return {passEl: target, hasVisPass: true};
    }
    var inputs = document.querySelectorAll ? document.querySelectorAll('input') : [];
    var visWithVal = null, visAny = null, anyWithVal = null;
    for (var i = 0; i < inputs.length; i++) {
      var el = inputs[i];
      if (!isPass(el)) continue;
      var vis = isVisible(el);
      var hasVal = String(el.value || '') !== '';
      if (vis && hasVal && !visWithVal) visWithVal = el;
      if (vis && !visAny) visAny = el;
      if (hasVal && !anyWithVal) anyWithVal = el;
    }
    return {passEl: visWithVal || anyWithVal || visAny, hasVisPass: !!visAny};
  }

  function findStep1User() {
    var inputs = document.querySelectorAll ? document.querySelectorAll('input') : [];
    var matches = [];
    for (var i = 0; i < inputs.length; i++) {
      var el = inputs[i];
      if (!isCandidateUserInput(el, null)) continue;
      var rawType = String((el.getAttribute && el.getAttribute('type')) || el.type || '').toLowerCase().trim();
      var info = attrText(el) + ' ' + rawType;
      if (searchRe.test(info)) continue;
      if (userRe.test(info)) matches.push(el);
    }
    if (matches.length === 1) {
      var v = String(matches[0].value || '').trim();
      if (v !== '') return v;
    }
    return '';
  }

  function extractSnapshot(target, allowStep1) {
    var st = findPassState(target);
    var href = String((typeof location !== 'undefined' && location.href) || '');
    if (st.passEl && String(st.passEl.value || '') !== '') {
      return {u: findUserForPass(st.passEl), p: String(st.passEl.value), url: href};
    }
    if (allowStep1 && !st.hasVisPass) {
      var u = findStep1User();
      if (u !== '') return {u: u, p: '', url: href};
    }
    return null;
  }
`

const loginCaptureJS = `(function(){try{
  if (window.__a2mLoginCaptureInstalled) return;
  window.__a2mLoginCaptureInstalled = true;
` + loginCaptureCoreJS + `
  window.__a2mReadCreds = function() {
    var snap = extractSnapshot(null, true) || {u: '', p: '', url: String((typeof location !== 'undefined' && location.href) || '')};
    return JSON.stringify(snap);
  };

  var lastSent = '';
  function report(target, allowStep1) {
    try {
      var snap = extractSnapshot(target, allowStep1);
      if (!snap) return;
      var payload = JSON.stringify(snap);
      if (payload === lastSent) return;
      if (typeof window.` + credBindingName + ` === 'function') {
        lastSent = payload;
        window.` + credBindingName + `(payload);
      }
    } catch (e) {}
  }

  scan(document);
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { scan(document); }, true);
  }
  if (typeof MutationObserver !== 'undefined') {
    var obs = new MutationObserver(function(muts) {
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type === 'attributes' && m.target && m.target.tagName === 'INPUT') {
          if (isPassAttr(m.target) || String(m.oldValue || '').toLowerCase() === 'password') {
            markPass(m.target);
          }
        } else if (m.addedNodes) {
          for (var j = 0; j < m.addedNodes.length; j++) {
            var n = m.addedNodes[j];
            if (!n || n.nodeType !== 1) continue;
            if (n.tagName === 'INPUT') markIfPass(n);
            else scan(n);
          }
        }
      }
    });
    var rootNode = document.documentElement || document;
    if (rootNode) {
      obs.observe(rootNode, {childList: true, subtree: true, attributes: true, attributeFilter: ['type'], attributeOldValue: true});
    }
  }

  document.addEventListener('focusin', function(e) { markIfPass(e && e.target); scan(document); }, true);
  document.addEventListener('input', function(e) { markIfPass(e && e.target); report(e && e.target, false); }, true);
  document.addEventListener('change', function(e) { markIfPass(e && e.target); report(e && e.target, false); }, true);
  document.addEventListener('submit', function(e) { report(e && e.target, true); }, true);
  document.addEventListener('click', function(e) { report(e && e.target, true); }, true);
  document.addEventListener('keydown', function(e) {
    if (e && (e.key === 'Enter' || e.keyCode === 13)) report(e.target, true);
  }, true);
}catch(e){}})();`

const readLoginCaptureJS = `(function(){try{
  if (typeof window.__a2mReadCreds === 'function') return window.__a2mReadCreds();
` + loginCaptureCoreJS + `
  var snap = extractSnapshot(null, true) || {u: '', p: '', url: String((typeof location !== 'undefined' && location.href) || '')};
  return JSON.stringify(snap);
}catch(e){return '';}})()`
