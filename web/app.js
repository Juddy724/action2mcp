'use strict';
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let STATUS = {};
let ROUTE = '';

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = typeof body === 'string' ? body : JSON.stringify(body); }
  const r = await fetch(path, opt);
  const t = await r.text();
  let j; try { j = t ? JSON.parse(t) : {}; } catch { j = { error: t }; }
  if (!r.ok) { const e = new Error(j.error || ('HTTP ' + r.status)); e.status = r.status; throw e; }
  return j;
}
function toast(msg, ms = 2600) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove('show'), ms); }
function openModal(html) { $('#modal-body').innerHTML = html; $('#modal').classList.remove('hidden'); }
function closeModal() { $('#modal').classList.add('hidden'); $('#modal-body').innerHTML = ''; }
function methodBadge(m) { return `<span class="badge m-${esc(m)}">${esc(m)}</span>`; }
function shortURL(u) { try { const x = new URL(u); return x.pathname + x.search; } catch { return u; } }
function hostOf(u) { try { return new URL(u).host; } catch { return ''; } }
function fmtSize(n) { if (!n) return '-'; if (n < 1024) return n + ' B'; return (n / 1024).toFixed(1) + ' KB'; }
function pretty(s) { if (!s) return ''; try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; } }

// ---------- status bar ----------
async function refreshStatus() {
  try { STATUS = await api('GET', '/api/status'); } catch { $('#statusbar').innerHTML = '<span class="pill">服务未连接</span>'; return; }
  const s = STATUS;
  let h = '';
  if (s.recording) {
    h = `<span class="pill recording"><span class="dot"></span>录制中「${esc(s.recording_name)}」· 已捕获 ${s.captured} 个请求 · ${s.recording_secs}s</span><button class="rec" onclick="stopRec()">■ 结束录制</button>`;
  } else {
    h = s.mcp_mode === 'flat'
      ? `<span class="pill">AI 当前可见 <b style="margin:0 3px">${s.exposed_tools}</b> 个工具</span>`
      : `<span class="pill" title="阶梯模式：AI 先看到 4 个入口工具，再按需加载流程包">阶梯模式 · <b style="margin:0 3px">${s.enabled_packs}</b> 个流程包 / ${s.exposed_tools} 个工具可加载</span>`;
  }
  $('#statusbar').innerHTML = h;
  const upBtn = $('#update-btn');
  if (upBtn) {
    if (s.update && s.update.available && s.update.latest_version) {
      const label = `⬆ 发现新版本 v${s.update.latest_version}`;
      if (upBtn.textContent !== label) upBtn.textContent = label;
      upBtn.hidden = false;
    } else {
      upBtn.hidden = true;
    }
  }
  if (!s.recording && s.last_stop && refreshStatus._lastStopID !== undefined && s.last_stop.recording_id !== refreshStatus._lastStopID) {
    showRecordingStopped(s.last_stop);
    if (ROUTE.startsWith('recordings')) render();
  }
  if (s.recording && ROUTE === 'recordings') { const el = $('#live-count'); if (el) el.textContent = s.captured; }
  if (refreshStatus._lastStopID === undefined) refreshStatus._lastStopID = s.last_stop?.recording_id || 0;
}
setInterval(refreshStatus, 1500);

function showRecordingStopped(info) {
  if (refreshStatus._lastStopID === info.recording_id) return;
  refreshStatus._lastStopID = info.recording_id;
  const login = info.login_detection;
  const notice = login?.detected || login?.action === 'error' ? login : null;
  if (notice) REC_STATE.loginResults[info.recording_id] = notice;
  toast(`录制已结束：捕获 ${info.count} 个请求，${info.useful} 个可能有用${notice ? '。' + notice.message : ''}`, notice ? 6500 : 2600);
}

async function startRec() {
  const name = $('#rec-name').value.trim();
  const url = $('#rec-url').value.trim();
  if (!name) { toast('请先给这次录制起个名字，比如「查询客户」'); $('#rec-name').focus(); return; }
  const b = $('#rec-btn'); b.disabled = true; b.textContent = '正在打开浏览器…';
  try {
    await api('POST', '/api/recordings/start', { name, url });
    localStorage.setItem('a2m_last_url', url);
    toast('已打开专用浏览器，请在里面操作。完成后点击页面右下角「结束录制」');
    await refreshStatus(); render();
  } catch (e) { toast('开始录制失败：' + e.message, 5000); b.disabled = false; b.textContent = '● 开始录制'; }
}
async function stopRec() {
  try { const r = await api('POST', '/api/recordings/stop', { reason: 'console' }); showRecordingStopped(r); await refreshStatus(); location.hash = '#/recordings/' + r.recording_id; render(); }
  catch (e) { toast(e.message); }
}
async function openLogin() {
  const url = prompt('要登录的网站地址（可留空）', localStorage.getItem('a2m_last_url') || '');
  if (url === null) return;
  try { await api('POST', '/api/browser/open', { url }); toast('已打开专用浏览器，登录完成后可以直接关闭窗口'); } catch (e) { toast(e.message, 5000); }
}

// ---------- router ----------
async function render() {
  const h = location.hash.replace(/^#\/?/, '') || 'recordings';
  ROUTE = h;
  const top = h.split('/')[0];
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a.dataset.nav === top));
  const app = $('#app');
  try {
    if (h === 'recordings') await pageRecordings(app);
    else if (h.startsWith('recordings/')) await pageRecording(app, +h.split('/')[1]);
    else if (h === 'tools') await pageTools(app);
    else if (h === 'approvals') await pageApprovals(app);
    else if (h === 'packs') await pagePacks(app);
    else if (h === 'settings') await pageSettings(app);
    else if (h === 'sites') await pageSites(app);
    else if (h === 'vault') await pageVault(app);
    else if (h === 'middleware') await pageMiddleware(app);
    else await pageRecordings(app);
  } catch (e) { app.innerHTML = `<div class="card notice">加载失败：${esc(e.message)}</div>`; }
}
window.addEventListener('hashchange', render);

// ---------- approvals ----------
const APPROVAL_TITLE = document.title;
const APPROVAL_SECRET_UNCHANGED = '******（未改动）';
const APPROVAL_STATUS_LABELS = { pending: '待审批', approved: '已通过', edited: '修改后通过', rejected: '已拒绝', timeout: '已超时', cancelled: '已取消' };
const APPROVALS = { pending: [], sessions: new Map(), polling: false, listEpoch: 0, soundEnabled: false, audio: null };
try { APPROVALS.soundEnabled = localStorage.getItem('a2m_approval_sound') === '1'; } catch { }

function updateApprovalSoundButton() {
  const btn = $('#approval-sound');
  if (!btn) return;
  btn.textContent = APPROVALS.soundEnabled ? '提示音已启用 · 试听' : '启用提示音';
  btn.setAttribute('aria-pressed', String(APPROVALS.soundEnabled));
}
function approvalAudioContext() {
  const Audio = window.AudioContext || window.webkitAudioContext;
  if (Audio && !APPROVALS.audio) APPROVALS.audio = new Audio();
  return APPROVALS.audio;
}
async function enableApprovalSound() {
  try {
    const ctx = approvalAudioContext();
    if (!ctx) { toast('当前浏览器不支持提示音'); return; }
    await ctx.resume();
    APPROVALS.soundEnabled = true;
    try { localStorage.setItem('a2m_approval_sound', '1'); } catch { }
    updateApprovalSoundButton();
    playApprovalSound();
  } catch { toast('提示音未能启用，请再次点击重试'); }
}
function playApprovalSound() {
  if (!APPROVALS.soundEnabled) return;
  try {
    const ctx = approvalAudioContext();
    if (!ctx || ctx.state !== 'running') return;
    const tone = ctx.createOscillator(), volume = ctx.createGain(), start = ctx.currentTime;
    tone.type = 'sine'; tone.frequency.setValueAtTime(880, start);
    volume.gain.setValueAtTime(0, start); volume.gain.linearRampToValueAtTime(0.16, start + 0.02); volume.gain.exponentialRampToValueAtTime(0.001, start + 0.24);
    tone.connect(volume); volume.connect(ctx.destination); tone.start(start); tone.stop(start + 0.25);
    tone.onended = () => { tone.disconnect(); volume.disconnect(); };
  } catch { }
}
// A remembered preference still needs a gesture to unlock audio in some browsers.
document.addEventListener('click', () => {
  if (APPROVALS.soundEnabled) {
    try { const ctx = approvalAudioContext(); if (ctx?.state === 'suspended') ctx.resume().catch(() => {}); } catch { }
  }
});
function updateApprovalBanner() {
  const count = APPROVALS.pending.length;
  const banner = $('#approval-banner');
  if (banner) banner.hidden = count === 0;
  const countEl = $('#approval-count');
  if (countEl) countEl.textContent = `有 ${count} 个调用等待审批`;
  document.title = count ? `(${count}) 待审批 · ${APPROVAL_TITLE}` : APPROVAL_TITLE;
  const navLink = $('nav a[data-nav="approvals"]');
  if (navLink) navLink.textContent = count ? `审批记录 (${count})` : '审批记录';
  const badge = $('#approval-pending-badge');
  if (badge) {
    badge.hidden = count === 0;
    badge.textContent = `${count} 条待审批`;
  }
}
function cleanupApprovalSession(id) {
  const numId = Number(id);
  const sess = APPROVALS.sessions.get(numId);
  if (sess) {
    clearTimeout(sess.previewTimer);
    APPROVALS.sessions.delete(numId);
  }
}
async function refreshApprovals(forceHistory = false) {
  if (APPROVALS.polling) return;
  APPROVALS.polling = true;
  const epoch = APPROVALS.listEpoch;
  try {
    const rows = await api('POST', '/api/approvals/list', { status: 'pending' });
    // A decision may finish while this list request is in flight.
    if (epoch !== APPROVALS.listEpoch) return;
    const oldIDs = new Set(APPROVALS.pending.map(p => String(p.id)));
    const newIDs = new Set(rows.map(p => String(p.id)));
    const added = rows.some(p => !oldIDs.has(String(p.id)));
    const removed = [...oldIDs].filter(id => !newIDs.has(id));
    APPROVALS.pending = rows;
    updateApprovalBanner();
    if (added) playApprovalSound();
    for (const id of removed) {
      const sess = APPROVALS.sessions.get(Number(id));
      if (sess && !sess.deciding && ROUTE === 'approvals') {
        toast(`审批 #${id} 已在其他地方结束或已过期`);
      }
      cleanupApprovalSession(Number(id));
    }
    if (ROUTE === 'approvals') {
      syncPendingApprovalsDOM();
      if (removed.length > 0 || forceHistory) {
        await refreshApprovalHistory();
      }
    }
  } catch { /* Server outages must not interrupt work or produce repeated toasts. */ }
  finally { APPROVALS.polling = false; }
}
function openApprovalList() {
  if (location.hash !== '#/approvals') {
    location.hash = '#/approvals';
    return;
  }
  const sec = $('#approval-pending-section');
  if (sec) sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
const openApprovalModal = openApprovalList;

function resolveApprovalSession(idOrSession) {
  if (!idOrSession) return null;
  if (typeof idOrSession === 'object' && idOrSession.item) return idOrSession;
  return APPROVALS.sessions.get(Number(idOrSession)) || null;
}
function approvalPreviewText(preview) {
  const p = preview || {};
  const headers = Object.entries(p.headers || {}).map(([k, v]) => k + ': ' + v).join('\n');
  return `${p.method || ''} ${p.url || ''}\n\n请求头\n${headers || '（无）'}\n\n请求体\n${p.body || '（空）'}`;
}
function approvalParamsDirty(session) { return session.fields.some((field, i) => field.value !== session.initial[i]); }
function collectApprovalArgs(session) {
  const args = Object.create(null);
  session.params.forEach((p, i) => {
    // Untouched fields retain the original value on the server, including masks.
    if (session.fields[i].value !== session.initial[i]) args[p.name] = session.fields[i].value;
  });
  return args;
}
function buildPendingApprovalCard(item) {
  const id = Number(item.id);
  const params = item.params || [];
  const initial = params.map(p => p.secret ? APPROVAL_SECRET_UNCHANGED : Object.hasOwn(item.args_display || {}, p.name) ? String(item.args_display[p.name] ?? '') : '');
  const session = { item, params, initial, fields: [], revision: 0, previewRevision: 0, previewRequest: 0, previewHash: item.preview_hash, previewLoading: false, previewError: '', deciding: false };
  APPROVALS.sessions.set(id, session);

  const card = document.createElement('details');
  card.className = 'approval-pending-card';
  card.dataset.approvalId = String(id);
  card.open = true;
  card.innerHTML = `
    <summary class="approval-pending-summary">
      <span class="pill approval-status-pending">待审批 #${esc(id)}</span>
      <b class="approval-pending-title">${esc(item.title || item.tool)}</b>
      <span class="mono small muted">${esc(item.tool)}</span>
      <span class="muted small approval-summary-meta">调用方：${esc(item.client || '未知调用方')} · ${esc(item.ts)}</span>
    </summary>
    <div class="approval-pending-body" id="approval-content-${id}">
      <div class="approval-explanation ${item.explanation ? '' : 'approval-explanation-empty'}">
        <div class="approval-section-label">AI 操作解释说明与影响分析</div>
        <div class="approval-explanation-text">${item.explanation ? esc(item.explanation) : '<span class="muted">AI 未提供操作解释说明</span>'}</div>
      </div>
      <div class="approval-section-label">调用参数</div>
      <div class="approval-params">${params.map((p, i) => `<label for="approval-arg-${id}-${i}"><span class="mono">${esc(p.name)}</span>${p.required ? ' *' : ''} <span class="muted small">${esc(p.type)}</span>
        ${p.description ? `<span class="muted small approval-param-hint">${esc(p.description)}</span>` : ''}
        ${p.secret ? `<input id="approval-arg-${id}-${i}" class="approval-arg" type="password" autocomplete="new-password" spellcheck="false"><span class="muted small approval-param-hint">保留 ${esc(APPROVAL_SECRET_UNCHANGED)} 沿用原值；输入新值可替换。</span>` : `<textarea id="approval-arg-${id}-${i}" class="approval-arg" rows="2" spellcheck="false"></textarea>${p.default ? `<span class="muted small approval-param-hint">未传入时使用默认值：${esc(p.default)}</span>` : ''}`}</label>`).join('') || '<div class="muted small">这个工具没有业务参数</div>'}</div>
      <details class="approval-preview-details" id="approval-preview-details-${id}">
        <summary class="approval-preview-summary">请求预览（<span class="mono">${esc(item.preview?.method || '')} ${esc(shortURL(item.preview?.url || ''))}</span>）</summary>
        <div class="approval-preview-box">
          <div class="row approval-preview-heading"><span id="approval-preview-state-${id}" class="small muted grow" role="status"></span><button type="button" id="approval-refresh-${id}" class="sm" onclick="refreshApprovalPreview(${id})">刷新预览</button></div>
          <pre id="approval-preview-${id}"></pre>
        </div>
      </details>
      <label for="approval-feedback-${id}" class="approval-feedback-label">告诉 AI 的意见（拒绝时必填）</label>
      <textarea id="approval-feedback-${id}" class="approval-feedback-input" rows="2" placeholder="例如：请先核对参数，再重新调用"></textarea>
      <div class="row approval-actions">
        <button type="button" id="approval-approve-${id}" class="pri" onclick="decideApproval(${id}, 'approve')">通过</button>
        <button type="button" id="approval-edit-${id}" class="pri" onclick="decideApproval(${id}, 'edit')">修改后通过</button>
        <button type="button" id="approval-reject-${id}" class="danger" onclick="decideApproval(${id}, 'reject')">拒绝并告诉 AI</button>
        <span id="approval-action-hint-${id}" class="muted small"></span>
      </div>
    </div>`;

  session.fields = params.map((p, i) => {
    const field = card.querySelector(`#approval-arg-${id}-${i}`);
    field.value = initial[i];
    // Textareas normalize line endings; untouched values still use the snapshot.
    initial[i] = field.value;
    field.addEventListener('input', () => approvalParamsChanged(session));
    if (p.secret) field.addEventListener('focus', () => { if (field.value === APPROVAL_SECRET_UNCHANGED) field.select(); });
    return field;
  });
  const previewEl = card.querySelector(`#approval-preview-${id}`);
  if (previewEl) previewEl.textContent = approvalPreviewText(item.preview);
  return { card, session };
}
function syncPendingApprovalsDOM() {
  const listEl = $('#approval-pending-list');
  if (!listEl) return;
  updateApprovalBanner();
  if (APPROVALS.pending.length === 0) {
    for (const id of [...APPROVALS.sessions.keys()]) cleanupApprovalSession(id);
    listEl.innerHTML = '<div class="empty approval-pending-empty">当前没有待审批的调用</div>';
    return;
  }
  listEl.querySelector('.approval-pending-empty')?.remove();
  const activeIDs = new Set(APPROVALS.pending.map(p => Number(p.id)));
  for (const el of [...listEl.querySelectorAll('.approval-pending-card[data-approval-id]')]) {
    const elId = Number(el.dataset.approvalId);
    if (!activeIDs.has(elId)) {
      cleanupApprovalSession(elId);
      el.remove();
    }
  }
  for (const item of APPROVALS.pending) {
    const id = Number(item.id);
    const existingCard = listEl.querySelector(`.approval-pending-card[data-approval-id="${id}"]`);
    if (existingCard && APPROVALS.sessions.has(id)) {
      APPROVALS.sessions.get(id).item.nonce = item.nonce;
      continue;
    }
    const { card, session } = buildPendingApprovalCard(item);
    listEl.appendChild(card);
    updateApprovalControls(session);
    if (!session.previewHash) refreshApprovalPreview(session);
  }
}
function updateApprovalControls(idOrSession) {
  const session = resolveApprovalSession(idOrSession);
  if (!session || APPROVALS.sessions.get(Number(session.item.id)) !== session) return;
  const id = Number(session.item.id);
  const changed = approvalParamsDirty(session), busy = session.deciding;
  const ready = session.previewRevision === session.revision && !!session.previewHash;
  session.fields.forEach(field => { field.disabled = busy; });
  const fb = $(`#approval-feedback-${id}`);
  if (fb) fb.disabled = busy;
  const btnApprove = $(`#approval-approve-${id}`);
  if (btnApprove) btnApprove.disabled = busy || changed || session.previewLoading;
  const btnEdit = $(`#approval-edit-${id}`);
  if (btnEdit) btnEdit.disabled = busy || !changed || session.previewLoading;
  const btnReject = $(`#approval-reject-${id}`);
  if (btnReject) btnReject.disabled = busy;
  const btnRefresh = $(`#approval-refresh-${id}`);
  if (btnRefresh) btnRefresh.disabled = busy || session.previewLoading;
  const content = $(`#approval-content-${id}`);
  if (content) content.setAttribute('aria-busy', String(busy));
  const preview = $(`#approval-preview-${id}`);
  if (preview) {
    preview.classList.toggle('stale', !ready);
    preview.setAttribute('aria-busy', String(session.previewLoading));
  }
  const state = $(`#approval-preview-state-${id}`);
  if (state) {
    state.className = 'small grow ' + (session.previewError ? 'st-bad' : 'muted');
    state.textContent = session.previewError || (ready ? '以下是当前参数的请求预览。' : '预览尚未更新，请等待或点击“刷新预览”。');
  }
  const hint = $(`#approval-action-hint-${id}`);
  if (hint) {
    hint.textContent = busy ? '正在提交审批决定…' : changed ? '参数已修改，请核对预览后点击“修改后通过”。' : '“通过”将执行本次调用的原始参数。';
  }
}
function approvalParamsChanged(idOrSession) {
  const session = resolveApprovalSession(idOrSession);
  if (!session || APPROVALS.sessions.get(Number(session.item.id)) !== session) return;
  const id = Number(session.item.id);
  const details = $(`#approval-preview-details-${id}`);
  if (details) details.open = true;
  session.revision++; session.previewLoading = false; session.previewError = '';
  clearTimeout(session.previewTimer);
  session.previewTimer = setTimeout(() => refreshApprovalPreview(session), 300);
  updateApprovalControls(session);
}
async function refreshApprovalPreview(idOrSession) {
  const session = resolveApprovalSession(idOrSession);
  if (!session || APPROVALS.sessions.get(Number(session.item.id)) !== session) return false;
  const id = Number(session.item.id);
  clearTimeout(session.previewTimer);
  const revision = session.revision, request = ++session.previewRequest;
  session.previewLoading = true; session.previewError = '';
  updateApprovalControls(session);
  const current = () => APPROVALS.sessions.get(id) === session && session.revision === revision && session.previewRequest === request;
  try {
    const result = await api('POST', `/api/approvals/${encodeURIComponent(id)}/preview`, { args: collectApprovalArgs(session), nonce: session.item.nonce });
    if (!current()) return false;
    const previewEl = $(`#approval-preview-${id}`);
    if (previewEl) previewEl.textContent = approvalPreviewText(result.preview);
    session.previewHash = result.preview_hash; session.previewRevision = revision; session.previewLoading = false;
    updateApprovalControls(session);
    return true;
  } catch (e) {
    if (!current()) return false;
    session.previewLoading = false; session.previewHash = '';
    toast('预览失败：' + e.message, 5000);
    if (e.status === 409 || e.status === 404) { forgetApproval(id); refreshApprovals(true); }
    else { session.previewError = e.message; updateApprovalControls(session); refreshApprovals(); }
    return false;
  }
}
function forgetApproval(id) {
  const numId = Number(id);
  APPROVALS.listEpoch++;
  APPROVALS.pending = APPROVALS.pending.filter(p => Number(p.id) !== numId);
  cleanupApprovalSession(numId);
  updateApprovalBanner();
  if (ROUTE === 'approvals') {
    syncPendingApprovalsDOM();
  }
}
async function decideApproval(idOrAction, maybeAction) {
  let id = idOrAction, action = maybeAction;
  if (maybeAction === undefined) {
    action = idOrAction;
    id = APPROVALS.pending[0]?.id;
  }
  const session = resolveApprovalSession(id);
  if (!session || session.deciding) return;
  const numId = Number(session.item.id);
  const fbEl = $(`#approval-feedback-${numId}`);
  const feedback = fbEl ? fbEl.value.trim() : '', changed = approvalParamsDirty(session);
  if (action === 'reject' && !feedback) { toast('拒绝时请填写告诉 AI 的意见'); fbEl?.focus(); return; }
  if (action === 'approve' && changed) { toast('参数已修改，请点击“修改后通过”'); return; }
  if (action === 'edit' && !changed) return;
  if (action !== 'reject' && (session.previewRevision !== session.revision || !session.previewHash)) {
    const details = $(`#approval-preview-details-${numId}`);
    if (details) details.open = true;
    if (await refreshApprovalPreview(session)) toast('请求预览已更新，请核对后再次确认', 5000);
    return;
  }
  session.deciding = true;
  clearTimeout(session.previewTimer);
  updateApprovalControls(session);
  try {
    await api('POST', `/api/approvals/${encodeURIComponent(numId)}/decide`, { action, args: collectApprovalArgs(session), feedback, nonce: session.item.nonce, preview_hash: session.previewHash || '' });
    toast(action === 'reject' ? '已拒绝，意见已交给 AI' : action === 'edit' ? '已修改参数并通过审批，已移入审批记录' : '已通过审批，已移入审批记录');
    forgetApproval(numId);
    await refreshApprovalHistory();
    refreshApprovals();
    if (action !== 'reject') {
      setTimeout(() => { if (ROUTE === 'approvals') refreshApprovalHistory(); }, 1200);
    }
  } catch (e) {
    if (APPROVALS.sessions.get(numId) !== session) return;
    toast(e.message, 5000);
    if (e.status === 409 && e.message.includes('预览已过期')) {
      session.previewHash = ''; session.previewRevision = -1;
      const details = $(`#approval-preview-details-${numId}`);
      if (details) details.open = true;
      if (await refreshApprovalPreview(session)) toast('预览已过期，已刷新，请核对后再次确认', 5000);
    } else if (e.status === 409 || e.status === 404) { forgetApproval(numId); refreshApprovals(true); }
    else refreshApprovals(true);
  } finally {
    if (APPROVALS.sessions.get(numId) === session) {
      session.deciding = false;
      if (!APPROVALS.pending.some(p => Number(p.id) === numId)) {
        toast('当前审批已在其他地方结束或已过期');
        forgetApproval(numId);
        refreshApprovalHistory();
      } else {
        updateApprovalControls(session);
      }
    }
  }
}
function renderApprovalHistoryHTML(rows) {
  const historyRows = (rows || []).filter(item => item.status !== 'pending');
  if (!historyRows.length) return '<div class="empty">还没有已处理的审批记录</div>';
  return `<div tabindex="0" role="region" aria-labelledby="approval-history-heading" class="approval-history-scroll"><table class="approval-history"><thead><tr><th scope="col">时间</th><th scope="col">工具 / 调用方</th><th scope="col">操作说明与影响</th><th scope="col">状态</th><th scope="col">意见</th><th scope="col">最终参数（脱敏）</th><th scope="col">执行结果</th></tr></thead><tbody>${historyRows.map(item => {
    const known = Object.hasOwn(APPROVAL_STATUS_LABELS, item.status);
    const args = item.final_args_display || item.args_display || {};
    return `<tr><td class="small approval-time">${esc(item.ts)}${item.decided_at ? `<div class="muted small">决定于 ${esc(item.decided_at)}</div>` : ''}</td>
      <td><b class="mono">${esc(item.tool)}</b><div>${esc(item.title)}</div><div class="muted small">${esc(item.client)}</div></td>
      <td class="approval-wrap">${item.explanation ? esc(item.explanation) : '<span class="muted">—</span>'}</td>
      <td><span class="pill ${known ? 'approval-status-' + esc(item.status) : ''}">${esc(known ? APPROVAL_STATUS_LABELS[item.status] : item.status)}</span></td>
      <td class="approval-wrap">${esc(item.feedback || '—')}</td><td><pre>${esc(JSON.stringify(args, null, 2))}</pre></td>${approvalResultCell(item)}</tr>`;
  }).join('')}</tbody></table></div>`;
}
async function refreshApprovalHistory() {
  const container = $('#approval-history-container');
  if (!container) return;
  try {
    const rows = await api('POST', '/api/approvals/list', { status: 'all', limit: 1000 });
    if (ROUTE !== 'approvals') return;
    const target = $('#approval-history-container');
    if (target) target.innerHTML = renderApprovalHistoryHTML(rows);
  } catch { }
}
async function pageApprovals(app) {
  const [pendingRows, allRows] = await Promise.all([
    api('POST', '/api/approvals/list', { status: 'pending' }),
    api('POST', '/api/approvals/list', { status: 'all', limit: 1000 }),
  ]);
  if (ROUTE !== 'approvals') return;
  APPROVALS.pending = pendingRows;
  for (const id of [...APPROVALS.sessions.keys()]) cleanupApprovalSession(id);
  app.innerHTML = `
    <div class="card" id="approval-pending-section">
      <div class="row approval-history-heading">
        <h2 class="grow" id="approval-pending-heading">待审批列表 <span id="approval-pending-badge" class="pill approval-status-pending" hidden></span></h2>
        <button type="button" onclick="refreshApprovals(true)">刷新</button>
      </div>
      <p class="muted small">多条待审批调用会同时展示在此列表中。请核对 AI 提交的操作说明与影响分析、调用参数及请求预览；审批完成后会自动转移到下方的「审批记录」中。</p>
      <div id="approval-pending-list" class="approval-pending-list"></div>
    </div>
    <div class="card" id="approval-history-section">
      <div class="row approval-history-heading">
        <h2 class="grow" id="approval-history-heading">审批记录</h2>
        <button type="button" onclick="refreshApprovalHistory()">刷新</button>
      </div>
      <p class="muted small">最近 1000 条已处理的记录。工具、操作说明、参数和执行结果均来自审批时保存的脱敏快照。</p>
      <div id="approval-history-container">${renderApprovalHistoryHTML(allRows)}</div>
    </div>`;
  syncPendingApprovalsDOM();
}
function approvalResultCell(item) {
  const preview = item.result ? `<pre class="approval-result-preview">${esc(item.result)}</pre>` : '<span class="muted">—</span>';
  const btn = item.has_full_result ? `<button type="button" class="sm" onclick="viewApprovalResult(${Number(item.id)})">查看全部</button>` : '';
  return `<td class="approval-wrap approval-result-cell">${preview}${btn}</td>`;
}
async function viewApprovalResult(id) {
  try {
    const data = await api('POST', `/api/approvals/${encodeURIComponent(id)}/result`, {});
    const text = data.result || '';
    const note = data.truncated ? '<p class="muted small">结果超过 1MB，已截断保存。</p>' : '';
    openModal(`<div class="approval-result-modal"><h3>执行结果</h3>${note}<div class="row approval-result-actions"><button type="button" class="sm" id="approval-result-copy">复制</button></div><pre class="approval-result-full" id="approval-result-full">${esc(text)}</pre></div>`);
    const copy = $('#approval-result-copy');
    if (copy) copy.addEventListener('click', copyApprovalResult);
  } catch (e) {
    toast(e.message || '无法加载执行结果');
  }
}
async function copyApprovalResult() {
  const node = $('#approval-result-full');
  const text = node ? node.textContent : '';
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    toast('已复制执行结果');
  } catch {
    toast('复制失败，请手动选择文本');
  }
}
updateApprovalSoundButton();
if (window.ResizeObserver) new ResizeObserver(() => {
  document.documentElement.style.setProperty('--console-top-height', $('#console-top').offsetHeight + 'px');
}).observe($('#console-top'));
refreshApprovals();
setInterval(refreshApprovals, 1500);

// ---------- recordings ----------
async function pageRecordings(app) {
  const list = await api('GET', '/api/recordings');
  const rec = STATUS.recording;
  const last = localStorage.getItem('a2m_last_url') || '';
  app.innerHTML = `
  <div class="card">
    <h2>录制一次业务操作</h2>
    ${rec ? `<div class="row"><span class="pill recording"><span class="dot"></span>正在录制「${esc(STATUS.recording_name)}」，已捕获 <span id="live-count">${STATUS.captured}</span> 个请求</span>
        <button class="rec big" onclick="stopRec()">■ 结束录制</button></div>
        <p class="muted small">在弹出的专用浏览器窗口里操作。结束方式任选：点页面右下角「结束录制」、点这里的按钮、命令行执行 <code>a2m stop</code>，或直接关闭浏览器窗口。</p>`
    : `<div class="hero">
        <label>录制名称（就是这项业务操作叫什么）<input id="rec-name" placeholder="例如：查询客户" onkeydown="if(event.key==='Enter')startRec()"></label>
        <label class="grow">起始网址（可选）<input id="rec-url" style="width:100%" placeholder="https://crm.example.com" value="${esc(last)}" onkeydown="if(event.key==='Enter')startRec()"></label>
        <button id="rec-btn" class="rec big" onclick="startRec()">● 开始录制</button>
      </div>
      <p class="muted small" style="margin-bottom:0">点击后会打开一个专用的浏览器窗口（登录一次以后会记住）。也可以在命令行执行：<code>a2m rec 查询客户 https://crm.example.com</code>　·　只想登录不录制？<a href="javascript:openLogin()">打开浏览器登录</a></p>`}
  </div>
  <div class="card">
    <h3>录制记录</h3>
    ${list.length === 0 ? '<div class="empty">还没有录制。给它起个名字，点「开始录制」试试。</div>' : `
    <table><thead><tr><th>名称</th><th>时间</th><th>请求</th><th>状态</th><th></th></tr></thead><tbody>
    ${list.map(r => `<tr class="click" onclick="location.hash='#/recordings/${r.id}'">
      <td><b>${esc(r.name)}</b><div class="muted small url">${esc(r.start_url || '')}</div></td>
      <td class="small">${esc(r.created_at)}</td>
      <td><b>${r.useful_count}</b> 个业务请求 <span class="muted small">/ 共 ${r.request_count}</span></td>
      <td>${r.status === 'recording' ? '<span class="pill recording"><span class="dot"></span>录制中</span>' : '<span class="muted">已完成</span>'}</td>
      <td style="text-align:right"><button class="danger" onclick="event.stopPropagation();delRec(${r.id})">删除</button></td></tr>`).join('')}
    </tbody></table>`}
  </div>`;
}
async function delRec(id) { if (!confirm('删除这条录制？（已保存的工具不受影响）')) return; await api('DELETE', '/api/recordings/' + id); render(); }

let REC_STATE = { showNoise: false, sel: 0, loginResults: {}, requests: {} };
const NOTE_CATEGORIES = { query: '查询', write: '写操作', auth: '登录认证', config: '配置枚举', page: '页面', noise: '无关' };
function requestOverrideHint(q) {
  const override = q.note?.noise_override;
  if (override == null || override === q.noise_heuristic) return '';
  return (q.note.source === 'agent' ? 'AI 判定为' : '手动判定为') + (override ? '无关' : '业务请求');
}
function requestNoteHTML(q, detail = false) {
  const n = q.note, hint = requestOverrideHint(q);
  return `<div class="request-note" data-note-id="${q.id}" data-note-detail="${detail}">
    <button class="note-purpose" onclick="event.stopPropagation();editRequestNote(this,${q.id})" title="点击编辑作用说明" aria-label="编辑作用说明">${n?.purpose ? esc(n.purpose) : '<span class="muted">未标注</span>'}</button>
    <div class="note-meta">${n?.category ? `<span class="badge note-cat-${esc(n.category)}">${esc(NOTE_CATEGORIES[n.category] || n.category)}</span>` : ''}${n?.useful === true ? '<span class="note-useful" title="完成流程所需的请求" aria-label="流程需要">★</span>' : ''}</div>
    ${hint ? `<div class="note-override small">${esc(hint)}</div>` : ''}
    ${detail && n ? `<div class="muted small">${n.source === 'agent' ? 'AI 标注' : '手动标注'} · ${esc(n.updated_at)}${n.useful === false ? ' · 流程不需要' : ''}</div>` : ''}
  </div>`;
}
function editRequestNote(btn, id) {
  const q = REC_STATE.requests[id] || CUR_REQ?.request;
  if (!q || q.id !== id) return;
  const n = q.note || { purpose: '', category: q.is_login ? 'auth' : q.resource_type === 'Document' ? 'page' : ['GET', 'HEAD', 'WS'].includes(q.method) ? 'query' : 'write' };
  const box = btn.closest('[data-note-id]');
  const triOptions = (value, labels) => [['', labels[0]], ['true', labels[1]], ['false', labels[2]]].map(([v, label]) => `<option value="${v}" ${String(value ?? '') === v ? 'selected' : ''}>${label}</option>`).join('');
  box.innerHTML = `<form class="note-editor" onclick="event.stopPropagation()" onsubmit="event.preventDefault();saveRequestNote(event,${id})" onkeydown="if(event.key==='Escape'){event.stopPropagation();cancelRequestNote(this,${id})}">
    <label>作用说明<textarea name="purpose" placeholder="用一句话说明这个请求做什么，例如：按订单号查询处理进度">${esc(n.purpose)}</textarea></label>
    <label>类别<select name="category">${Object.entries(NOTE_CATEGORIES).map(([k, label]) => `<option value="${k}" ${n.category === k ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
    <label>流程是否需要<select name="useful">${triOptions(n.useful, ['未判断', '★ 流程需要', '流程不需要'])}</select></label>
    <label>放在哪个列表<select name="noise_override">${triOptions(n.noise_override, ['自动判断', '无关请求', '业务请求'])}</select></label>
    <div class="row"><button type="submit" class="pri sm">保存</button><button type="button" class="sm" onclick="cancelRequestNote(this,${id})">取消</button>${q.note ? `<button type="button" class="sm danger" onclick="deleteRequestNote(this,${id})" title="清除说明和判定，恢复自动分类">清除标注</button>` : ''}</div>
  </form>`;
  $('textarea', box).focus();
}
function cancelRequestNote(el, id) {
  const box = el.closest('[data-note-id]');
  const q = REC_STATE.requests[id] || CUR_REQ?.request;
  if (q) box.outerHTML = requestNoteHTML(q, box.dataset.noteDetail === 'true');
}
async function saveRequestNote(event, id) {
  const form = event.currentTarget, fields = new FormData(form);
  const tri = name => fields.get(name) === '' ? null : fields.get(name) === 'true';
  const btn = $('button[type="submit"]', form);
  btn.disabled = true;
  try {
    const n = await api('PUT', `/api/requests/${id}/note`, { purpose: fields.get('purpose').trim(), category: fields.get('category'), useful: tri('useful'), noise_override: tri('noise_override') });
    REC_STATE.sel = id;
    if (n.noise_override === true) REC_STATE.showNoise = true;
    await render();
    toast('作用说明已保存');
  } catch (e) { toast('保存失败：' + e.message, 5000); btn.disabled = false; }
}
async function deleteRequestNote(btn, id) {
  btn.disabled = true;
  try { await api('DELETE', `/api/requests/${id}/note`); await render(); toast('已清除标注，恢复自动分类'); }
  catch (e) { toast('清除失败：' + e.message, 5000); btn.disabled = false; }
}
async function pageRecording(app, id) {
  const d = await api('GET', '/api/recordings/' + id);
  const reqs = d.requests;
  REC_STATE.requests = Object.fromEntries(reqs.map(q => [q.id, q]));
  const stoppedLogin = STATUS.last_stop?.recording_id === id ? STATUS.last_stop.login_detection : null;
  const login = REC_STATE.loginResults[id] || (stoppedLogin?.action !== 'none' ? stoppedLogin : null);
  const useful = reqs.filter(r => !r.noise), noise = reqs.filter(r => r.noise);
  const reasons = {}; noise.forEach(r => { const reason = requestOverrideHint(r) || r.noise_reason || '无关请求'; reasons[reason] = (reasons[reason] || 0) + 1; });
  const row = r => `<tr class="click ${REC_STATE.sel === r.id ? 'sel' : ''}" data-id="${r.id}" onclick="selectReq(${r.id})">
      <td>${methodBadge(r.method)}</td>
      <td>${requestNoteHTML(r)}</td>
      <td class="request-path"><div class="url mono" title="${esc(r.url)}">${esc(shortURL(r.url))}</div><div class="muted small">${esc(hostOf(r.url))} · ${esc(r.resource_type)}${r.noise && !requestOverrideHint(r) ? ' · ' + esc(r.noise_reason) : ''}${r.is_login ? ' · <span class="badge login-badge">登录请求</span>' : ''}</div></td>
      <td class="${r.status >= 200 && r.status < 400 ? 'st-ok' : 'st-bad'}">${r.status || '-'}</td>
      <td class="small muted">${fmtSize(r.resp_size)}</td></tr>`;
  const table = rows => `<table class="request-table"><colgroup><col class="request-method-col"><col class="request-purpose-col"><col><col class="request-status-col"><col class="request-size-col"></colgroup><thead><tr><th>方法</th><th>作用</th><th>接口地址</th><th>状态</th><th>响应大小</th></tr></thead><tbody>${rows.map(row).join('')}</tbody></table>`;
  app.innerHTML = `
  <div class="row" style="margin-bottom:12px"><a class="btn" href="#/recordings">← 返回</a><h2 style="margin:0">${esc(d.recording.name)}</h2>
    <span class="muted small">${esc(d.recording.created_at)} · ${d.recording.status === 'recording' ? '录制中…' : '已完成'}</span>
    <div class="row" style="margin-left:auto"><button onclick="detectRecLogin(this,${id})" ${d.recording.status === 'recording' ? 'disabled' : ''} title="从录制中的企业微信登录流程识别并补充登录配置">加入登录中心</button><button onclick="render()">刷新</button></div></div>
  ${login ? `<div class="${login.detected && login.action !== 'suggestion' ? 'ok-notice' : 'notice'}" id="recording-login-notice" role="status">${esc(login.message)}${login.site_id ? '。<a href="#/sites">查看登录中心 →</a>' : ''}</div>` : ''}
  ${d.recording.summary ? `<div class="card recording-summary"><h3>这次操作的作用</h3><p>${esc(d.recording.summary)}</p></div>` : ''}
  <div class="split recording-split">
    <div class="card request-lists">
      <div style="padding:8px 10px" class="row"><b>可能的业务请求（${useful.length}）</b><span class="muted small">点击作用可编辑说明；点击接口查看详情，再「保存为工具」</span></div>
      ${useful.length ? table(useful) : '<div class="empty">没有识别出业务请求，可以展开下面的无关请求看看。</div>'}
      <button class="collapse-h" onclick="REC_STATE.showNoise=!REC_STATE.showNoise;render()" aria-expanded="${REC_STATE.showNoise}">${REC_STATE.showNoise ? '▾' : '▸'} 无关请求（${noise.length}）
        <span class="small">${Object.entries(reasons).map(([k, v]) => esc(k) + ' ' + v).join(' · ')}</span></button>
      ${REC_STATE.showNoise && noise.length ? table(noise) : ''}
    </div>
    <div class="card detail" id="req-detail"><div class="empty">← 选择左侧的请求查看详情</div></div>
  </div>`;
  if (REC_STATE.sel && reqs.some(r => r.id === REC_STATE.sel)) await selectReq(REC_STATE.sel);
  else if (useful.length) await selectReq(useful[0].id);
}
async function detectRecLogin(btn, id) {
  btn.disabled = true; btn.textContent = '正在识别…';
  try {
    const r = await api('POST', '/api/recordings/' + id + '/detect-login');
    REC_STATE.loginResults[id] = r;
    toast(r.message, 6500);
    if (ROUTE === 'recordings/' + id) await render();
  } catch (e) { toast(e.message, 5000); }
  finally { if (btn.isConnected) { btn.disabled = false; btn.textContent = '加入登录中心'; } }
}
let CUR_REQ = null;
async function selectReq(id) {
  REC_STATE.sel = id;
  document.querySelectorAll('tr[data-id]').forEach(tr => tr.classList.toggle('sel', +tr.dataset.id === id));
  const d = await api('GET', '/api/requests/' + id);
  CUR_REQ = d;
  const q = d.request;
  const ws = q.resource_type === 'WebSocket' || q.method === 'WS';
  const hdrCell = (k, v) => {
    if (/cookie|authorization/i.test(k)) {
      if (ws) return '******';
      const s = String(v);
      return s.slice(0, 40) + (s.length > 40 ? '…' : '');
    }
    return v;
  };
  const hdrs = h => `<table class="kv">${Object.entries(h || {}).sort().map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(hdrCell(k, v))}</td></tr>`).join('')}</table>`;
  $('#req-detail').innerHTML = `
    <div class="row">${methodBadge(q.method)}<b class="${q.status < 400 ? 'st-ok' : 'st-bad'}">${q.status || '-'}</b><span class="muted small">${esc(q.resource_type)} · ${esc(q.ts)}</span>
      <span style="margin-left:auto" class="row">${ws ? `<button class="pri" onclick="openToolEditorFromReq()">保存为工具</button><button onclick="saveRecordedWS()">保存为 WebSocket 连接</button>` : `<button class="pri" onclick="openToolEditorFromReq()">保存为工具</button>`}</span></div>
    <div class="mono small" style="margin:8px 0;word-break:break-all">${esc(q.url)}</div>
    <section class="request-note-panel" aria-label="接口作用说明"><h3>作用说明</h3>${requestNoteHTML(q, true)}</section>
    ${ws ? `<div class="notice">这是一条 WebSocket 连接。可以把带 SQL 的出站消息保存为「工具」（走 SQL 护栏和审批），也可以保存为中间件「WebSocket 连接」。保存为工具时不会写入登录令牌，调用时从本机已收获的请求头注入。</div>` : ''}
    ${q.is_login ? `<div class="ok-notice login-box">🔑 这看起来是一个<b>登录请求</b>（密码已在页面上隐藏）。保存后，账号密码会加密存进「配置管理」，以后这个网站登录过期时会自动用它重新登录，AI 看不到账号密码。
      <div class="row" style="margin-top:8px"><button class="pri" onclick="saveLoginReq(${q.id})">保存为登录配置</button></div></div>` : ''}
    ${q.noise ? `<div class="notice">${esc(requestOverrideHint(q) || ('已被识别为无关请求：' + q.noise_reason))}${ws ? '' : '（如果它其实有用，也可以保存为工具）'}</div>` : ''}
    <div class="tabs"><button class="on" data-t="body" onclick="reqTab(this)">${ws ? '发出的消息' : '请求体'}</button><button data-t="resp" onclick="reqTab(this)">${ws ? '收到的消息' : '响应'}</button><button data-t="hdr" onclick="reqTab(this)">请求头</button><button data-t="rhdr" onclick="reqTab(this)">响应头</button></div>
    <div data-p="body">${q.req_body ? `<pre>${ws ? wsRender(q.req_body, '→') : esc(pretty(q.req_body))}</pre>` : '<div class="muted small">无请求体</div>'}</div>
    <div data-p="resp" hidden><pre>${ws ? wsRender(q.resp_body, '←') : (esc(pretty(q.resp_body)) || '(空)')}</pre></div>
    <div data-p="hdr" hidden>${hdrs(q.req_headers)}</div>
    <div data-p="rhdr" hidden>${hdrs(q.resp_headers)}</div>`;
}
function wsRender(body, arrow) {
  let env;
  try { env = JSON.parse(body || ''); } catch (e) { return esc(body || ''); }
  if (!env || env.v !== 1 || !Array.isArray(env.frames)) return esc(pretty(body));
  const lines = [];
  for (const f of env.frames) {
    const kind = f.op === 1 ? 'text' : f.op === 2 ? 'binary' : ('op ' + f.op);
    let payload = '';
    if (f.op === 1) payload = f.text || '';
    else if (f.op === 2) payload = (f.bytes || 0) + ' 字节';
    lines.push(arrow + ' ' + (f.ts || '') + ' ' + kind + (payload ? '\n' + payload : ''));
  }
  if (env.state === 'closed') lines.push(arrow + ' closed');
  if (env.state === 'error') lines.push(arrow + ' error' + (env.error ? '\n' + env.error : ''));
  if (env.truncated) lines.push('…[已截断，只保留完整的帧]');
  return esc(lines.join('\n') || '(空)');
}
function wsNameFromURL(url) {
  try { return new URL(url).hostname.replace(/[^\p{L}\p{N}_.\-]/gu, '').slice(0, 40); }
  catch (e) { return ''; }
}
async function saveRecordedWS() {
  const q = CUR_REQ && CUR_REQ.request;
  if (!q) return;
  let u;
  try { u = new URL(q.url); } catch (e) { toast('这条记录没有可用的 WebSocket 地址'); return; }
  if (u.protocol !== 'ws:' && u.protocol !== 'wss:') { toast('只能把 ws:// 或 wss:// 地址保存为 WebSocket 连接'); return; }
  try {
    if (!MW || !MW.perm_defs) MW = await api('GET', '/api/middleware');
    const m = mwDefault('websocket');
    m.name = wsNameFromURL(q.url);
    m.config.url = q.url || '';
    m.config.ws_messages = [];
    m.fromRecording = true;
    m.recordedBody = q.req_body || '';
    openMWEditor(m);
  } catch (e) { toast(e.message, 5000); }
}
function reqTab(btn) {
  const box = btn.closest('.card');
  box.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b === btn));
  box.querySelectorAll('[data-p]').forEach(p => p.hidden = p.dataset.p !== btn.dataset.t);
}

// ---------- tool editor ----------
let EDIT = null; // {tool, candidates, reqId}
async function openToolEditorFromReq() {
  const d = CUR_REQ;
  const cands = (d.candidates || []).map(c => ({ ...c, on: c.suggest }));
  EDIT = { reqId: d.request.id, candidates: cands, tool: null };
  await redraft();
  const packs = await api('GET', '/api/packs');
  // pre-select the pack(s) the user put the previous recorded tool into (nothing on first use)
  let last = []; try { last = JSON.parse(localStorage.getItem('a2m_last_packs') || '[]'); } catch (e) { }
  EDIT.packs = packs; EDIT.packSel = new Set(packs.filter(p => last.includes(p.id)).map(p => p.id));
  drawEditor();
}
async function redraft() {
  const params = EDIT.candidates.filter(c => c.on);
  const t = await api('POST', `/api/requests/${EDIT.reqId}/draft`, { params });
  if (EDIT.tool) { t.name = EDIT.tool.name || t.name; t.title = EDIT.tool.title || t.title; t.description = EDIT.tool.description || ''; t.method = EDIT.tool.method; t.approval = EDIT.tool.approval; }
  EDIT.tool = t;
}
async function toggleCand(i, on) { EDIT.candidates[i].on = on; collectEditor(); await redraft(); drawEditor(); }
function candName(i, v) { EDIT.candidates[i].name = v.replace(/[^A-Za-z0-9_]/g, '_'); }
function secretCand(c, i) {
  const useRef = c.ref !== '' && c.ref !== undefined && c.ref !== null;
  return `<div class="chk secret-cand"><div>🔒 <span class="mono">${esc(c.path)}</span> <span class="muted small">${c.loc === 'query' ? '网址参数' : c.loc === 'form' ? '表单' : 'JSON'} · 疑似密码 / 敏感值（${esc(c.example)}）</span><br>
    <label class="small"><input type="radio" name="sc${i}" ${useRef ? 'checked' : ''} onchange="secretMode(${i},true)"> 从「配置管理」取（推荐，AI 看不到）</label>
    ${useRef ? `<input class="small mono" style="padding:2px 6px;width:170px" value="${esc(c.ref)}" title="配置项名称" onchange="secretRef(${i},this.value)"> <span class="muted small">${c.ref_exists ? '已存在' : '保存时自动用录制到的值创建'}</span>` : ''}<br>
    <label class="small"><input type="radio" name="sc${i}" ${useRef ? '' : 'checked'} onchange="secretMode(${i},false)"> 让 AI 每次传入</label></div></div>`;
}
async function secretMode(i, ref) {
  const c = EDIT.candidates[i];
  if (ref) { c.ref = c._ref || c.ref || ''; if (!c.ref) c.ref = (c.name || 'password'); c.on = true; }
  else { c._ref = c.ref; c.ref = ''; c.on = true; }
  collectEditor(); await redraft(); drawEditor();
}
async function secretRef(i, v) { EDIT.candidates[i].ref = v.replace(/[^A-Za-z0-9_]/g, '_'); collectEditor(); await redraft(); drawEditor(); }
function refsIn(t) {
  const all = [t.url, t.body, ...Object.values(t.headers || {}), ...((t.config && t.config.messages) || [])].join('\n');
  const refs = [...new Set([...all.matchAll(/\{\{\s*((?:secret|cfg|header|cookie)\.[A-Za-z0-9_.-]+)\s*\}\}/g)].map(m => m[1]))];
  return refs.length ? '<br>当前引用：' + refs.map(r => `<code>${esc(r)}</code>`).join(' ') : '';
}
async function saveLoginReq(id) {
  try {
    const r = await api('POST', `/api/requests/${id}/save-login`, {});
    toast(`已保存：账号 ${r.username_name || '（无）'}、密码 ${r.password_name} 已加密存入配置管理；${r.site.origin} 的登录方式改为「账号密码」`, 6000);
    selectReq(id);
  } catch (e) { toast('保存失败：' + e.message, 5000); }
}
async function editTool(id) {
  const d = await api('GET', '/api/tools/' + id);
  const packs = await api('GET', '/api/packs');
  EDIT = { tool: d.tool, candidates: null, packs, packSel: new Set(packs.filter(p => p.tool_ids.includes(id)).map(p => p.id)) };
  drawEditor();
}
function drawEditor() {
  const t = EDIT.tool;
  const cands = EDIT.candidates;
  if (!t.id && !EDIT.approvalManual) t.approval = defaultToolApproval(t.method);
  openModal(`
  <h2>${t.id ? '编辑工具' : '保存为工具'}</h2>
  ${cands ? `<h3>哪些值需要 AI 每次传入？<span class="muted small" style="font-weight:400">（勾选后会变成参数 {{名称}}）</span></h3>
   ${cands.length ? `<div class="cands">${cands.map((c, i) => c.secret ? secretCand(c, i) : `<label class="chk"><input type="checkbox" ${c.on ? 'checked' : ''} onchange="toggleCand(${i},this.checked)">
     <div><span class="mono">${esc(c.path)}</span> <span class="muted small">${c.loc === 'query' ? '网址参数' : c.loc === 'form' ? '表单' : 'JSON'}</span><br>
     <span class="muted small">示例：${esc(String(c.example).slice(0, 40))}</span>
     ${c.on ? `<br><input class="small" style="padding:2px 6px;width:150px" value="${esc(c.name)}" title="参数名" onchange="candName(${i},this.value);collectEditor();redraft().then(drawEditor)">` : ''}</div></label>`).join('')}</div>`
     : '<div class="muted small">这个请求没有可识别的参数，可以在下面模板里手动写 {{参数名}}。</div>'}<hr style="border:none;border-top:1px solid var(--line);margin:16px 0">` : ''}
  <div class="form-grid">
    <label>工具标识 *</label><input id="t-name" class="mono" value="${esc(t.name)}" placeholder="search_customer（英文、数字、下划线）">
    <label>显示名称</label><input id="t-title" value="${esc(t.title)}" placeholder="查询客户">
    <label>用途说明</label><input id="t-desc" value="${esc(t.description)}" placeholder="告诉 AI 什么时候用它，例如：按关键字查询 CRM 客户，返回客户列表">
    <label>请求</label><div class="row"><select id="t-method" onchange="toolMethodChanged()">${['GET','HEAD','POST','PUT','PATCH','DELETE','WS'].map(m => `<option ${m === t.method ? 'selected' : ''}>${m}</option>`).join('')}</select><input id="t-url" class="grow mono" value="${esc(t.url)}"></div>
    <label for="t-approval">审批模式</label><select id="t-approval" onchange="EDIT.approvalManual=true;EDIT.tool.approval=this.value"><option value="off" ${t.approval !== 'always' ? 'selected' : ''}>不审批</option><option value="always" ${t.approval === 'always' ? 'selected' : ''}>每次都审批</option></select>
    <label for="t-result-format">返回格式</label><div><select id="t-result-format" onchange="resultFormatChanged()">${[['auto','自动清洗'],['raw','原始 HTML'],['selector','只取区域']].map(([v,l]) => `<option value="${v}" ${(t.config && t.config.result_format || 'auto') === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <input id="t-result-selector" class="mono" style="margin-top:6px;width:100%;${(t.config && t.config.result_format) === 'selector' ? '' : 'display:none'}" placeholder="CSS 选择器，例如 div#main 或 #bug-content" value="${esc((t.config && t.config.result_selector) || '')}">
      <div class="muted small">JSON 原样返回。HTML 默认去掉脚本和导航并转成 Markdown；清洗后几乎为空会退回原始 HTML。</div></div>
    <label for="t-detect-failure">失败检测</label><div><label class="chk"><input type="checkbox" id="t-detect-failure" ${(t.config && t.config.detect_failure === false) ? '' : 'checked'}> 开启后，页面上的错误提示或 JSON 失败码会标成工具错误，而不是成功结果。</label></div>
    <label for="t-op-kind">操作类型</label><div><select id="t-op-kind">${[['auto','自动（按请求方法）'],['read','只读'],['write','写操作']].map(([v,l]) => `<option value="${v}" ${(t.config && t.config.op_kind || 'auto') === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <div class="muted small">站点用 POST 做查询时应选「只读」，这样不会被标成写操作。</div></div>
    <label>请求头 (JSON)</label><textarea id="t-headers" style="min-height:80px">${esc(JSON.stringify(t.headers || {}, null, 2))}</textarea>
    <label>请求体模板</label><textarea id="t-body" style="min-height:120px">${esc(t.body || '')}</textarea>
    ${String(t.method).toUpperCase() === 'WS' ? `<label>WebSocket 消息</label><textarea id="t-messages" class="mono" style="min-height:120px">${esc((t.config && t.config.messages || []).join('\n'))}</textarea>
    <label>SQL 护栏</label><div class="row"><label class="chk"><input type="checkbox" id="t-sqlguard" ${t.config && t.config.sql_guard && t.config.sql_guard.enabled ? 'checked' : ''}> 仅允许单条只读 SELECT，且必须有 LIMIT（最多 200 行）</label></div>
    <div class="muted small">护栏开启后执行前会发 EXPLAIN 预检；关闭护栏不能同时把审批降为「不审批」。令牌请使用 <code>{{header.sso-epctoken}}</code>，不要写入字面值。</div>` : ''}
    <label>参数</label><div id="t-params">${paramsTable(t.params || [])}</div>
    <label>配置引用</label><div class="muted small">模板里可以写 <code>{{secret.名称}}</code> / <code>{{cfg.名称}}</code> 引用「配置管理」里的值，调用时在本机替换，AI 看不到。${refsIn(t)}</div>
    <label>登录凭证</label><div class="ok-notice">${(t.cred_headers || []).length ? `已移除 <span class="mono">${esc(t.cred_headers.join(', '))}</span>，不会保存进工具。` : '工具里不保存任何登录凭证。'}调用时会自动从专用浏览器的登录态里取 Cookie（CSRF 类请求头会从同名 Cookie 自动补上）。</div>
    <label>放进流程包</label><div class="row">${(EDIT.packs || []).map(p => `<label class="chk"><input type="checkbox" class="t-pack" value="${p.id}" ${EDIT.packSel.has(p.id) ? 'checked' : ''}> ${esc(p.name)} ${p.enabled ? '<span class="badge" style="background:#dcfce7;color:#15803d">已开启</span>' : ''}</label>`).join('')}
      <input id="t-newpack" placeholder="或新建流程包，如：客服查单" style="width:220px"></div>
    <div class="muted small">可以不选：工具会先保存，之后在「流程包」页用「+ 添加工具」放进去。</div>
  </div>
  <div class="row" style="margin-top:18px;justify-content:flex-end"><button onclick="closeModal()">取消</button><button class="pri big" onclick="saveTool()">保存工具</button></div>`);
}
function defaultToolApproval(method) { return ['POST', 'PUT', 'PATCH', 'DELETE', 'WS'].includes(String(method).toUpperCase()) ? 'always' : 'off'; }
function toolMethodChanged() {
  EDIT.tool.method = $('#t-method').value;
  if (!EDIT.tool.id && !EDIT.approvalManual) $('#t-approval').value = EDIT.tool.approval = defaultToolApproval(EDIT.tool.method);
}
function paramsTable(ps) {
  if (!ps.length) return '<span class="muted small">无参数（模板里出现的 {{名称}} 会自动成为参数）</span>';
  return `<table class="kv"><tr><td>名称</td><td>类型</td><td>必填</td><td>说明（给 AI 看）</td><td>示例/默认值</td></tr>${ps.map((p, i) => `<tr data-pi="${i}">
   <td class="mono">${esc(p.name)}</td>
   <td><select class="p-type">${['string','number','integer','boolean'].map(x => `<option ${x === p.type ? 'selected' : ''}>${x}</option>`).join('')}</select></td>
   <td><input type="checkbox" class="p-req" ${p.required ? 'checked' : ''}></td>
   <td><input class="p-desc" style="width:100%" value="${esc(p.description)}"></td>
   <td><input class="p-def" style="width:110px" value="${esc(p.default || '')}"></td></tr>`).join('')}</table>`;
}
function resultFormatChanged() {
  const sel = $('#t-result-selector');
  const fmt = $('#t-result-format');
  if (sel && fmt) sel.style.display = fmt.value === 'selector' ? '' : 'none';
}
function collectEditor() {
  const t = EDIT.tool; if (!$('#t-name')) return t;
  t.name = $('#t-name').value.trim(); t.title = $('#t-title').value.trim(); t.description = $('#t-desc').value.trim();
  t.method = $('#t-method').value; t.url = $('#t-url').value.trim(); t.body = $('#t-body').value;
  t.approval = $('#t-approval').value;
  t.config = t.config || {};
  if ($('#t-result-format')) t.config.result_format = $('#t-result-format').value || 'auto';
  if ($('#t-result-selector')) t.config.result_selector = $('#t-result-selector').value.trim();
  if ($('#t-detect-failure')) t.config.detect_failure = $('#t-detect-failure').checked;
  if ($('#t-op-kind')) t.config.op_kind = $('#t-op-kind').value || 'auto';
  try { t.headers = JSON.parse($('#t-headers').value || '{}'); } catch { throw new Error('请求头不是合法的 JSON'); }
  if (String(t.method).toUpperCase() === 'WS') {
    t.config = t.config || {};
    if ($('#t-messages')) t.config.messages = $('#t-messages').value.split('\n').map(s => s.trim()).filter(Boolean);
    const on = $('#t-sqlguard') ? $('#t-sqlguard').checked : !!(t.config.sql_guard && t.config.sql_guard.enabled);
    t.config.sql_guard = Object.assign({ param: 'sql', path: 'data.sql', max_rows: 200 }, t.config.sql_guard || {}, { enabled: on });
  }
  document.querySelectorAll('#t-params tr[data-pi]').forEach(tr => {
    const p = t.params[+tr.dataset.pi]; if (!p) return;
    p.type = $('.p-type', tr).value; p.required = $('.p-req', tr).checked; p.description = $('.p-desc', tr).value; p.default = $('.p-def', tr).value;
  });
  EDIT.packSel = new Set([...document.querySelectorAll('.t-pack:checked')].map(x => +x.value));
  return t;
}
async function saveTool() {
  let t;
  try { t = collectEditor(); } catch (e) { toast(e.message); return; }
  try {
    const saved = t.id ? await api('PUT', '/api/tools/' + t.id, t) : await api('POST', '/api/tools', t);
    const newPack = $('#t-newpack').value.trim();
    const packs = await api('GET', '/api/packs');
    for (const p of packs) {
      const want = EDIT.packSel.has(p.id), has = p.tool_ids.includes(saved.id);
      if (want && !has) await api('POST', `/api/packs/${p.id}/tools`, { ids: [saved.id] });
      if (!want && has) await api('DELETE', `/api/packs/${p.id}/tools/${saved.id}`);
    }
    let np = null;
    if (newPack) np = await api('POST', '/api/packs', { name: newPack, description: '', enabled: true, tool_ids: [saved.id] });
    if (!t.id) localStorage.setItem('a2m_last_packs', JSON.stringify([...EDIT.packSel, ...(np ? [np.id] : [])]));
    closeModal(); toast('已保存工具 ' + saved.name + (newPack ? '，并放进新流程包「' + newPack + '」（已开启）' : ''));
    refreshStatus(); if (ROUTE === 'tools') render();
  } catch (e) { toast('保存失败：' + e.message, 5000); }
}

// ---------- tools ----------
async function pageTools(app) {
  const tools = await api('GET', '/api/tools');
  app.innerHTML = `<h2>工具 <span class="muted small" style="font-weight:400">共 ${tools.length} 个。工具要放进「已开启」的流程包，AI 才能看到。</span></h2>
  ${tools.length === 0 ? '<div class="card empty">还没有工具。先去「录制」页录一次操作，再把有用的请求保存为工具。</div>' :
  tools.map(t => `<div class="card"><div class="row">
    <div class="grow"><b class="mono" style="font-size:15px">${esc(t.name)}</b> <span>${esc(t.title)}</span>
      <div class="muted small">${esc(t.description || '（没有用途说明，建议补充，AI 会更会用）')}</div>
      <div class="small" style="margin-top:4px">${methodBadge(t.method)} <span class="mono">${esc(t.url)}</span></div>
      <div class="small muted" style="margin-top:4px">参数：${t.params.length ? t.params.map(p => `<code>${esc(p.name)}</code>`).join(' ') : '无'}　·　流程包：${(t.packs || []).length ? t.packs.map(esc).join('、') : '<span style="color:var(--amber)">未加入任何流程包</span>'}</div></div>
    <button class="pri" onclick="testTool(${t.id})">▶ 测试</button><button onclick="editTool(${t.id})">编辑</button>${isWSGuardTool(t) ? `<button onclick="convertToolToMW(${t.id})">转为 SQL 控制台</button>` : ''}<button class="danger" onclick="delTool(${t.id})">删除</button></div></div>`).join('')}`;
}
function isWSGuardTool(t) {
  return String(t.method || '').toUpperCase() === 'WS' && t.config && t.config.sql_guard && t.config.sql_guard.enabled;
}
async function convertToolToMW(id) {
  if (!confirm('把这个 WebSocket SQL 工具转成「中间件管理」里的 SQL 控制台？原工具会删除，所属流程包会改挂到新的中间件。请补全数据源的名称和说明。')) return;
  try {
    const m = await api('POST', '/api/tools/' + id + '/convert-to-middleware');
    toast('已转为中间件「' + m.name + '」，请到「中间件」页核对数据源并填写说明');
    refreshStatus(); render();
  } catch (e) { toast('转换失败：' + e.message, 5000); }
}
async function delTool(id) { if (!confirm('删除这个工具？')) return; await api('DELETE', '/api/tools/' + id); refreshStatus(); render(); }
async function testTool(id) {
  const d = await api('GET', '/api/tools/' + id);
  const t = d.tool;
  openModal(`<h2>测试工具 <span class="mono">${esc(t.name)}</span></h2>
   <div class="form-grid">${t.params.map(p => `<label>${esc(p.name)}${p.required ? ' *' : ''}</label><input class="targ" data-n="${esc(p.name)}" data-t="${esc(p.type)}" value="${esc(p.default || '')}" placeholder="${esc(p.description)}">`).join('') || '<div class="full muted">这个工具没有参数</div>'}</div>
   <div class="row" style="margin-top:14px"><button class="pri" onclick="runTool(${id})">▶ 运行</button><span class="muted small">会用专用浏览器里的登录态发出真实请求</span></div>
   <div id="run-out" style="margin-top:12px"></div>`);
}
async function runTool(id) {
  const args = {};
  document.querySelectorAll('.targ').forEach(i => { let v = i.value; if (i.dataset.t === 'number' || i.dataset.t === 'integer') v = v === '' ? undefined : Number(v); if (i.dataset.t === 'boolean') v = v === 'true'; if (v !== undefined) args[i.dataset.n] = v; });
  $('#run-out').innerHTML = '<div class="muted">请求中…</div>';
  try {
    const r = await api('POST', `/api/tools/${id}/run`, { args });
    $('#run-out').innerHTML = `<div class="row"><b class="${r.status && r.status < 400 ? 'st-ok' : 'st-bad'}">HTTP ${r.status || '失败'}</b><span class="muted small">${r.duration_ms} ms · 登录态来源：${esc(r.cred_source)} · 带上的 Cookie：${(r.cookie_names || []).map(esc).join(', ') || '无'}</span></div>
      ${r.error ? `<div class="notice">${esc(r.error)}</div>` : ''}
      ${r.status === 401 || r.status === 403 ? '<div class="notice">目标网站返回未登录/无权限：点「录制」页的「打开浏览器登录」登录一次后再试。</div>' : ''}
      <div class="small muted" style="margin-top:6px">${esc(r.method)} ${esc(r.url)}</div>${r.request_body ? `<pre>${esc(r.request_body)}</pre>` : ''}
      <div class="small muted" style="margin-top:8px">响应</div><pre>${esc(pretty(r.body))}</pre>`;
  } catch (e) { $('#run-out').innerHTML = `<div class="notice">${esc(e.message)}</div>`; }
}

// ---------- packs ----------
async function pagePacks(app) {
  const [packs, tools, mwr] = await Promise.all([api('GET', '/api/packs'), api('GET', '/api/tools'), api('GET', '/api/middleware')]);
  const mws = mwr.items; MW = mwr;
  PACKDATA = { packs, tools, mws };
  const toolById = Object.fromEntries(tools.map(t => [t.id, t])), mwById = Object.fromEntries(mws.map(m => [m.id, m]));
  await refreshStatus();
  const on = packs.filter(p => p.enabled);
  const tiered = STATUS.mcp_mode !== 'flat';
  app.innerHTML = `
  <div class="card mode-card"><h3 style="margin-top:0">AI 获取工具的方式（MCP 暴露模式）</h3>
    <div class="mode-opts">
      <label class="mode-opt ${tiered ? 'sel' : ''}"><input type="radio" name="mcpmode" ${tiered ? 'checked' : ''} onchange="setMode('tiered')">
        <div><b>阶梯模式</b> <span class="badge" style="background:#e0e7ff;color:#3730a3">推荐</span><br><span class="muted small">AI 连上后只看到 4 个入口工具：先 <code>list_packs</code> 看有哪些流程包和适用场景，再按任务 <code>load_pack</code> 加载需要的包，用完 <code>unload_pack</code>。上下文最小，不相关的工具不会塞给 AI。</span></div></label>
      <label class="mode-opt ${!tiered ? 'sel' : ''}"><input type="radio" name="mcpmode" ${!tiered ? 'checked' : ''} onchange="setMode('flat')">
        <div><b>平铺模式</b><br><span class="muted small">AI 一连上就看到所有已开启流程包里的全部工具（0.3.0 及以前的方式）。适合工具很少，或者客户端不支持动态刷新工具列表的情况。</span></div></label>
    </div></div>
  <div class="expose">${tiered
    ? `阶梯模式：AI 先看到 <b>4</b> 个入口工具，可按需加载 ${on.length} 个已开启的流程包${on.length ? '：' + on.map(p => '「' + esc(p.name) + '」').join('') : ''}（共 ${STATUS.exposed_tools} 个工具${STATUS.exposed_middleware ? `，含 ${STATUS.exposed_middleware} 个中间件的通用工具` : ''}）。
    <div class="muted small">关闭的流程包 AI 看不到、也加载不了。请给每个流程包写好「说明」和「适用场景」，AI 会据此判断该加载哪个包。「使用说明」会在加载之后交给 AI，用来说明工具顺序。开关变化会实时通知已连接的 AI 客户端。</div>`
    : `平铺模式：AI 当前能看到 <b>${STATUS.exposed_tools}</b> 个工具${STATUS.exposed_middleware ? `（含 ${STATUS.exposed_middleware} 个中间件的通用工具）` : ''}，来自 ${on.length} 个已开启的流程包${on.length ? '：' + on.map(p => '「' + esc(p.name) + '」').join('') : ''}。
    <div class="muted small">只开当前工作要用的流程包，AI 的上下文更干净、更不容易用错工具。切换后在 AI 客户端里重新连接 / 刷新 MCP 即可生效。</div>`}</div>
  <div class="card"><h3>新建流程包</h3><div class="row"><input id="p-name" placeholder="流程包名称，如：客服查单"><input id="p-desc" class="grow" placeholder="说明（可选）"></div>
    <div class="row" style="margin-top:8px"><input id="p-scen" class="grow" placeholder="适用场景（可选，给 AI 看的），如：查询订单状态、处理客户退款、记录工时"><button class="pri" onclick="createPack()">新建</button></div></div>
  ${packs.length === 0 ? '<div class="card empty">还没有流程包。流程包 = 一组一起开、一起关的工具，比如「财务开票」「客服查单」。</div>' :
  packs.map(p => `<div class="pack ${p.enabled ? 'on' : ''}">
    <div class="row"><label class="switch"><input type="checkbox" ${p.enabled ? 'checked' : ''} onchange="togglePack(${p.id},this.checked)"><span></span></label>
      <div class="grow"><b style="font-size:15px">${esc(p.name)}</b> <span class="muted small">${p.enabled ? '已开启' : '已关闭'} · ${p.tool_ids.length} 个工具 · ${(p.middleware_ids || []).length} 个中间件</span></div>
      <button class="danger" onclick="delPack(${p.id})">删除</button></div>
    <div class="pack-meta"><label class="small muted">说明</label><input value="${esc(p.description)}" placeholder="这个流程包是做什么的" onchange="packField(${p.id},'description',this.value)">
      <label class="small muted">适用场景</label><input value="${esc(p.scenarios || '')}" placeholder="AI 遇到哪些任务时该加载它，如：记工时、查我的任务、提交日报" onchange="packField(${p.id},'scenarios',this.value)"></div>
    <div class="pack-guide"><label class="small muted">使用说明</label><textarea class="mono" placeholder="可选。加载后 AI 会先看这段。写清先调哪个工具、上一步的哪个结果填下一步。不要写密码、Cookie 或密钥。" onchange="packField(${p.id},'guide',this.value)">${esc(p.guide || '')}</textarea>
      <div class="muted small">最多 8KB。阶梯模式在 load_pack 的返回里给出。平铺模式写在连接说明里，改完需要重新连接。</div></div>
    <div class="sec-head"><span class="muted small">工具（${p.tool_ids.length}）</span><button class="sm add-btn" data-add="tools" onclick="openPackPicker(${p.id},'tools')">+ 添加工具</button></div>
    <div class="chips">${p.tool_ids.map(id => toolById[id]).filter(Boolean).map(t => `<div class="chip" data-tool="${esc(t.name)}"><div class="chip-txt"><span class="mono">${esc(t.name)}</span><span class="muted small">${esc(t.title || t.description || '')}</span></div><button class="chip-x" title="从流程包移除（工具本身不会删除）" onclick="removeFromPack(${p.id},'tools',${t.id})">×</button></div>`).join('') || '<div class="muted small chips-empty">还没有工具，点「+ 添加工具」把需要的工具加进来。</div>'}</div>
    <div class="sec-head" style="margin-top:12px"><span class="muted small">中间件（${(p.middleware_ids || []).length}）· 加入后 AI 可以按权限操作它们，见「中间件」页</span><button class="sm add-btn" data-add="middleware" onclick="openPackPicker(${p.id},'middleware')">+ 添加中间件</button></div>
    <div class="chips">${(p.middleware_ids || []).map(id => mwById[id]).filter(Boolean).map(m => `<div class="chip" data-mw="${esc(m.name)}"><div class="chip-txt"><span><span class="mw-type t-${esc(m.type)}">${esc(m.kind_label)}</span> <b>${esc(m.name)}</b></span><span class="muted small">${esc(permText(m))}</span></div><button class="chip-x" title="从流程包移除（中间件本身不会删除）" onclick="removeFromPack(${p.id},'middleware',${m.id})">×</button></div>`).join('') || '<div class="muted small chips-empty">还没有中间件。需要查库、读缓存、收发消息时点「+ 添加中间件」。</div>'}</div>
  </div>`).join('')}`;
}
async function createPack() {
  const name = $('#p-name').value.trim(); if (!name) { toast('请输入流程包名称'); return; }
  try { await api('POST', '/api/packs', { name, description: $('#p-desc').value.trim(), scenarios: $('#p-scen').value.trim(), enabled: true, tool_ids: [] }); render(); } catch (e) { toast(e.message); }
}
async function setRecAnalysis(on) {
  try {
    await api('PUT', '/api/settings', { rec_analysis: on });
    toast(on ? '已开启录制分析：AI 可以识别录制并保存成工具' : '已关闭录制分析：AI 不再看到这些工具');
    render();
  } catch (e) { toast(e.message); render(); }
}
async function setMode(m) {
  await api('PUT', '/api/settings', { mcp_mode: m });
  toast(m === 'flat' ? '已切换为平铺模式：AI 直接看到所有已开启流程包的工具' : '已切换为阶梯模式：AI 先列出流程包，再按需加载', 5000);
  render();
}
async function packField(pid, field, val) {
  const packs = await api('GET', '/api/packs'); const p = packs.find(x => x.id === pid);
  p[field] = val.trim();
  try { await api('PUT', '/api/packs/' + pid, p); toast('已保存'); } catch (e) { toast(e.message); }
}
async function togglePack(id, en) { await api('POST', `/api/packs/${id}/toggle`, { enabled: en }); toast(en ? '已开启，AI 可以看到这组工具' : '已关闭，这组工具对 AI 隐藏'); render(); }
let PACKDATA = null;
function openPackPicker(pid, kind) {
  const { packs, tools, mws } = PACKDATA;
  const p = packs.find(x => x.id === pid);
  const isTools = kind === 'tools';
  const have = new Set(isTools ? p.tool_ids : (p.middleware_ids || []));
  const items = (isTools ? tools : mws).filter(x => !have.has(x.id));
  const total = (isTools ? tools : mws).length;
  const row = x => isTools
    ? `<label class="chk pick-row" data-q="${esc((x.name + ' ' + (x.title || '') + ' ' + (x.description || '')).toLowerCase())}"><input type="checkbox" class="pick" value="${x.id}"><div><span class="mono">${esc(x.name)}</span>${x.title ? ' · ' + esc(x.title) : ''}<br><span class="muted small">${esc(x.description || '')}</span></div></label>`
    : `<label class="chk pick-row" data-q="${esc((x.name + ' ' + x.kind_label + ' ' + (x.config.description || '')).toLowerCase())}"><input type="checkbox" class="pick" value="${x.id}"><div><span class="mw-type t-${esc(x.type)}">${esc(x.kind_label)}</span> <b>${esc(x.name)}</b><br><span class="muted small">${esc(permText(x))}</span></div></label>`;
  const what = isTools ? '工具' : '中间件';
  openModal(`<button class="modal-close" onclick="closeModal()">×</button>
    <h2 style="margin-top:0">添加${what}到「${esc(p.name)}」</h2>
    ${items.length ? `<div class="row"><input id="pick-q" class="grow" placeholder="搜索${what}名称或说明" oninput="filterPick()"><label class="small" style="white-space:nowrap"><input type="checkbox" id="pick-all" onchange="pickAll(this.checked)"> 全选</label></div>
    <div class="pick-list">${items.map(row).join('')}</div>
    <div class="muted small" id="pick-none" style="display:none;padding:12px 0">没有匹配的${what}</div>`
    : `<div class="empty">${total ? `所有${what}都已经在这个流程包里了。` : (isTools ? '还没有工具，请先录制并保存为工具。' : '还没有中间件，可在「中间件」页添加。')}</div>`}
    <div class="row" style="justify-content:flex-end;margin-top:16px"><span class="muted small grow" id="pick-count">已选 0 个</span><button onclick="closeModal()">取消</button><button class="pri" id="pick-ok" ${items.length ? '' : 'disabled'} onclick="confirmPick(${pid},'${kind}')">确定</button></div>`);
  document.querySelectorAll('#modal-body .pick').forEach(c => c.addEventListener('change', pickCount));
  const q = $('#pick-q'); if (q) q.focus();
}
function pickCount() { $('#pick-count').textContent = `已选 ${document.querySelectorAll('#modal-body .pick:checked').length} 个`; }
function filterPick() {
  const q = $('#pick-q').value.trim().toLowerCase(); let n = 0;
  document.querySelectorAll('#modal-body .pick-row').forEach(r => { const on = !q || r.dataset.q.includes(q); r.style.display = on ? '' : 'none'; if (on) n++; });
  $('#pick-none').style.display = n ? 'none' : '';
}
function pickAll(on) { document.querySelectorAll('#modal-body .pick-row').forEach(r => { if (r.style.display !== 'none') r.querySelector('.pick').checked = on; }); pickCount(); }
async function confirmPick(pid, kind) {
  const ids = [...document.querySelectorAll('#modal-body .pick:checked')].map(x => +x.value);
  if (!ids.length) { toast('请先勾选要添加的' + (kind === 'tools' ? '工具' : '中间件')); return; }
  try { const r = await api('POST', `/api/packs/${pid}/${kind}`, { ids }); closeModal(); toast(`已添加 ${r.added} 个${kind === 'tools' ? '工具' : '中间件'}`); render(); } catch (e) { toast(e.message); }
}
async function removeFromPack(pid, kind, id) {
  const it = (kind === 'tools' ? PACKDATA.tools : PACKDATA.mws).find(x => x.id === id); const name = it ? it.name : '#' + id;
  try { await api('DELETE', `/api/packs/${pid}/${kind}/${id}`); toast(`已从流程包移除「${name}」（${kind === 'tools' ? '工具' : '中间件'}本身没有删除）`); render(); } catch (e) { toast(e.message); }
}
async function delPack(id) { if (!confirm('删除这个流程包？（工具本身不会删除）')) return; await api('DELETE', '/api/packs/' + id); render(); }

// ---------- settings ----------
async function pageSettings(app) {
  await refreshStatus();
  const creds = await api('GET', '/api/credentials');
  const settings = await api('GET', '/api/settings');
  const recOn = !!settings.rec_analysis;
  const s = STATUS;
  const exe = s.exe_path || 'a2m';
  const mcpURL = s.mcp_url;
  const cfgClaude = JSON.stringify({ mcpServers: { action2mcp: { command: exe, args: ['mcp'] } } }, null, 2);
  const cfgCursor = JSON.stringify({ mcpServers: { action2mcp: { url: mcpURL } } }, null, 2);
  const cfgCodex = `[mcp_servers.action2mcp]\ncommand = ${JSON.stringify(exe)}\nargs = ["mcp"]`;
  app.innerHTML = `
  <div class="card"><h2>接入 AI</h2>
    <p>MCP 地址（Streamable HTTP）：<code>${esc(mcpURL)}</code>　·　只支持命令行方式的客户端，用 <code>${esc(exe)} mcp</code>（stdio）。</p>
    <h3>Cursor（~/.cursor/mcp.json）</h3><pre>${esc(cfgCursor)}</pre>
    <h3 style="margin-top:14px">Claude Desktop（claude_desktop_config.json）</h3><pre>${esc(cfgClaude)}</pre>
    <h3 style="margin-top:14px">Codex（~/.codex/config.toml）</h3><pre>${esc(cfgCodex)}</pre>
    <h3 style="margin-top:14px">Claude Code</h3><pre>claude mcp add --transport http action2mcp ${esc(mcpURL)}</pre>
    <p class="muted small">AI 调用工具时，Action2MCP 必须在运行（stdio 方式会自动在后台启动它）。</p>
    <p class="small">当前 MCP 暴露模式：<b>${s.mcp_mode === 'flat' ? '平铺模式' : '阶梯模式'}</b>（在「流程包」页切换）。${s.mcp_mode === 'flat' ? '' : 'AI 会先调用 <code>list_packs</code> 查看流程包，再 <code>load_pack</code> 加载需要的那个；客户端不刷新工具列表时用 <code>call_pack_tool</code> 调用。'}</p></div>
  <div class="card"><h2>录制分析</h2>
    <div class="row">
      <label class="switch"><input type="checkbox" ${recOn ? 'checked' : ''} onchange="setRecAnalysis(this.checked)"><span></span></label>
      <div class="grow"><b>让 AI 分析录制</b>
        <div class="muted small">默认开启。AI 可以通过内置流程包「录制分析」列出录制、查看请求、给接口写作用，并把完成流程所需的最少请求保存成工具。对 AI 说「帮我把录制记录里的某某流程识别一下并保存成工具」即可。如果没说保存到哪个流程包，AI 会先问你。关闭后这些 rec_* 工具不再出现，也无法调用。返回给 AI 的内容会去掉 Cookie、Token 和密码。</div>
      </div>
    </div>
  </div>
  <div class="card"><h2>审批设置</h2>
    <form class="row" onsubmit="event.preventDefault();saveApprovalTimeout(this)">
      <label for="approval-timeout">审批等待时间（秒）</label>
      <input id="approval-timeout" name="approval_timeout_secs" type="number" min="30" max="1800" step="1" required value="${esc(settings.approval_timeout_secs ?? 300)}" aria-describedby="approval-timeout-hint">
      <button type="submit" class="pri">保存</button><span class="muted small" id="approval-timeout-hint">30–1800，默认 300。超时后本次调用不会执行。</span>
    </form>
  </div>
  <div class="card"><h2>导出 / 导入</h2>
    <p class="muted">导出的 .a2m 文件只有工具定义、流程包、登录配置和配置项的<b>名称</b>，<b>不包含任何 Cookie、Token、登录态，也不包含密码等配置值</b>，可以放心发给同事。对方导入后，在「配置管理」里填上自己的账号密码（或用企业微信登录一次）就能用。</p>
    <div class="row"><a class="btn pri" style="background:var(--pri);color:#fff" href="/api/export">⬇ 导出 .a2m</a>
    <label class="btn">⬆ 导入 .a2m<input type="file" accept=".a2m,.json" style="display:none" onchange="importFile(this)"></label></div></div>
  <div class="card"><h2>登录态</h2>
    <p class="muted">登录态只保存在本机的 <code>${esc(s.data_dir)}</code> 里（专用浏览器配置 + 本地快照），不会进入工具和导出文件。</p>
    <p>已保存登录态的网站：${Object.keys(creds.domains).length ? Object.entries(creds.domains).map(([d, n]) => `<code>${esc(d)}</code>`).join(' ') : '<span class="muted">暂无</span>'}</p>
    <div class="row"><button onclick="openLogin()">打开浏览器登录</button><button class="danger" onclick="clearCreds()">清除本地登录态快照</button></div></div>
  <div class="card small muted row" style="justify-content:space-between">
    <span>Action2MCP ${esc(s.version)} · 进程 ${s.pid} · 数据目录 ${esc(s.data_dir)}${s.update?.checked_at ? ` · 上次检查更新 ${esc(s.update.checked_at)}` : ''}</span>
    <button type="button" class="sm" onclick="checkUpdateManual(this)">检查更新</button>
  </div>`;
}

function openUpdateModal() {
  const u = STATUS.update;
  if (!u || !u.available) {
    toast('当前已是最新版本 v' + (STATUS.version || ''));
    return;
  }
  openModal(`
    <h2>发现新版本 v${esc(u.latest_version)}</h2>
    <p>当前版本：<code>v${esc(u.current_version || STATUS.version)}</code> → 最新版本：<b style="color:var(--green)">v${esc(u.latest_version)}</b>${u.asset_name ? ` <span class="muted small">(${esc(u.asset_name)})</span>` : ''}</p>
    ${u.release_notes ? `<div class="small muted" style="margin-top:8px">更新说明：</div><pre style="max-height:200px;white-space:pre-wrap">${esc(u.release_notes)}</pre>` : ''}
    <p class="muted small" style="margin-top:12px">点击「立即更新并重启」将自动下载新版本并重启服务，本地所有配置、工具与登录数据均不受影响。</p>
    <div class="row" style="margin-top:18px;justify-content:flex-end">
      <button type="button" id="cancel-update-btn" onclick="closeModal()">稍后再说</button>
      <button type="button" class="pri big" id="confirm-update-btn" onclick="applySelfUpdate(this)">⬆ 立即更新并重启</button>
    </div>`);
  $('#confirm-update-btn')?.focus();
}

async function checkUpdateManual(btn) {
  if (btn) { btn.disabled = true; btn.textContent = '检查中…'; }
  try {
    const u = await api('POST', '/api/update/check', {});
    await refreshStatus();
    if (u.available) {
      openUpdateModal();
    } else {
      toast(`当前已是最新版本（v${u.current_version || STATUS.version}）`);
      if (ROUTE === 'settings') render();
    }
  } catch (e) {
    toast('检查更新失败：' + e.message, 5000);
  } finally {
    if (btn && btn.isConnected) { btn.disabled = false; btn.textContent = '检查更新'; }
  }
}

async function applySelfUpdate(btn) {
  const cancelBtn = $('#cancel-update-btn');
  const oldPID = STATUS.pid;
  if (btn) {
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.textContent = '正在下载并替换新版本…';
  }
  if (cancelBtn) cancelBtn.disabled = true;
  try {
    const r = await api('POST', '/api/update', {});
    if (btn) btn.textContent = `正在重启至 v${r.target_version || ''}，请稍候…`;
    for (let i = 0; i < 45; i++) {
      await new Promise(res => setTimeout(res, 600));
      try {
        const st = await api('GET', '/api/status');
        if (st && st.version && (st.pid !== oldPID || st.version === r.target_version)) {
          STATUS = st;
          closeModal();
          await refreshStatus();
          await render();
          toast(`已成功更新并重启至 v${st.version}`, 6000);
          return;
        }
      } catch {
        // Server is briefly offline while restarting; keep polling.
      }
    }
    toast('更新已完成，请手动刷新页面查看最新状态', 6000);
    closeModal();
    await refreshStatus();
    await render();
  } catch (e) {
    toast('更新失败：' + e.message, 6000);
    if (btn && btn.isConnected) {
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
      btn.textContent = '⬆ 立即更新并重启';
    }
    if (cancelBtn && cancelBtn.isConnected) cancelBtn.disabled = false;
  }
}
async function saveApprovalTimeout(form) {
  const secs = Number(form.elements.approval_timeout_secs.value);
  if (!Number.isInteger(secs) || secs < 30 || secs > 1800) { toast('审批等待时间必须是 30–1800 的整数'); return; }
  const btn = $('button[type="submit"]', form); btn.disabled = true;
  try { await api('PUT', '/api/settings', { approval_timeout_secs: secs }); toast('审批等待时间已保存'); }
  catch (e) { toast('保存失败：' + e.message, 5000); }
  finally { btn.disabled = false; }
}
async function importFile(inp) {
  const f = inp.files[0]; if (!f) return;
  try { const r = await api('POST', '/api/import', await f.text()); toast(`导入完成：新增工具 ${r.tools_added}，更新 ${r.tools_updated}；新增流程包 ${r.packs_added}；登录配置 ${r.sites_added + r.sites_updated} 个` + ((r.vault_to_fill || []).length ? `。请到「配置管理」填写：${r.vault_to_fill.join('、')}` : ''), 7000); refreshStatus(); }
  catch (e) { toast('导入失败：' + e.message, 5000); }
  inp.value = '';
}
async function clearCreds() { if (!confirm('清除本地登录态快照？（专用浏览器里的登录不受影响）')) return; await api('DELETE', '/api/credentials'); render(); }

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});
refreshStatus().then(render);

// ---------- 登录中心 ----------
const METHOD_NAMES = { wecom_sso: '企业微信 / 单点登录', form: '账号密码', manual: '手动登录' };
const STATUS_NAMES = { valid: ['有效', 'st-ok'], invalid: ['已失效', 'st-bad'], unknown: ['未知', 'muted'] };
let SITES = [];
async function pageSites(app) {
  SITES = await api('GET', '/api/sites');
  app.innerHTML = `
  <div class="card"><h2>登录中心</h2>
    <p class="muted small">AI 调用工具时，如果目标网站返回“未登录”（401/403、被跳转到登录页、返回登录页面或“请先登录”提示），Action2MCP 会按这里的配置在后台自动重新登录，然后重试一次。
    支持企业微信的网站用<b>企业微信 / 单点登录</b>；不支持的网站用<b>账号密码</b>（账号密码保存在「配置管理」里，AI 看不到）。保存工具时会自动为新网站创建一条配置；点「打开浏览器登录」会先自动验证登录及重登配置，仅在失效或未配置时打开浏览器录入并更新账号密码或单点登录配置。</p>
    ${SITES.length === 0 ? '<div class="empty">还没有网站。保存第一个工具后会自动出现在这里。</div>' : `
    <table><thead><tr><th>网站</th><th>登录方式</th><th>状态</th><th>上次登录</th><th></th></tr></thead><tbody>
    ${SITES.map(s => { const st = STATUS_NAMES[s.status] || STATUS_NAMES.unknown; return `<tr>
      <td><b>${esc(s.name || hostOf(s.origin))}</b><div class="muted small mono">${esc(s.origin)}</div>
        <div class="muted small">${s.tools.length ? '工具：' + s.tools.map(esc).join('、') : '暂无工具'}</div></td>
      <td>${esc(METHOD_NAMES[s.method] || s.method)}${s.method === 'form' ? `<div class="muted small">${(s.form.mode !== 'fill' && s.form.request) ? '重放录制的登录请求' : '浏览器自动填表'}${(s.form.password_ref || s.creds.length) ? '' : ' · <span class="st-bad">未配置账号密码</span>'}</div>` : ''}
        ${s.keepalive_min ? `<div class="muted small">保活：每 ${s.keepalive_min} 分钟</div>` : ''}</td>
      <td><b class="${st[1]}">${st[0]}</b>${s.pending ? `<div class="small" style="color:#b45309">${esc(s.pending_msg || '等待登录')}…</div>` : ''}
        ${s.last_error && s.status !== 'valid' ? `<div class="muted small" style="max-width:280px">${esc(s.last_error)}</div>` : ''}
        ${s.cooldown ? `<div class="small st-bad">已暂停自动登录（密码错误）</div>` : ''}</td>
      <td class="small">${esc(s.last_login_at || '-')}<div class="muted small">自动登录 ${s.login_count} 次</div></td>
      <td style="text-align:right;white-space:nowrap">${s.pending ? `<button onclick="siteCancel(${s.id}, this)">取消</button> ` : ''}<button onclick="siteRelogin(${s.id}, this)">测试重新登录</button> <button onclick="siteOpen(${s.id}, this)">打开浏览器登录</button>
        <button onclick="editSite(${s.id})">编辑</button> <button class="danger" onclick="delSite(${s.id})">删除</button></td></tr>`; }).join('')}
    </tbody></table>`}
    <div class="row" style="margin-top:12px"><button onclick="editSite(0)">＋ 添加网站</button><button onclick="render()">刷新</button></div>
  </div>
  <div class="card small muted">提示：企业微信本身的登录（扫码）过期时，AI 调用会返回“企业微信登录已过期，请在弹出的窗口扫码后重试”，并自动弹出登录窗口；扫码后再让 AI 重试即可。</div>`;
  const pending = SITES.some(s => s.pending);
  clearTimeout(pageSites._poll);
  if (pending) pageSites._poll = setTimeout(() => { if (ROUTE === 'sites' || location.hash === '#/sites') render(); }, 1500);
}
async function siteRelogin(id, btn) {
  btn.disabled = true; btn.textContent = '登录中…';
  try {
    const r = await api('POST', `/api/sites/${id}/relogin`);
    if (r.ok) toast(r.check === false && r.check_msg ? '已重新登录，但检测地址显示：' + r.check_msg : '重新登录成功', 5000);
    else toast(r.error, 8000);
  } catch (e) { toast(e.message, 6000); }
  render();
}
async function siteOpen(id, btn, force = false) {
  const numId = Number(id);
  const el = btn || document.querySelector(`button[onclick="siteOpen(${numId}, this)"]`);
  const origText = el ? el.textContent : '打开浏览器登录';
  if (el) {
    el.disabled = true;
    el.setAttribute('aria-busy', 'true');
    el.textContent = force ? '打开中…' : '检测登录中…';
  }
  try {
    const r = await api('POST', `/api/sites/${numId}/open`, { force: !!force });
    if (r.already_valid) {
      await render();
      openModal(`
        <h2>登录状态正常</h2>
        <p>${esc(r.message || '当前登录及自动重登配置已验证通过，工具调用时不会报登录失效，无需重新登录。')}</p>
        <p class="muted small">如果你需要切换账号或修改保存的登录密码，可以强制重新打开浏览器录入。</p>
        <div class="row" style="margin-top:18px;justify-content:flex-end">
          <button type="button" onclick="closeModal(); siteOpen(${numId}, null, true)">仍要打开浏览器（切换账号）</button>
          <button type="button" class="pri" onclick="closeModal()">知道了</button>
        </div>`);
      $('#modal-body button.pri')?.focus();
    } else {
      toast(r.message || '已打开登录窗口，完成登录后会自动保存登录配置并关闭窗口', 5500);
      await render();
    }
  } catch (e) {
    toast(e.message, 5000);
  } finally {
    if (el && el.isConnected) {
      el.disabled = false;
      el.removeAttribute('aria-busy');
      el.textContent = origText;
    }
  }
}
async function siteCancel(id, btn) {
  if (btn) btn.disabled = true;
  try { await api('POST', `/api/sites/${id}/cancel`, {}); toast('已取消登录等待'); }
  catch (e) { toast(e.message, 5000); }
  render();
}
async function delSite(id) { if (!confirm('删除这个网站的登录配置？（不影响工具，下次调用时会重新创建默认配置）')) return; await api('DELETE', '/api/sites/' + id); render(); }
let VAULT_NAMES = [];
async function editSite(id) {
  const s = id ? SITES.find(x => x.id === id) : { id: 0, origin: '', name: '', method: 'wecom_sso', entry_url: '', check_url: '', success_url: '', sso_hosts: '', keepalive_min: 0, detect: { statuses: [], url_patterns: [], body_patterns: [], no_defaults: false }, form: { mode: 'fill' } };
  const v = await api('GET', '/api/vault'); VAULT_NAMES = v.items;
  const f = s.form || {}, d = s.detect || {};
  const refOpts = (cur, kind) => `<option value="">（自动：按网站匹配）</option>` + VAULT_NAMES.map(it => { const r = (it.type === 'secret' ? 'secret.' : 'cfg.') + it.name; return `<option value="${esc(r)}" ${r === cur ? 'selected' : ''}>${esc(r)}${it.has_value ? '' : '（未填写）'}</option>`; }).join('');
  openModal(`
  <h2>${id ? '编辑登录配置' : '添加网站'}</h2>
  <div class="form-grid">
    <label>网站地址 *</label><div><input id="s-origin" class="mono" value="${esc(s.origin)}" placeholder="https://app.example.com"><div class="muted small">请填写 http:// 或 https://。WebSocket 地址请改成对应的网页源（wss → https，ws → http）。</div></div>
    <label>名称</label><input id="s-name" value="${esc(s.name)}" placeholder="禅道">
    <label>登录方式</label><select id="s-method" onchange="siteMethodUI()">${Object.entries(METHOD_NAMES).map(([k, n]) => `<option value="${k}" ${k === s.method ? 'selected' : ''}>${n}</option>`).join('')}</select>
    <label>登录入口</label><input id="s-entry" class="mono" value="${esc(s.entry_url)}" placeholder="留空 = 网站首页（会自动跳到登录页）">
    <label>单点登录地址</label><input id="s-sso" class="mono" value="${esc(s.sso_hosts)}" placeholder="可选，如 sso.company.com（企业微信地址已内置）">
    <label>登录成功地址</label><input id="s-success" class="mono" value="${esc(s.success_url)}" placeholder="可选，正则；浏览器到达匹配的地址即算登录成功">
    <label>检测地址</label><input id="s-check" class="mono" value="${esc(s.check_url)}" placeholder="可选，GET 一个需要登录的地址来判断状态">
  </div>
  <div id="s-form-box" class="form-grid" style="margin-top:10px">
    <label>账号</label><select id="s-user">${refOpts(f.username_ref)}</select>
    <label>密码</label><select id="s-pass">${refOpts(f.password_ref)}</select>
    <label>方式</label><select id="s-mode"><option value="replay" ${f.mode === 'replay' ? 'selected' : ''} ${f.request ? '' : 'disabled'}>重放录制的登录请求${f.request ? '（' + esc(f.request.method + ' ' + shortURL(f.request.url)) + '）' : '（需先在录制里「保存为登录配置」）'}</option><option value="fill" ${f.mode !== 'replay' ? 'selected' : ''}>在浏览器里自动填写登录表单</option></select>
    <label>登录页</label><input id="s-loginurl" class="mono" value="${esc(f.login_url || '')}" placeholder="可选，登录表单所在页面（也用于获取 CSRF）">
    <label>CSRF 字段</label><input id="s-csrf" class="mono" value="${esc(f.csrf_field || '')}" placeholder="可选，自动识别">
    <label>表单选择器</label><div class="row"><input id="s-usel" class="mono" style="width:150px" value="${esc(f.user_selector || '')}" placeholder="账号框（自动）"><input id="s-psel" class="mono" style="width:150px" value="${esc(f.pass_selector || '')}" placeholder="密码框（自动）"><input id="s-ssel" class="mono" style="width:150px" value="${esc(f.submit_selector || '')}" placeholder="登录按钮（自动）"></div>
  </div>
  <details style="margin-top:10px"><summary>未登录识别规则 / 保活</summary>
  <div class="form-grid" style="margin-top:8px">
    <label>状态码</label><input id="s-statuses" class="mono" value="${esc((d.statuses || []).join(','))}" placeholder="默认 401,403">
    <label>登录页地址</label><input id="s-urlpat" class="mono" value="${esc((d.url_patterns || []).join('\n'))}" placeholder="正则，多个用 ; 分隔；默认识别 login / sso / passport 等">
    <label>响应内容</label><input id="s-bodypat" class="mono" value="${esc((d.body_patterns || []).join('\n'))}" placeholder="正则，多个用 ; 分隔，如 &quot;result&quot;:&quot;fail&quot;.*登录">
    <label>内置规则</label><label class="chk"><input type="checkbox" id="s-nodef" ${d.no_defaults ? 'checked' : ''}> 关闭内置规则（登录页 HTML、“请先登录”提示等）</label>
    <label>定时保活</label><div class="row"><input id="s-keep" type="number" min="0" style="width:90px" value="${s.keepalive_min || 0}"> <span class="muted small">分钟检查一次，失效就后台重新登录（0 = 关闭）</span></div>
  </div></details>
  <div class="row" style="margin-top:18px;justify-content:flex-end"><button onclick="closeModal()">取消</button><button class="pri big" onclick="saveSite(${id})">保存</button></div>`);
  siteMethodUI();
}
function siteMethodUI() { const b = $('#s-form-box'); if (b) b.style.display = $('#s-method').value === 'form' ? '' : 'none'; }
async function saveSite(id) {
  const old = id ? SITES.find(x => x.id === id) : null;
  const split = v => v.split(/[;\n]/).map(x => x.trim()).filter(Boolean);
  const s = {
    origin: $('#s-origin').value.trim(), name: $('#s-name').value.trim(), method: $('#s-method').value,
    entry_url: $('#s-entry').value.trim(), sso_hosts: $('#s-sso').value.trim(), success_url: $('#s-success').value.trim(), check_url: $('#s-check').value.trim(),
    keepalive_min: +$('#s-keep').value || 0,
    detect: { statuses: $('#s-statuses').value.split(/[,，\s]+/).filter(Boolean).map(Number).filter(n => n > 0), url_patterns: split($('#s-urlpat').value), body_patterns: split($('#s-bodypat').value), no_defaults: $('#s-nodef').checked },
    form: { mode: $('#s-mode').value, username_ref: $('#s-user').value, password_ref: $('#s-pass').value, login_url: $('#s-loginurl').value.trim(), csrf_field: $('#s-csrf').value.trim(),
      user_selector: $('#s-usel').value.trim(), pass_selector: $('#s-psel').value.trim(), submit_selector: $('#s-ssel').value.trim(), request: old && old.form ? old.form.request : null },
  };
  const mapOrigin = v => {
    if (!v) return v;
    try {
      const u = new URL(v.includes('://') ? v : ('https://' + v));
      if (u.protocol === 'wss:') u.protocol = 'https:';
      else if (u.protocol === 'ws:') u.protocol = 'http:';
      if (u.protocol === 'http:' || u.protocol === 'https:') return u.origin;
    } catch {}
    return v;
  };
  const httpURL = (v, field) => {
    if (!v) return '';
    try {
      const u = new URL(v);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return field + '必须是 http:// 或 https:// 地址' + (u.protocol === 'ws:' || u.protocol === 'wss:' ? '，不能使用 ' + u.protocol + '//' : '');
    } catch { return field + '格式不正确，请填写 http:// 或 https:// 地址'; }
    return '';
  };
  s.origin = mapOrigin(s.origin);
  const bad = httpURL(s.origin, '网站地址') || httpURL(s.entry_url, '登录入口') || httpURL(s.check_url, '检测地址') || httpURL(s.form.login_url, '登录页');
  if (bad) { toast('保存失败：' + bad, 5000); return; }
  try { id ? await api('PUT', '/api/sites/' + id, s) : await api('POST', '/api/sites', s); closeModal(); toast('已保存登录配置'); render(); }
  catch (e) { toast('保存失败：' + e.message, 5000); }
}

// ---------- 配置管理 ----------
let VAULT = { items: [] };
async function pageVault(app) {
  VAULT = await api('GET', '/api/vault');
  app.innerHTML = `
  <div class="card"><h2>配置管理</h2>
    <p class="muted small">保存网站账号、密码、API Key 等配置。<b>密码类</b>的值加密保存在本机（密钥在数据目录的 <code>secret.key</code>），页面上默认隐藏；
    工具模板里用 <code>{{secret.名称}}</code> 或 <code>{{cfg.名称}}</code> 引用，调用时在本机替换——<b>AI 看不到这些值</b>：工具列表和导出文件里只有名称；<b>密码类</b>的值即使被网站原样返回，也会在调用结果、错误信息和日志里被替换成 ******。（普通类适合用户名等不敏感的值，网站返回内容里本来就有的不会被遮盖。）
    「账号密码」登录方式的网站会自动使用绑定到该网站的账号密码。</p>
    ${VAULT.items.length === 0 ? '<div class="empty">还没有配置。可以手动添加，也可以在录制里对登录请求点「保存为登录配置」。</div>' : `
    <table><thead><tr><th>名称</th><th>值</th><th>所属网站</th><th>说明 / 使用位置</th><th></th></tr></thead><tbody>
    ${VAULT.items.map(it => `<tr>
      <td><b class="mono">${esc(it.name)}</b><div class="muted small">${it.type === 'secret' ? '🔒 密码类' : '普通'} · 引用 <code>{{${it.type === 'secret' ? 'secret' : 'cfg'}.${esc(it.name)}}}</code></div></td>
      <td class="mono" id="v-val-${it.id}">${it.has_value ? (it.type === 'secret' ? esc(it.masked || '******') : esc(it.value)) : '<span class="st-bad">未填写</span>'}
        ${it.type === 'secret' && it.has_value && VAULT.can_reveal ? ` <a href="javascript:revealVault(${it.id})" class="small">显示</a>` : ''}</td>
      <td class="small mono">${esc(it.site || '-')}</td>
      <td class="small">${esc(it.note || '')}<div class="muted small">${it.used_by.length ? '用于：' + it.used_by.map(esc).join('、') : ''}</div></td>
      <td style="text-align:right;white-space:nowrap"><button onclick="editVault(${it.id})">编辑</button> <button class="danger" onclick="delVault(${it.id})">删除</button></td></tr>`).join('')}
    </tbody></table>`}
    <div class="row" style="margin-top:12px"><button onclick="editVault(0)">＋ 添加配置</button></div>
  </div>`;
}
async function revealVault(id) {
  try { const r = await api('POST', `/api/vault/${id}/reveal`); const el = $('#v-val-' + id); el.textContent = r.value; setTimeout(() => render(), 15000); }
  catch (e) { toast(e.message, 5000); }
}
async function editVault(id) {
  const it = id ? VAULT.items.find(x => x.id === id) : { id: 0, name: '', type: 'secret', value: '', site: '', note: '', has_value: false };
  const sites = await api('GET', '/api/sites');
  openModal(`
  <h2>${id ? '编辑配置' : '添加配置'}</h2>
  <div class="form-grid">
    <label>名称 *</label><input id="v-name" class="mono" value="${esc(it.name)}" placeholder="zentao_password（英文、数字、下划线）">
    <label>类型</label><select id="v-type"><option value="secret" ${it.type === 'secret' ? 'selected' : ''}>🔒 密码类（加密、隐藏）</option><option value="plain" ${it.type === 'plain' ? 'selected' : ''}>普通（如用户名）</option></select>
    <label>值</label><input id="v-value" type="${it.type === 'secret' ? 'password' : 'text'}" autocomplete="new-password" value="${it.type === 'secret' ? '' : esc(it.value)}" placeholder="${it.type === 'secret' && it.has_value ? '留空 = 不修改' : ''}">
    <label>所属网站</label><input id="v-site" class="mono" list="v-sites" value="${esc(it.site)}" placeholder="可选，如 https://zentao.example.com；账号密码登录会自动使用">
    <datalist id="v-sites">${sites.map(s => `<option value="${esc(s.origin)}">`).join('')}</datalist>
    <label>说明</label><input id="v-note" value="${esc(it.note)}" placeholder="可选">
  </div>
  <div class="row" style="margin-top:18px;justify-content:flex-end"><button onclick="closeModal()">取消</button><button class="pri big" onclick="saveVault(${id})">保存</button></div>`);
  $('#v-type').onchange = () => { $('#v-value').type = $('#v-type').value === 'secret' ? 'password' : 'text'; };
}
async function saveVault(id) {
  const it = id ? VAULT.items.find(x => x.id === id) : null;
  const value = $('#v-value').value;
  const body = { name: $('#v-name').value.trim(), type: $('#v-type').value, site: $('#v-site').value.trim(), note: $('#v-note').value.trim(), value,
    keep_value: !!(it && it.type === 'secret' && $('#v-type').value === 'secret' && value === '') };
  try { id ? await api('PUT', '/api/vault/' + id, body) : await api('POST', '/api/vault', body); closeModal(); toast('已保存'); render(); }
  catch (e) { toast('保存失败：' + e.message, 5000); }
}
async function delVault(id) { if (!confirm('删除这个配置？引用它的工具和登录配置将无法使用。')) return; try { await api('DELETE', '/api/vault/' + id); render(); } catch (e) { toast(e.message, 5000); } }

// ---------- 中间件 ----------
let MW = null;
const MW_PORTS = { mysql: 3306, redis: 6379, rocketmq: 9876, kafka: 9092, rabbitmq: 5672 };
const DEFAULT_WS_TERM_MSGS = ['{"type":"TERMINAL_COMMAND","text":"{{command}}"}', '{"type":"TERMINAL_COMMAND","text":"\\r"}'];
const DEFAULT_WS_SQL_MSG = 'execute {"data":{"sql":"{{sql}}","spaceCode":"{{ds.space_code}}","dsId":"{{ds.ds_id}}","envId":"{{ds.env_id}}","envType":"{{ds.env_type}}","dbType":"{{ds.db_type}}"},"token":"{{header.sso-epctoken}}"}';
function mwIsSQL(m) {
  return !!(m && m.type === 'websocket' && m.config && m.config.ws_mode === 'sql_console');
}
function mwPermDefsFor(m) {
  if (mwIsSQL(m)) return (MW && MW.perm_defs_sql_console) || [];
  const typ = m && m.type;
  return (MW && MW.perm_defs && typ && MW.perm_defs[typ]) || [];
}
function currentWSMode() {
  const el = document.querySelector('#modal-body input[name="mw-wsmode"]:checked');
  return el ? el.value : 'terminal';
}
function asNumOrStr(v) { return v === undefined || v === null ? '' : String(v); }
function maybeJSONNum(v) {
  const s = String(v == null ? '' : v).trim();
  if (s !== '' && /^-?\d+$/.test(s)) return Number(s);
  return s;
}
function permText(m) {
  const defs = mwPermDefsFor(m);
  const on = defs.filter(d => m.config.perms && m.config.perms[d.key]).map(d => d.label);
  return on.length ? '权限：' + on.join('、') : '权限：无';
}
function mwAddr(m) {
  const c = m.config;
  if (m.type === 'websocket') {
    const u = (c.url || '').split('?')[0];
    return u.length > 72 ? u.slice(0, 72) + '…' : u;
  }
  if (m.type === 'mq' && c.mq_kind !== 'rabbitmq') return c.addrs;
  if (m.type === 'redis' && c.redis_mode && c.redis_mode !== 'standalone') return c.addrs;
  return `${c.host}:${c.port}`;
}
async function pageMiddleware(app) {
  MW = await api('GET', '/api/middleware');
  const audit = await api('GET', '/api/middleware/audit?limit=100');
  app.innerHTML = `
  <div class="card"><h2>中间件管理</h2>
    <p class="muted small">在这里登记数据库（MySQL / OceanBase）、Redis、消息队列（RocketMQ / Kafka / RabbitMQ）、WebSocket（终端或 SQL 控制台），再把它们加入「流程包」。流程包开启后，AI 会看到 <code>db_query</code>、<code>redis_command</code>、<code>mq_send</code>、<code>pod_read_log</code>、<code>ws_sql_query</code> 等通用工具，
    但<b>只能做你开启了权限的操作</b>，没开启的会收到「无权限」错误。<b>密码加密保存在「配置管理」里，AI 看不到</b>（工具列表、调用结果、错误、日志、导出文件里都不会出现）；连接地址也不会出现在工具说明里。</p>
    ${MW.items.length === 0 ? '<div class="empty">还没有中间件。点下面的按钮添加第一个。</div>' : `
    <table><thead><tr><th>名称</th><th>类型 / 地址</th><th>权限</th><th>范围 / 限制</th><th>流程包</th><th></th></tr></thead><tbody>
    ${MW.items.map(m => `<tr>
      <td><b>${esc(m.name)}</b><div class="muted small">${esc(m.config.description || '')}</div></td>
      <td class="mw-addr"><span class="mw-type t-${esc(m.type)}">${esc(m.kind_label)}</span><div class="mono small">${esc(mwAddr(m))}${m.config.database ? ' / ' + esc(m.config.database) : ''}</div>
        <div class="small">${m.type === 'websocket' ? (mwIsSQL(m) ? '<span class="muted">登录中心 Cookie + 已收获的请求头令牌</span>' : '<span class="muted">使用登录中心的 Cookie</span>') : (m.config.password_ref ? (m.password_set ? '🔒 密码已保存' : '<span class="st-bad">密码待填写</span>') : '<span class="muted">无密码</span>')}</div></td>
      <td>${mwPermDefsFor(m).map(d => `<span class="perm ${m.config.perms[d.key] ? 'on' : ''}">${esc(d.label)}</span>`).join('')}${mwIsSQL(m) ? ' <span class="perm on">最多 ' + esc(m.config.max_rows || 200) + ' 行</span> <span class="perm on">必须索引</span>' + (m.config.approval === 'off' ? ' <span class="perm">审批已关闭</span>' : ' <span class="perm on">每次审批</span>') : ''}</td>
      <td class="small">${esc(mwScope(m))}</td>
      <td class="small mw-packs">${m.packs.length ? m.packs.map(esc).join('、') : '<span class="muted">未加入</span>'}</td>
      <td style="text-align:right;white-space:nowrap"><button onclick="testMWSaved(${m.id},this)">测试连接</button> <button onclick="editMW(${m.id})">编辑</button> <button class="danger" onclick="delMW(${m.id})">删除</button></td></tr>`).join('')}
    </tbody></table>`}
    <div class="row" style="margin-top:12px"><button class="pri" onclick="editMW(0,'mysql')">＋ 数据库</button><button class="pri" onclick="editMW(0,'redis')">＋ Redis</button><button class="pri" onclick="editMW(0,'mq')">＋ 消息队列</button><button class="pri" onclick="editMW(0,'websocket')">＋ WebSocket</button></div>
  </div>
  <div class="card"><div class="row"><h3 class="grow" style="margin:0">操作审计</h3><span class="muted small">最近 100 条 · AI 对中间件的每次调用（包括被拒绝的）</span><button onclick="render()">刷新</button><button class="danger" onclick="clearAudit()">清空</button></div>
    ${audit.length === 0 ? '<div class="empty">还没有调用记录</div>' : `<table class="audit"><thead><tr><th>时间</th><th>客户端</th><th>中间件</th><th>工具 / 操作</th><th>权限</th><th>结果</th></tr></thead><tbody>
    ${audit.map(e => `<tr><td class="small mono" style="white-space:nowrap">${esc(e.ts.replace('T', ' ').slice(0, 19))}</td><td class="small">${esc(e.client)}</td><td>${esc(e.mw)}</td>
      <td><span class="mono small">${esc(e.tool)}</span><div class="mono small muted act">${esc(e.action)}</div></td><td class="small">${esc(e.perm)}</td>
      <td class="small">${e.allowed && !e.result.startsWith('执行失败') ? '<span class="st-ok">✔ ' + esc(e.result) + '</span>' : '<span class="st-bad">' + (e.allowed ? '' : '✘ ') + esc(e.result) + '</span>'}${e.ms ? ` <span class="muted">${e.ms}ms</span>` : ''}</td></tr>`).join('')}
    </tbody></table>`}
  </div>`;
}
function mwScope(m) {
  const c = m.config, p = [];
  if (m.type === 'mysql') {
    if (c.allowed_dbs && c.allowed_dbs.length) p.push('库：' + c.allowed_dbs.join('、'));
    if (c.allowed_tables && c.allowed_tables.length) p.push('表：' + c.allowed_tables.join('、'));
    p.push('最多 ' + c.max_rows + ' 行'); if (c.require_where !== false) p.push('改/删须带 WHERE');
  } else if (m.type === 'redis') {
    if (c.key_prefixes && c.key_prefixes.length) p.push('key 前缀：' + c.key_prefixes.join('、'));
  } else if (m.type === 'websocket') {
    if (mwIsSQL(m)) {
      const aliases = (c.datasources || []).filter(d => d && d.alias && d.enabled !== false).map(d => d.alias);
      if (aliases.length) p.push('数据源：' + aliases.join('、'));
      p.push('最多 ' + (c.max_rows || 200) + ' 行');
      p.push('必须索引');
    } else if (c.command_allow && c.command_allow.length) p.push('命令：' + c.command_allow.join('、'));
    else p.push('执行命令不限');
  } else if (c.topics && c.topics.length) p.push('Topic：' + c.topics.join('、'));
  p.push(c.timeout_sec + ' 秒超时');
  return p.join('；');
}
function mwDefault(type) {
  const perms = {}; (MW.perm_defs[type] || []).forEach(d => perms[d.key] = d.default);
  const ws = type === 'websocket';
  return { id: 0, name: '', type, password_set: false, config: { host: ws ? '' : '127.0.0.1', port: type === 'mysql' ? 3306 : type === 'redis' ? 6379 : ws ? 0 : 9876, user: '', password_ref: '', database: '',
    addrs: '', mq_kind: 'rocketmq', redis_mode: 'standalone', master_name: '', tls: false, tls_skip_verify: false, sasl: '', broker_addr: '', perms,
    allowed_dbs: [], allowed_tables: [], key_prefixes: [], topics: [], max_rows: 200, max_result_kb: 256, timeout_sec: ws ? 30 : 15, require_where: true, description: '',
    url: '', ws_mode: 'terminal', ws_messages: ['{"type":"TERMINAL_COMMAND","text":"{{command}}"}', '{"type":"TERMINAL_COMMAND","text":"\\r"}'],
    command_allow: ['tail', 'head', 'ls', 'cat', 'grep', 'pwd'], datasources: [], sql_defaults: {} } };
}
const lines = a => (a || []).join('\n');
function editMW(id, type) {
  openMWEditor(id ? MW.items.find(x => x.id === id) : mwDefault(type));
}
function openMWEditor(m) {
  const id = m.id || 0;
  const c = m.config, t = m.type;
  const sql = t === 'websocket' && c.ws_mode === 'sql_console';
  const defs = sql ? (MW.perm_defs_sql_console || []) : (MW.perm_defs[t] || []);
  const kindName = t === 'mysql' ? '数据库' : t === 'redis' ? ' Redis' : t === 'websocket' ? (sql ? ' SQL 控制台' : ' WebSocket') : '消息队列';
  const sd = c.sql_defaults || {};
  openModal(`
  <h2>${id ? '编辑' : '添加'}${kindName}</h2>
  <input type="hidden" id="mw-type" value="${esc(t)}">
  <input type="hidden" id="mw-id" value="${id}">
  <div class="form-grid">
    <label>名称 *</label><input id="mw-name" value="${esc(m.name)}" placeholder="${t === 'websocket' ? '如：Phoenix终端 或 数据平台SQL（AI 用这个名字指定中间件）' : '如：订单库、缓存、订单MQ（AI 用这个名字指定中间件）'}">
    ${t === 'websocket' ? `
    ${m.fromRecording ? '<input type="hidden" id="mw-from-rec" value="1">' : ''}
    <label>连接类型</label><div class="row"><label class="chk"><input type="radio" name="mw-wsmode" value="terminal" ${sql ? '' : 'checked'} onchange="mwFormUI()"> 终端</label><label class="chk"><input type="radio" name="mw-wsmode" value="sql_console" ${sql ? 'checked' : ''} onchange="mwFormUI()"> SQL 控制台</label></div>
    <label>WebSocket 地址 *</label><textarea id="mw-url" class="mono" style="min-height:68px" placeholder="wss://example.com/ws/ssh?appCode={{app_code}}&podName={{pod_name}}&namespace={{namespace}}&serviceName={{service_name}}">${esc(c.url || '')}</textarea>
    <label>发送的文本帧</label><textarea id="mw-msgs" class="mono" style="min-height:68px" placeholder="${m.fromRecording ? '写一条模板，把命令或 SQL 的位置写成占位符' : '一行一条'}">${esc((c.ws_messages || []).join('\n'))}</textarea>
    ${m.fromRecording ? `<div class="full f-term"><label>录到的帧（只读，不会发送）</label><pre class="mono" style="max-height:160px;overflow:auto">${wsRender(m.recordedBody || '', '→')}</pre></div>
    <div class="full f-term"><div class="notice">保存的是终端式的文本帧模板。请另写一条模板，把命令的位置写成 <code>{{command}}</code>。上面录到的帧只作对照，不会写入模板，测试连接和以后的调用也都不会自动发出这些帧。查询参数如果每次不同，写成 <code>{{参数名}}</code>。登录用「登录中心」的 Cookie。二进制帧、子协议和按响应决定的初始化不在这个连接里重放。</div></div>` : `<div class="full f-term"><p class="muted small" style="margin:0">认证用这个地址对应网站在「登录中心」里的 Cookie，不在这里填密码。默认的两行帧是：先发命令，再发一个回车。</p></div>`}
    <div class="full f-sql"><p class="muted small" style="margin:0">在消息里用 <code>{{sql}}</code> 表示要执行的语句。spaceCode、dsId、envId、envType、dbType 写成 <code>{{ds.space_code}}</code>、<code>{{ds.ds_id}}</code> 等，保存时按所选数据源自动填入，不会成为 AI 参数。登录令牌用 <code>{{header.sso-epctoken}}</code>，不要写入字面值。测试连接只做握手，不会执行 SQL。</p></div>
    <label class="f-sql" for="mw-approval">审批模式</label><div class="f-sql"><select id="mw-approval" onchange="mwApprovalHint()"><option value="always" ${c.approval !== 'off' ? 'selected' : ''}>每次审批</option><option value="off" ${c.approval === 'off' ? 'selected' : ''}>关闭</option></select><p id="mw-approval-hint" class="notice" style="margin:8px 0 0"${c.approval === 'off' ? '' : ' hidden'}>关闭后 AI 可直接执行查询，只读/LIMIT/索引等守卫仍生效。</p></div>
    <div class="full f-sql"><h3 style="margin:10px 0 4px">默认环境参数</h3><p class="muted small" style="margin:0 0 8px">各数据源共用的 spaceCode、dbType。某一行需要不同值时，点该行「高级」覆盖。envId 和 envType 按行填写，三个值一起确定一个库。</p>
      <div class="row ds-defaults"><label>spaceCode <input id="mw-space" class="mono" value="${esc(sd.space_code || '')}"></label><label>dbType <input id="mw-dbtype" class="mono" value="${esc(sd.db_type || '')}"></label></div></div>
    ${dsTableHTML(c.datasources)}` : ''}
    ${t === 'mysql' ? `<label>类型</label><div class="muted small">MySQL / OceanBase（MySQL 模式）/ MariaDB / TiDB 等兼容 MySQL 协议的数据库</div>` : ''}
    ${t === 'mq' ? `<label>消息队列</label><select id="mw-mqkind" onchange="mwFormUI()">${Object.entries(MW.mq_kinds).map(([k, v]) => `<option value="${k}" ${c.mq_kind === k ? 'selected' : ''}>${v}</option>`).join('')}</select>` : ''}
    ${t === 'redis' ? `<label>部署方式</label><select id="mw-rmode" onchange="mwFormUI()"><option value="standalone" ${c.redis_mode !== 'cluster' && c.redis_mode !== 'sentinel' ? 'selected' : ''}>单机 / 主从</option><option value="cluster" ${c.redis_mode === 'cluster' ? 'selected' : ''}>Cluster 集群</option><option value="sentinel" ${c.redis_mode === 'sentinel' ? 'selected' : ''}>Sentinel 哨兵</option></select>` : ''}
    <label class="f-host">主机 / 端口</label><div class="row f-host"><input id="mw-host" class="grow mono" value="${esc(c.host)}" placeholder="127.0.0.1"><input id="mw-port" class="mono" style="width:100px" value="${esc(c.port || '')}"></div>
    <label class="f-addrs">地址列表</label><input id="mw-addrs" class="mono f-addrs" value="${esc(c.addrs)}" placeholder="host1:port,host2:port">
    <label class="f-master">Master 名称</label><input id="mw-master" class="mono f-master" value="${esc(c.master_name)}" placeholder="mymaster">
    <label class="f-user">用户名</label><input id="mw-user" class="mono f-user" value="${esc(c.user)}" autocomplete="off">
    <label class="f-pw">密码</label><div class="f-pw"><input id="mw-pw" type="password" autocomplete="new-password" style="width:100%" placeholder="${m.password_set ? '已保存（留空 = 不修改）' : c.password_ref ? '待填写' : '没有密码可留空'}">
      <div class="muted small">加密保存到「配置管理」${c.password_ref ? '（配置项 <code>' + esc(c.password_ref) + '</code>）' : ''}，AI 看不到。${m.password_set ? ' <label><input type="checkbox" id="mw-pwclear"> 清除密码</label>' : ''}</div></div>
    <label class="f-db">${t === 'mysql' ? '默认库' : t === 'redis' ? 'DB 编号' : 'Vhost'}</label><input id="mw-db" class="mono f-db" value="${esc(c.database)}" placeholder="${t === 'mysql' ? '可选，如 shop' : t === 'redis' ? '0' : '/'}">
    <label class="f-sasl">SASL</label><select id="mw-sasl" class="f-sasl">${['', 'PLAIN', 'SCRAM-SHA-256', 'SCRAM-SHA-512'].map(x => `<option value="${x}" ${c.sasl === x ? 'selected' : ''}>${x || '不认证'}</option>`).join('')}</select>
    <label class="f-broker">Broker 地址</label><input id="mw-broker" class="mono f-broker" value="${esc(c.broker_addr)}" placeholder="创建 Topic 用，默认 NameServer 主机:10911">
    <label class="f-tls">TLS</label><div class="row f-tls"><label><input type="checkbox" id="mw-tls" ${c.tls ? 'checked' : ''}> 使用 TLS 加密连接</label><label><input type="checkbox" id="mw-tlsskip" ${c.tls_skip_verify ? 'checked' : ''}> 不校验证书</label></div>
    <label>说明</label><input id="mw-desc" value="${esc(c.description)}" placeholder="可选，会展示给 AI，如：订单相关表都在这里">
    <div class="full"><h3 style="margin:10px 0 4px">权限 <span class="muted small" style="font-weight:400">没开启的操作，AI 调用时会收到「无权限」错误</span></h3>
      <div class="perms" id="mw-perms">${defs.map(d => permSwitchHTML(d, !!(c.perms && c.perms[d.key]))).join('')}</div></div>
    <div class="full"><h3 style="margin:10px 0 4px">范围与限制</h3></div>
    ${t === 'mysql' ? `
    <label>允许的库</label><textarea id="mw-dbs" class="mono" style="min-height:50px" placeholder="每行一个，留空 = 不限制（mysql 系统库始终禁止；设置后 information_schema 等系统库也禁止）">${esc(lines(c.allowed_dbs))}</textarea>
    <label>允许的表</label><textarea id="mw-tables" class="mono" style="min-height:50px" placeholder="每行一个：orders 或 shop.orders 或 shop.*，留空 = 不限制">${esc(lines(c.allowed_tables))}</textarea>
    <label>最多返回行数</label><input id="mw-maxrows" type="number" value="${c.max_rows}" style="width:120px">
    <label>WHERE 保护</label><label><input type="checkbox" id="mw-where" ${c.require_where !== false ? 'checked' : ''}> UPDATE / DELETE 必须带 WHERE 条件，禁止 TRUNCATE（推荐）</label>` : ''}
    ${t === 'redis' ? `<label>允许的 key 前缀</label><textarea id="mw-prefixes" class="mono" style="min-height:50px" placeholder="每行一个，如 order:，留空 = 不限制">${esc(lines(c.key_prefixes))}</textarea>` : ''}
    ${t === 'mq' ? `<label>允许的 Topic / 队列</label><textarea id="mw-topics" class="mono" style="min-height:50px" placeholder="每行一个，支持 order_* 这样的前缀通配，留空 = 不限制">${esc(lines(c.topics))}</textarea>` : ''}
    ${t === 'websocket' ? `<label class="f-term">允许的命令</label><textarea id="mw-allow" class="mono f-term" style="min-height:50px" placeholder="每行一个，如 tail。只约束 pod_exec，管道的每一段也要在这里。留空 = 开启「执行命令」后不限制">${esc(lines(c.command_allow))}</textarea>
    <label class="f-sql">最多返回行数</label><div class="row f-sql"><input id="mw-maxrows" type="number" min="1" max="200" value="${c.max_rows || 200}" style="width:120px"><span class="muted small">行，最多 200，必须写 LIMIT 且走索引</span></div>` : ''}
    <label>结果大小上限</label><div class="row"><input id="mw-maxkb" type="number" value="${c.max_result_kb}" style="width:120px"><span class="muted small">KB，超出会截断</span></div>
    <label>超时</label><div class="row"><input id="mw-timeout" type="number" value="${c.timeout_sec}" style="width:120px"><span class="muted small">秒</span></div>
  </div>
  <div id="mw-test-res" style="margin-top:12px"></div>
  <div class="row" style="margin-top:18px;justify-content:flex-end"><button onclick="testMWForm(${id},this)">测试连接</button><span class="grow"></span><button onclick="closeModal()">取消</button><button class="pri big" onclick="saveMW(${id})">保存</button></div>`);
  lastWSMode = null;
  mwFormUI();
}
function permSwitchHTML(d, on) {
  return `<label class="perm-sw"><label class="switch"><input type="checkbox" data-perm="${esc(d.key)}" ${on ? 'checked' : ''}><span></span></label><div><b>${esc(d.label)}</b><div class="muted small">${esc(d.hint)}</div></div></label>`;
}
function dsTableHTML(rows) {
  const list = (rows && rows.length) ? rows : [{ alias: '', ds_id: '', env_id: '', env_type: 'PROD', description: '' }];
  return `<div class="full f-sql"><div class="row" style="margin:10px 0 6px"><h3 style="margin:0">数据源</h3><span class="muted small grow">填写「名称」「数据源 ID」「envId」「envType」「说明（给 AI 看）」。名称和说明会列在工具描述里，供 AI 选择数据库。数据源 ID、envId、envType 三个值一起确定一个库，只保存在本机。envType 默认为 PROD。可在数据平台对该库录制一次查询，从 execute 消息里复制这三个值。</span><button type="button" class="sm" onclick="addDSRow()">添加</button></div>
    <table class="ds-table"><thead><tr><th>名称</th><th>数据源ID</th><th>envId</th><th>envType</th><th>说明（给AI看）</th><th></th></tr></thead>
    <tbody id="mw-ds-body">${list.map(dsRowHTML).join('')}</tbody></table></div>`;
}
function dsRowHTML(d) {
  d = d || {};
  const adv = !!(d.space_code || d.db_type);
  const envType = (d.env_type == null || d.env_type === '') ? 'PROD' : d.env_type;
  return `<tr class="ds-row${adv ? ' adv-on' : ''}">
    <td><input class="ds-alias" placeholder="如 orders" value="${esc(d.alias || '')}"></td>
    <td><input class="ds-id mono" placeholder="数据源 ID" value="${esc(asNumOrStr(d.ds_id))}"></td>
    <td><input class="ds-envid mono" placeholder="envId" value="${esc(asNumOrStr(d.env_id))}"></td>
    <td><input class="ds-envtype mono" placeholder="PROD" value="${esc(envType)}"></td>
    <td><input class="ds-desc" placeholder="例如：订单相关表" value="${esc(d.description || '')}"></td>
    <td class="ds-actions"><button type="button" class="sm" onclick="toggleDSAdv(this)">高级</button> <button type="button" class="danger sm" onclick="delDSRow(this)">删除</button>
      <div class="ds-adv"><div class="row" style="margin-top:6px">
        <input class="ds-space" placeholder="spaceCode 覆盖" value="${esc(d.space_code || '')}">
        <input class="ds-dbtype" placeholder="dbType 覆盖" value="${esc(d.db_type || '')}">
      </div></div></td></tr>`;
}
function addDSRow() {
  const tb = $('#mw-ds-body');
  if (!tb) return;
  tb.insertAdjacentHTML('beforeend', dsRowHTML({ env_type: 'PROD' }));
}
function delDSRow(btn) {
  const tr = btn.closest('tr');
  if (tr) tr.remove();
  const tb = $('#mw-ds-body');
  if (tb && !tb.children.length) addDSRow();
}
function toggleDSAdv(btn) {
  const tr = btn.closest('tr');
  if (tr) tr.classList.toggle('adv-on');
}
function collectDatasources() {
  return [...document.querySelectorAll('#mw-ds-body tr')].map(tr => {
    const d = {
      alias: ($('.ds-alias', tr).value || '').trim(),
      ds_id: maybeJSONNum($('.ds-id', tr).value),
      description: ($('.ds-desc', tr).value || '').trim(),
    };
    if (d.ds_id === '') delete d.ds_id;
    const ei = maybeJSONNum(($('.ds-envid', tr).value || ''));
    const et = ($('.ds-envtype', tr).value || '').trim() || 'PROD';
    if (ei !== '') d.env_id = ei;
    d.env_type = et;
    if (tr.classList.contains('adv-on')) {
      const sc = ($('.ds-space', tr).value || '').trim();
      const dt = ($('.ds-dbtype', tr).value || '').trim();
      if (sc) d.space_code = sc;
      if (dt) d.db_type = dt;
    }
    return d;
  }).filter(d => d.alias || d.ds_id || d.env_id || d.description);
}
function looksLikeTermMsgs(s) { return s.includes('{{command}}') && !s.includes('{{sql}}'); }
function looksLikeDefaultSQLMsgs(s) { return s.trim() === DEFAULT_WS_SQL_MSG; }
let lastWSMode = null;
function mwApprovalHint() {
  const hint = $('#mw-approval-hint');
  const sel = $('#mw-approval');
  if (!hint || !sel) return;
  hint.hidden = sel.value !== 'off';
}
function mwFormUI() {
  const t = $('#mw-type').value;
  const kind = $('#mw-mqkind') ? $('#mw-mqkind').value : '';
  const rmode = $('#mw-rmode') ? $('#mw-rmode').value : 'standalone';
  const ws = t === 'websocket';
  const useAddrs = !ws && ((t === 'mq' && kind !== 'rabbitmq') || (t === 'redis' && rmode !== 'standalone'));
  const show = (cls, on) => document.querySelectorAll('#modal-body .' + cls).forEach(el => el.style.display = on ? '' : 'none');
  show('f-host', !ws && !useAddrs); show('f-addrs', useAddrs); show('f-master', !ws && t === 'redis' && rmode === 'sentinel');
  show('f-db', !ws && (t !== 'mq' || kind === 'rabbitmq')); show('f-sasl', !ws && kind === 'kafka'); show('f-broker', !ws && kind === 'rocketmq');
  show('f-tls', !ws && kind !== 'rocketmq'); show('f-user', !ws); show('f-pw', !ws);
  const sql = ws && currentWSMode() === 'sql_console';
  show('f-term', ws && !sql); show('f-sql', sql);
  if (ws) {
    const ta = $('#mw-msgs');
    if (ta && lastWSMode && lastWSMode !== currentWSMode()) {
      const v = ta.value || '';
      if (sql && looksLikeTermMsgs(v)) ta.value = DEFAULT_WS_SQL_MSG;
      if (!sql && looksLikeDefaultSQLMsgs(v)) ta.value = DEFAULT_WS_TERM_MSGS.join('\n');
    }
    lastWSMode = currentWSMode();
    syncMWPerms(sql);
    mwApprovalHint();
    if (ta) ta.placeholder = sql ? '一行一条，{{sql}} 会换成要执行的语句' : '一行一条，{{command}} 会换成要执行的命令';
  } else {
    lastWSMode = null;
  }
  const ul = document.querySelector('#modal-body label.f-user'); if (ul) ul.textContent = kind === 'rocketmq' ? 'AccessKey' : '用户名';
  const pl = document.querySelector('#modal-body label.f-pw'); if (pl) pl.textContent = kind === 'rocketmq' ? 'SecretKey' : '密码';
  const ap = $('#mw-addrs'); if (ap) ap.placeholder = kind === 'rocketmq' ? 'NameServer，如 10.0.0.1:9876;10.0.0.2:9876 用逗号分隔' : kind === 'kafka' ? 'Broker，如 10.0.0.1:9092,10.0.0.2:9092' : '节点，如 10.0.0.1:7000,10.0.0.2:7000';
  const port = $('#mw-port'); if (port && t === 'mq' && kind === 'rabbitmq' && (!port.value || port.value === '9876')) port.value = 5672;
}
function syncMWPerms(sql) {
  const box = $('#mw-perms');
  if (!box) return;
  const t = $('#mw-type').value;
  const defs = sql ? (MW.perm_defs_sql_console || []) : (MW.perm_defs[t] || []);
  const prev = {};
  box.querySelectorAll('[data-perm]').forEach(el => { prev[el.dataset.perm] = el.checked; });
  const id = +($('#mw-id') && $('#mw-id').value || 0);
  const old = id ? (MW.items || []).find(x => x.id === id) : null;
  box.innerHTML = defs.map(d => {
    let on = d.default;
    if (Object.prototype.hasOwnProperty.call(prev, d.key)) on = prev[d.key];
    else if (old && old.config && old.config.perms && Object.prototype.hasOwnProperty.call(old.config.perms, d.key)) on = !!old.config.perms[d.key];
    return permSwitchHTML(d, on);
  }).join('');
}
function mwCollect(id) {
  const t = $('#mw-type').value;
  const list = sel => $(sel) ? $(sel).value.split(/[\n,，]/).map(x => x.trim()).filter(Boolean) : [];
  const perms = {}; document.querySelectorAll('#modal-body [data-perm]').forEach(el => perms[el.dataset.perm] = el.checked);
  const old = id ? MW.items.find(x => x.id === id) : null;
  const cfg = {
    host: $('#mw-host').value.trim(), port: +$('#mw-port').value || 0, user: $('#mw-user').value.trim(), password_ref: old ? old.config.password_ref : '',
    database: $('#mw-db').value.trim(), addrs: $('#mw-addrs').value.trim(), mq_kind: $('#mw-mqkind') ? $('#mw-mqkind').value : '',
    redis_mode: $('#mw-rmode') ? $('#mw-rmode').value : '', master_name: $('#mw-master').value.trim(), tls: $('#mw-tls').checked, tls_skip_verify: $('#mw-tlsskip').checked,
    sasl: $('#mw-sasl').value, broker_addr: $('#mw-broker').value.trim(), perms,
    allowed_dbs: list('#mw-dbs'), allowed_tables: list('#mw-tables'), key_prefixes: list('#mw-prefixes'), topics: list('#mw-topics'),
    max_rows: $('#mw-maxrows') ? +$('#mw-maxrows').value : 200, max_result_kb: +$('#mw-maxkb').value, timeout_sec: +$('#mw-timeout').value,
    require_where: $('#mw-where') ? $('#mw-where').checked : true, description: $('#mw-desc').value.trim(),
  };
  if (t === 'websocket') {
    cfg.url = $('#mw-url').value.trim();
    cfg.ws_messages = $('#mw-msgs').value.split('\n').map(s => s.trim()).filter(Boolean);
    cfg.ws_mode = currentWSMode();
    cfg.host = ''; cfg.port = 0;
    if (old && old.config) {
      if (old.config.ws_headers) cfg.ws_headers = old.config.ws_headers;
      if (old.config.sql_path) cfg.sql_path = old.config.sql_path;
      if (old.config.ds_field_paths) cfg.ds_field_paths = old.config.ds_field_paths;
      if (old.config.ws_auth) cfg.ws_auth = old.config.ws_auth;
      if (old.config.ws_collect) cfg.ws_collect = old.config.ws_collect;
    }
    if (cfg.ws_mode === 'sql_console') {
      const defaults = {
        space_code: ($('#mw-space') && $('#mw-space').value || '').trim(),
        db_type: ($('#mw-dbtype') && $('#mw-dbtype').value || '').trim(),
      };
      cfg.sql_defaults = defaults;
      cfg.datasources = collectDatasources();
      cfg.command_allow = [];
      cfg.approval = ($('#mw-approval') && $('#mw-approval').value) || 'always';
    } else {
      cfg.command_allow = list('#mw-allow');
      delete cfg.approval;
    }
  }
  const useAddrs = (t === 'mq' && cfg.mq_kind !== 'rabbitmq') || (t === 'redis' && cfg.redis_mode !== 'standalone');
  if (useAddrs && !cfg.addrs && cfg.host) cfg.addrs = cfg.host + ':' + (cfg.port || MW_PORTS[cfg.mq_kind] || 6379);
  return { id, name: $('#mw-name').value.trim(), type: t, config: cfg, password: $('#mw-pw').value, clear_password: !!($('#mw-pwclear') && $('#mw-pwclear').checked) };
}
function wsTemplateReady() {
  if (currentWSMode() === 'sql_console') return ($('#mw-msgs') && $('#mw-msgs').value || '').includes('{{sql}}');
  const flag = $('#mw-from-rec');
  if (!flag || flag.value !== '1') return true;
  return ($('#mw-msgs').value || '').includes('{{command}}');
}
function wsTemplateHint() {
  if (currentWSMode() === 'sql_console') return '请先在文本帧里写上 {{sql}}。测试连接只做握手，不会执行 SQL。';
  return '请先写一条包含 {{command}} 的文本帧。录到的历史帧不会代发。';
}
async function saveMW(id) {
  if (!wsTemplateReady()) { toast(wsTemplateHint()); return; }
  const body = mwCollect(id);
  try { id ? await api('PUT', '/api/middleware/' + id, body) : await api('POST', '/api/middleware', body); closeModal(); toast('已保存'); render(); }
  catch (e) { toast('保存失败：' + e.message, 5000); }
}
async function testMWForm(id, btn) {
  if (!wsTemplateReady()) { $('#mw-test-res').innerHTML = '<div class="notice">' + esc(wsTemplateHint()) + '</div>'; return; }
  const body = mwCollect(id); btn.disabled = true; $('#mw-test-res').innerHTML = '<span class="muted">正在连接…</span>';
  try { const r = await api('POST', '/api/middleware/test', body);
    $('#mw-test-res').innerHTML = r.ok ? `<div class="ok-notice">✔ ${esc(r.msg)}（${r.ms}ms）</div>` : `<div class="notice">✘ 连接失败：${esc(r.error)}</div>`; }
  catch (e) { $('#mw-test-res').innerHTML = `<div class="notice">✘ ${esc(e.message)}</div>`; }
  btn.disabled = false;
}
async function testMWSaved(id, btn) {
  btn.disabled = true; const old = btn.textContent; btn.textContent = '连接中…';
  try { const r = await api('POST', '/api/middleware/test', { id }); toast(r.ok ? '✔ ' + r.msg : '✘ 连接失败：' + r.error, 6000); }
  catch (e) { toast(e.message, 5000); }
  btn.disabled = false; btn.textContent = old;
}
async function delMW(id) {
  const m = MW.items.find(x => x.id === id);
  if (!confirm(`删除中间件「${m.name}」？它会从所有流程包里移除，自动保存的密码也会一起删除。`)) return;
  try { await api('DELETE', '/api/middleware/' + id); toast('已删除'); render(); } catch (e) { toast(e.message, 5000); }
}
async function clearAudit() { if (!confirm('清空操作审计记录？')) return; await api('DELETE', '/api/middleware/audit'); render(); }
