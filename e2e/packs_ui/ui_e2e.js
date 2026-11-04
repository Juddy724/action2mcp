// Headless Chrome e2e for the pack membership UI (0.4.1).
// usage: NODE_PATH=<dir with puppeteer-core> node ui_e2e.js http://localhost:PORT SCREEN_DIR
const puppeteer = require('puppeteer-core');
const BASE = process.argv[2] || 'http://localhost:17811';
const OUT = process.argv[3] || '.';
const PACK = '工时';
const assert = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } console.log('ok  ', m); };

// --- minimal MCP client with GET stream to watch list_changed
let sid = '', notes = [];
async function rpc(method, params, id = Math.floor(Math.random() * 1e9)) {
  const r = await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...(sid ? { 'mcp-session-id': sid } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }) });
  sid = r.headers.get('mcp-session-id') || sid;
  const txt = await r.text();
  const msgs = r.headers.get('content-type').startsWith('text/event-stream')
    ? txt.split('\n').filter(l => l.startsWith('data:')).map(l => JSON.parse(l.slice(5))) : [JSON.parse(txt)];
  for (const m of msgs) if (!('id' in m)) notes.push(m.method);
  return msgs.find(m => m.id === id);
}
const callTool = async (name, args) => (await rpc('tools/call', { name, arguments: args })).result.content[0].text;
const toolNames = async () => (await rpc('tools/list', {})).result.tools.map(t => t.name);
async function openStream() {
  const r = await fetch(BASE + '/mcp', { headers: { accept: 'text/event-stream', 'mcp-session-id': sid } });
  const rd = r.body.getReader(), dec = new TextDecoder(); let buf = '';
  (async () => { for (;;) { const { value, done } = await rd.read(); if (done) return; buf += dec.decode(value);
    let i; while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1);
      if (l.startsWith('data:')) { const m = JSON.parse(l.slice(5)); if (m.method) notes.push(m.method); } } } })();
}
async function shot(path) {
  await page.evaluate(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n); window.scrollTo(0, c.getBoundingClientRect().top + window.scrollY - 330); }, PACK);
  await sleep(150); await page.screenshot({ path });
}
let page;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitNote(label) {
  for (let i = 0; i < 30; i++) { const k = notes.indexOf('notifications/tools/list_changed'); if (k >= 0) { notes.splice(k, 1); return assert(true, label); } await sleep(100); }
  assert(false, label);
}

(async () => {
  await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'ui-e2e', version: '1' } });
  await fetch(BASE + '/mcp', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', 'mcp-session-id': sid }, body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) });
  await callTool('load_pack', { pack: PACK }); notes = [];
  await openStream(); await sleep(200);
  const before = await toolNames();
  assert(before.includes('log_hours') && !before.includes('submit_daily'), 'MCP before: loaded pack has only log_hours');

  const browser = await puppeteer.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox', '--disable-gpu'], defaultViewport: { width: 1280, height: 1000 } });
  page = await browser.newPage();
  page.on('pageerror', e => { console.error('pageerror', e.message); process.exit(1); });
  await page.goto(BASE + '/#/packs', { waitUntil: 'networkidle0' });
  await page.waitForSelector('[data-add="tools"]');
  const cardSel = async () => page.evaluateHandle(n => [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n), PACK);
  const chipsIn = async () => page.evaluate(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n);
    return [...c.querySelectorAll('.chip[data-tool]')].map(x => x.dataset.tool); }, PACK);
  assert(JSON.stringify(await chipsIn()) === '["log_hours"]', 'pack card shows only its own tool (log_hours), not all tools');
  const otherShown = await page.evaluate(() => [...document.querySelectorAll('.chip[data-tool]')].map(x => x.dataset.tool));
  assert(!otherShown.includes('submit_daily') && !otherShown.includes('list_tasks'), 'unassigned tools are not listed in any pack');
  await shot(OUT + '/packs-1-before.png');

  // open the picker on the 工时 pack
  const c = await cardSel();
  await (await c.$('[data-add="tools"]')).click();
  await page.waitForSelector('.pick-list');
  const offered = await page.$$eval('input.pick', xs => xs.map(x => x.closest('label').textContent));
  assert(offered.length === 5 && !offered.some(t => t.includes('log_hours')), 'modal lists the 5 tools not yet in the pack');
  await page.type('#pick-q', '日报');
  const visible = await page.$$eval('.pick-row', xs => xs.filter(x => x.style.display !== 'none').map(x => x.textContent));
  assert(visible.length === 1 && visible[0].includes('submit_daily'), 'search filters the list');
  await page.$eval('#pick-q', e => { e.value = ''; e.dispatchEvent(new Event('input')); });
  for (const name of ['submit_daily', 'list_tasks']) {
    const h = await page.evaluateHandle(n => [...document.querySelectorAll('.pick-row')].find(r => r.textContent.includes(n)).querySelector('input.pick'), name);
    await h.click();
  }
  assert((await page.$eval('#pick-count', e => e.textContent)).includes('2'), 'count shows 2 selected');
  await page.screenshot({ path: OUT + '/packs-2-modal.png' });
  await page.click('#pick-ok');
  await page.waitForFunction(() => !document.querySelector('.pick-list'));
  await page.waitForFunction(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n); return c && c.querySelectorAll('.chip[data-tool]').length === 3; }, {}, PACK);
  assert(JSON.stringify((await chipsIn()).sort()) === '["list_tasks","log_hours","submit_daily"]', 'after 确定 the 2 checked tools appear in the pack');
  await waitNote('list_changed sent after add');
  let names = await toolNames();
  assert(names.includes('submit_daily') && names.includes('list_tasks') && names.includes('log_hours'), 'MCP tools/list (loaded pack) has the added tools');
  let lp = JSON.parse(await callTool('list_packs', {}));
  const pk = (lp.packs || lp).find(p => p.name === PACK);
  assert(pk && JSON.stringify(pk).includes('submit_daily') && JSON.stringify(pk).includes('list_tasks'), 'list_packs reflects new membership');
  await shot(OUT + '/packs-3-after-add.png');

  // remove list_tasks with ×
  const x = await page.evaluateHandle(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n);
    return c.querySelector('.chip[data-tool="list_tasks"] .chip-x'); }, PACK);
  await x.click();
  await page.waitForFunction(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n); return c && c.querySelectorAll('.chip[data-tool]').length === 2; }, {}, PACK);
  assert(JSON.stringify((await chipsIn()).sort()) === '["log_hours","submit_daily"]', '× removed list_tasks from the pack');
  await waitNote('list_changed sent after remove');
  names = await toolNames();
  assert(!names.includes('list_tasks') && names.includes('submit_daily'), 'MCP tools/list no longer has list_tasks');
  const lt = await (await fetch(BASE + '/api/tools')).json();
  assert(lt.some(t => t.name === 'list_tasks'), 'tool itself was not deleted');
  const lpk = await callTool('load_pack', { pack: PACK });
  assert(lpk.includes('submit_daily') && !lpk.includes('list_tasks'), 'load_pack reflects membership');
  await shot(OUT + '/packs-4-after-remove.png');

  // middleware picker on the same pack
  await (await (await cardSel()).$('[data-add="middleware"]')).click();
  await page.waitForSelector('.pick-list');
  await page.click('input.pick'); await page.click('#pick-ok');
  await page.waitForFunction(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n); return c && c.querySelectorAll('.chip[data-mw]').length === 1; }, {}, PACK);
  assert(true, 'middleware added via picker');
  await waitNote('list_changed sent after middleware add');
  await shot(OUT + '/packs-5-middleware.png');
  const mx = await page.evaluateHandle(n => [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n).querySelector('.chip[data-mw] .chip-x'), PACK);
  await mx.click();
  await page.waitForFunction(n => { const c = [...document.querySelectorAll('.pack')].find(c => c.querySelector('b').textContent === n); return c && c.querySelectorAll('.chip[data-mw]').length === 0; }, {}, PACK);
  assert(true, 'middleware removed via ×');
  await waitNote('list_changed sent after middleware remove');

  // flat mode
  await fetch(BASE + '/api/settings', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mcp_mode: 'flat' }) });
  names = await toolNames();
  assert(names.includes('submit_daily') && !names.includes('list_tasks') && !names.includes('secret_tool'), 'flat-mode tools/list reflects membership (enabled packs only)');
  await fetch(BASE + '/api/settings', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ mcp_mode: 'tiered' }) });
  await browser.close();
  console.log('ALL PASS');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
