'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

test('approval edits submit whole changed parameters and leave originals on the server', () => {
  const element = { addEventListener() {}, setAttribute() {} };
  const context = {
    document: { title: 'test', querySelector: () => element, addEventListener() {} },
    window: { addEventListener() {} }, localStorage: { getItem: () => null },
    setInterval() {}, fetch: () => new Promise(() => {}),
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../web/app.js'), 'utf8'), context);
  const original = '{"note":"old","id":" 123 "}';
  const edited = '{"note":"new","id":" 123 "}';
  const session = {
    item: { args_display: { value: original, label: '******', count: '1' } },
    params: [{ name: 'value' }, { name: 'label', secret: true }, { name: 'count' }, { name: 'optional' }],
    initial: [original, '******（未改动）', '1', ''],
  };
  session.fields = session.initial.map(value => ({ value }));
  const diff = () => JSON.parse(JSON.stringify(context.collectApprovalArgs(session)));
  assert.deepEqual(diff(), {});
  session.fields[2].value = '2';
  assert.deepEqual(diff(), { count: '2' });
  session.fields[1].value = 'replacement';
  assert.deepEqual(diff(), { label: 'replacement', count: '2' });
  session.fields[0].value = edited;
  assert.deepEqual(diff(), { value: edited, label: 'replacement', count: '2' });
  session.fields[0].value = original;
  session.fields[2].value = '1';
  session.fields[1].value = session.initial[1];
  assert.deepEqual(diff(), {});

  const historyHTML = context.renderApprovalHistoryHTML([
    { id: 1, ts: '2026-11-18 17:00:00', tool: 'pending_tool', title: '待处理', client: 'agent', status: 'pending', explanation: '不应出现在历史表' },
    { id: 2, ts: '2026-11-18 16:59:00', decided_at: '2026-11-18 16:59:10', tool: 'done_tool', title: '已完成', client: 'agent', status: 'approved', explanation: '删除测试订单，影响：订单状态变为已删除', args_display: { id: '42' }, result: 'HTTP 200\nok' },
  ]);
  assert.equal(historyHTML.includes('pending_tool'), false);
  assert.equal(historyHTML.includes('done_tool'), true);
  assert.equal(historyHTML.includes('删除测试订单，影响：订单状态变为已删除'), true);
});
