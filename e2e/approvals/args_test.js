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
});
