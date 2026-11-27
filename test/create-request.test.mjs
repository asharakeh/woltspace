import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

import { createUntilStarted } from '../tui/src/create-wolt.js';

const lodge = readFileSync(new URL('../public/static/lodge.js', import.meta.url), 'utf8');
const source = (name) => lodge.slice(lodge.indexOf(`function ${name}(`), lodge.indexOf('\n}\n', lodge.indexOf(`function ${name}(`)) + 2);

test('the lodge page keeps one request ID per exact form and reads both session shapes', () => {
  const page = {};
  runInNewContext(`let createRequest = null;\n${source('createRequestBody')}\n${source('createdSessionName')}
    page.body = createRequestBody; page.name = createdSessionName;`, { page });
  let n = 0;
  const id = () => `id-${(n += 1)}`;
  const form = { name: 'maple', type: 'beaver', harness: 'claude' };
  assert.equal(page.body(form, id).request_id, 'id-1');
  assert.equal(page.body({ ...form }, id).request_id, 'id-1');  // "check again" is the same request
  assert.equal(page.body({ ...form, type: 'otter' }, id).request_id, 'id-2');  // other terms, other request
  assert.equal(page.name({ name: 'maple-1' }), 'maple-1');  // ordinary lodge
  assert.equal(page.name({ status: 'launched', session: { name: 'maple-2' } }), 'maple-2');  // isolated lodge
});

test('the tui resubmits the same request while it waits for the owner', async () => {
  const sent = [];
  const replies = [{ status: 'pending', detail: 'waiting' }, { status: 'pending', detail: 'waiting' },
    { status: 'launched', session: { name: 'maple-1' } }];
  const create = async (...args) => { sent.push(args); return replies.shift(); };
  const said = [];
  const action = { name: 'maple', woltType: 'beaver', workdir: null, executionPolicy: 'bypass' };
  let ids = 0;
  const name = await createUntilStarted(create, action, { say: (l) => said.push(l), wait: async () => {}, newId: () => `r${(ids += 1)}` });
  assert.equal(name, 'maple-1');
  assert.deepEqual(sent.map((a) => a[4]), ['r1', 'r1', 'r1']);
  assert.deepEqual(said, ['waiting', 'waiting']);
  assert.equal(await createUntilStarted(async () => ({ name: 'plain' }), action, { say() {}, wait() {}, newId: () => 'r2' }), 'plain');
});
