import { randomUUID } from 'node:crypto';
import { spawnTarget } from './session-view.js';

export const woltTypes = ['raccoon', 'beaver', 'otter'];

export function validateWoltName(value) {
  const name = (value || '').trim().toLowerCase();
  if (!name) return 'name is required';
  if (name.length > 20) return 'name must be 20 characters or less';
  if (!/^[a-z][a-z0-9-]*$/.test(name)) {
    return 'use lowercase letters, numbers, and hyphens; start with a letter';
  }
  return '';
}

// One request ID for the whole wait: a pending answer is resubmitted unchanged until the
// host owner approves it; the first session's name is top level or under `session`.
export async function createUntilStarted(create, action, { say, wait, newId = () => randomUUID().replaceAll('-', '') }) {
  const requestId = newId();
  for (;;) {
    const r = await create(action.name, action.woltType, action.workdir, action.executionPolicy, requestId);
    if (r?.status !== 'pending') return (r?.session || r)?.name;
    say(r.detail);
    await wait();
  }
}

export function createWoltAction(name, type, capabilities, launchCwd, level = '') {
  const error = validateWoltName(name);
  if (error) throw new Error(error);
  if (!woltTypes.includes(type)) throw new Error(`unsupported wolt type: ${type}`);
  const target = spawnTarget(capabilities, null, launchCwd, level);
  return {
    type: 'create',
    name: name.trim().toLowerCase(),
    woltType: type,
    workdir: target.workdir,
    executionPolicy: target.executionPolicy,
    isolation: capabilities?.isolation,
  };
}
