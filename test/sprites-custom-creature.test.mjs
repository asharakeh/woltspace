import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';

// The lodge pages' shared helpers, from the real sprites.js.
const source = readFileSync(new URL('../public/static/sprites.js', import.meta.url), 'utf8');
const context = {};
runInNewContext(`${source}\nthis.h = { woltEmoji, woltBaseType, woltSpriteAvatar, RODENT_TYPES };`, context);
const { woltEmoji, woltBaseType, woltSpriteAvatar, RODENT_TYPES } = context.h;

test('a built-in wolt keeps its emoji, whatever the lodge sends', () => {
  assert.equal(woltEmoji({ type: 'raccoon', emoji: '⭐' }), '🦝');
  assert.equal(woltEmoji({ type: 'beaver' }), '🦫');
  assert.equal(woltEmoji(undefined), '🦫');
});

test('a custom creature shows its own emoji and behaves like its size', () => {
  const astre = { type: 'star', emoji: '⭐', base_type: 'raccoon' };
  assert.equal(woltEmoji(astre), '⭐');
  assert.equal(woltSpriteAvatar(astre.type, 20), null); // no pixel art: the emoji stands in
  assert.ok(RODENT_TYPES.has(woltBaseType(astre)));
  assert.equal(woltBaseType({ type: 'otter' }), 'otter');
});
