import { it } from 'node:test';
import assert from 'node:assert/strict';
import { Transport } from '../dist/transport.js';
async function exercise(options = {}, status = 200) {
  const originalSet = globalThis.setTimeout;
  const originalClear = globalThis.clearTimeout;
  const pending = new Map();
  let next = 0;
  globalThis.setTimeout = (callback) => { const id = ++next; pending.set(id, callback); return id; };
  globalThis.clearTimeout = id => pending.delete(id);
  try {
    const healthy = new Transport({ fetch: async () => new Response('{"ok":true}') });
    assert.deepEqual(await healthy.get('/healthy'), { ok: true });
    assert.equal(pending.size, 0, 'completed control releases timer');
    let entered, release;
    const bodyEntered = new Promise(resolve => { entered = resolve; });
    const fetch = async (_url, { signal }) => ({
      ok: status < 400, status,
      text() {
        return new Promise((resolve, reject) => {
          const abort = () => reject(new DOMException('body aborted', 'AbortError'));
          signal.addEventListener('abort', abort, { once: true });
          release = () => { signal.removeEventListener('abort', abort); resolve('{"ok":true}'); };
          entered(signal);
        });
      },
    });
    const transport = new Transport({ fetch, timeoutMs: 37 });
    const done = transport.get('/gated', options).then(value => ({ value }), error => ({ error }));
    const signal = await bodyEntered;
    const active = pending.size;
    for (const callback of [...pending.values()]) callback();
    const aborted = signal.aborted;
    release();
    const outcome = await done;
    assert.equal(pending.size, 0, 'all completion paths release timer');
    return { active, aborted, outcome };
  } finally {
    globalThis.setTimeout = originalSet;
    globalThis.clearTimeout = originalClear;
  }
}

for (const [name, options, status] of [
  ['JSON', {}, 200],
  ['raw export', { raw: true }, 200],
  ['HTTP error', {}, 503],
]) {
  it(`keeps the request timeout active through the gated ${name} body`, async () => {
    const result = await exercise(options, status);
    assert.equal(result.active, 1);
    assert.equal(result.aborted, true);
    assert.ok(result.outcome.error);
  });
}
