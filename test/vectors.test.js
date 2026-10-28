// Runs the language-neutral conformance vectors. A port to another language runs the same files.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequestGuard } = require('..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'request-guards.json'), 'utf8'));

for (const group of vectors.groups) {
  test(`request guards: ${group.name}`, async (t) => {
    const guard = createRequestGuard(group.guard);
    for (const vector of group.cases) {
      await t.test(vector.name, () => {
        const decision = guard.check(vector.request);
        assert.equal(decision.allowed, vector.expect.allowed);
        if (!vector.expect.allowed) {
          assert.equal(decision.reason, vector.expect.reason);
          assert.equal(decision.status, 403);
        }
      });
    }
  });
}

test('the vectors cover every refusal reason and both outcomes', () => {
  const reasons = new Set(vectors.groups.flatMap((group) => group.cases.map((vector) => vector.expect.reason)).filter(Boolean));
  assert.deepEqual([...reasons].sort(), ['content_type', 'fetch_metadata_malformed', 'fetch_metadata_missing', 'fetch_site', 'not_same_origin', 'origin_mismatch', 'origin_missing']);
  assert.ok(vectors.groups.some((group) => group.cases.some((vector) => vector.expect.allowed)));
});
