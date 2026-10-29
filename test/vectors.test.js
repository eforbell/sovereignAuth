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

const { parseSnapshot, resolveMember } = require('..');
const snapshotVectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'snapshot.json'), 'utf8'));

function applyChanges(document, changes) {
  let result = structuredClone(document);
  for (const change of changes) {
    if (!change.path.length) {
      result = structuredClone(change.value);
      continue;
    }
    const parent = change.path.slice(0, -1).reduce((node, key) => node[key], result);
    const key = change.path.at(-1);
    if (change.remove) delete parent[key];
    else parent[key] = structuredClone(change.value);
  }
  return result;
}

test('snapshot format', async (t) => {
  for (const vector of snapshotVectors.format) {
    await t.test(vector.name, () => {
      const data = applyChanges(snapshotVectors.snapshot, vector.changes);
      if (vector.expect.ok) {
        assert.equal(parseSnapshot(data).generation, data.generation);
      } else {
        assert.throws(() => parseSnapshot(data), (error) => error.reason === vector.expect.reason);
      }
    });
  }
});

test('member resolution', async (t) => {
  const snapshot = parseSnapshot(snapshotVectors.snapshot);
  for (const vector of snapshotVectors.members) {
    await t.test(vector.name, () => {
      const result = resolveMember(snapshot, vector.headers, { appId: vector.appId });
      if (vector.expect.member_id) {
        assert.equal(result.member?.memberId, vector.expect.member_id);
      } else {
        assert.equal(result.member, null);
        assert.equal(result.reason, vector.expect.reason);
      }
    });
  }
});
