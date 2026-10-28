// File trust for the snapshot reader (D18). These run as an ordinary user, so "the Home Base user" is the
// user running the tests; ownership by another real user is proven on the test VM.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createSnapshotReader, writeSnapshot } = require('..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'snapshot.json'), 'utf8'));
const UID = process.getuid();
const T0 = Date.parse('2026-10-28T19:00:00.000Z');

function snapshotAt(ms, generation = 7) {
  return { ...structuredClone(vectors.snapshot), generation, written_at: new Date(ms).toISOString() };
}

// A tree like /var/lib/sovereign-home/identity/snapshot.json under a fresh directory that stands in for
// the root-owned part of the path.
function tree(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-snapshot-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'identity');
  fs.mkdirSync(dir, { mode: 0o755 });
  fs.chmodSync(dir, 0o755);
  const file = path.join(dir, 'snapshot.json');
  let clock = T0;
  const reader = (options = {}) => createSnapshotReader({ homeBaseUid: UID, file, trustedRoot: root, now: () => clock, ...options });
  return { root, dir, file, reader, write: (data) => writeSnapshot(data, { file }), setClock: (ms) => { clock = ms; } };
}

test('a snapshot written by the Home Base user is read, and its members resolve', (t) => {
  const { file, reader, write } = tree(t);
  write(snapshotAt(T0));
  assert.equal(fs.statSync(file).mode & 0o777, 0o644);
  const state = reader().current();
  assert.equal(state.ok, true, state.message);
  assert.equal(state.snapshot.household, 'smith');
  assert.equal(state.snapshot.byUserId.get('1001').memberId, 'm_parent');
  assert.equal(state.snapshot.keys.get('k1').asymmetricKeyType, 'ed25519');
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['snapshot.json'], 'no temporary file is left behind');
});

test('missing, symlinked, linked, writable or foreign snapshots are refused', (t) => {
  const cases = [
    ['missing', () => {}, 'missing'],
    ['the file is a symlink', ({ dir, file }) => { writeSnapshot(snapshotAt(T0), { file: path.join(dir, 'real.json') }); fs.symlinkSync(path.join(dir, 'real.json'), file); }, 'untrusted'],
    ['the file is writable by its group', ({ write, file }) => { write(snapshotAt(T0)); fs.chmodSync(file, 0o664); }, 'untrusted'],
    ['the file is writable by others', ({ write, file }) => { write(snapshotAt(T0)); fs.chmodSync(file, 0o646); }, 'untrusted'],
    ['the file has a second link', ({ write, file, root }) => { write(snapshotAt(T0)); fs.linkSync(file, path.join(root, 'elsewhere.json')); }, 'untrusted'],
    ['the file is a directory', ({ file }) => { fs.mkdirSync(file); }, 'untrusted'],
    ['the directory is writable by others', ({ write, dir }) => { write(snapshotAt(T0)); fs.chmodSync(dir, 0o757); }, 'untrusted'],
    ['the file is not JSON', ({ file }) => { fs.writeFileSync(file, '{"format":', { mode: 0o644 }); }, 'malformed'],
    ['the file is another format', ({ write, file }) => { write(snapshotAt(T0)); const data = JSON.parse(fs.readFileSync(file)); data.format = 2; fs.writeFileSync(file, JSON.stringify(data)); }, 'format'],
  ];
  for (const [name, arrange, reason] of cases) {
    const context = tree(t);
    arrange(context);
    const state = context.reader().current();
    assert.equal(state.ok, false, name);
    assert.equal(state.reason, reason, `${name}: ${state.message}`);
  }
});

test('a FIFO in place of the snapshot is refused without blocking', (t) => {
  const { file, reader } = tree(t);
  require('node:child_process').execFileSync('mkfifo', [file]);
  assert.equal(reader().current().reason, 'untrusted');
});

test('the directory must be the Home Base user\'s, and everything above it root\'s', (t) => {
  const { write, reader, root, dir } = tree(t);
  write(snapshotAt(T0));
  assert.equal(reader({ homeBaseUid: UID + 1 }).current().reason, 'untrusted', 'owned by someone else');

  // A directory between the trusted root and the snapshot's own, owned by an ordinary user.
  const nested = path.join(root, 'lib', 'identity');
  fs.mkdirSync(nested, { recursive: true, mode: 0o755 });
  const nestedFile = path.join(nested, 'snapshot.json');
  writeSnapshot(snapshotAt(T0), { file: nestedFile });
  const state = createSnapshotReader({ homeBaseUid: UID, file: nestedFile, trustedRoot: root, now: () => T0 }).current();
  assert.equal(state.reason, 'untrusted');
  assert.match(state.message, /lib is owned by uid/);

  // The snapshot's directory reached through a symlinked parent.
  fs.symlinkSync(dir, path.join(root, 'link'));
  assert.equal(createSnapshotReader({ homeBaseUid: UID, file: path.join(root, 'link', 'snapshot.json'), trustedRoot: root, now: () => T0 }).current().reason, 'untrusted');
});

test('freshness: refused after 120 s, refused from the future, and the age is checked on every call', (t) => {
  const { write, reader, setClock } = tree(t);
  write(snapshotAt(T0));
  const r = reader();
  setClock(T0 + 120_000);
  assert.equal(r.current().ok, true, 'exactly 120 s old is still fresh');
  setClock(T0 + 120_001);
  assert.equal(r.current().reason, 'stale', 'checked again without re-reading the file');
  setClock(T0 - 31_000);
  assert.equal(r.current().reason, 'future');
});

test('the file is re-read at most every 5 s, and a refusal is not remembered as good', (t) => {
  const { write, reader, setClock, file } = tree(t);
  write(snapshotAt(T0, 7));
  const r = reader();
  assert.equal(r.current().snapshot.generation, 7);
  write(snapshotAt(T0, 8));
  setClock(T0 + 4_999);
  assert.equal(r.current().snapshot.generation, 7, 'not re-read yet');
  setClock(T0 + 5_000);
  assert.equal(r.current().snapshot.generation, 8);
  fs.chmodSync(file, 0o666);
  setClock(T0 + 10_000);
  assert.equal(r.current().reason, 'untrusted');
  setClock(T0 + 12_000);
  assert.equal(r.current().reason, 'untrusted', 'still refused until the next re-read');
  fs.chmodSync(file, 0o644);
  setClock(T0 + 15_000);
  assert.equal(r.current().snapshot.generation, 8);
});

test('a lower generation than one already seen is refused until a newer one appears', (t) => {
  const { write, reader, setClock } = tree(t);
  const r = reader({ recheckMs: 0 });
  write(snapshotAt(T0, 5));
  assert.equal(r.current().snapshot.generation, 5);
  write(snapshotAt(T0, 4));
  assert.equal(r.current().reason, 'rollback');
  write(snapshotAt(T0, 5));
  assert.equal(r.current().snapshot.generation, 5, 'the same generation again is fine');
  write(snapshotAt(T0, 6));
  setClock(T0 + 1);
  assert.equal(r.current().snapshot.generation, 6);
});

test('the writer refuses an invalid snapshot and leaves the old one in place', (t) => {
  const { write, file } = tree(t);
  write(snapshotAt(T0, 7));
  assert.throws(() => write({ ...snapshotAt(T0, 8), members: 'everyone' }), /members/);
  assert.equal(JSON.parse(fs.readFileSync(file)).generation, 7);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['snapshot.json']);
});

test('the reader needs the Home Base user\'s uid, and it is never root', () => {
  assert.throws(() => createSnapshotReader({}), /uid/);
  assert.throws(() => createSnapshotReader({ homeBaseUid: '1000' }), /uid/);
  assert.throws(() => createSnapshotReader({ homeBaseUid: 0 }), /never root/);
});
