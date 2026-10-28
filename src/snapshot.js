// The directory snapshot (wire contract, section 5; D18). Home Base publishes the household directory as a
// file apps can read but not write, and trust comes from who owns it, not from a signature: the file and
// its directory must belong to the Home Base user and be writable by no one else, and nothing on the way
// there may be a symlink or writable by anyone but root.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_SNAPSHOT_PATH = '/var/lib/sovereign-home/identity/snapshot.json';
const FORMAT = 1;
const MAX_AGE_MS = 120_000;
const RECHECK_MS = 5_000;
const MAX_FUTURE_MS = 30_000;
const MAX_BYTES = 1024 * 1024;
const ROLES = new Set(['parent', 'kid']);
const STATUSES = new Set(['active', 'disabled']);
const WRITABLE_BY_OTHERS = 0o022;

class SnapshotError extends Error {
  constructor(reason, message) {
    super(message);
    this.reason = reason;
  }
}

function fail(reason, message) {
  throw new SnapshotError(reason, message);
}

const isText = (value) => typeof value === 'string' && value.length > 0;
const isCount = (value) => Number.isSafeInteger(value) && value >= 0;

// Ed25519 public keys travel as base64url of the raw 32 bytes; anything else is a malformed snapshot.
function importKey(entry, index) {
  if (!isText(entry?.kid)) fail('malformed', `keys[${index}].kid is missing`);
  const raw = isText(entry.public_key) && /^[A-Za-z0-9_-]+$/.test(entry.public_key) ? Buffer.from(entry.public_key, 'base64url') : null;
  if (!raw || raw.length !== 32) fail('malformed', `keys[${index}].public_key is not a raw Ed25519 key`);
  return [entry.kid, crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' })];
}

function validMember(member, index) {
  const where = `members[${index}]`;
  if (!isText(member?.user_id)) fail('malformed', `${where}.user_id is missing`);
  if (!isText(member.member_id)) fail('malformed', `${where}.member_id is missing`);
  if (!isText(member.login)) fail('malformed', `${where}.login is missing`);
  if (typeof member.name !== 'string') fail('malformed', `${where}.name is missing`);
  if (!ROLES.has(member.role)) fail('malformed', `${where}.role must be parent or kid`);
  if (!STATUSES.has(member.status)) fail('malformed', `${where}.status must be active or disabled`);
  if (!isCount(member.epoch)) fail('malformed', `${where}.epoch must be a whole number`);
  if (!Array.isArray(member.apps) || !member.apps.every(isText)) fail('malformed', `${where}.apps must list app IDs`);
  return Object.freeze({
    userId: member.user_id,
    memberId: member.member_id,
    login: member.login,
    name: member.name,
    role: member.role,
    status: member.status,
    epoch: member.epoch,
    apps: Object.freeze([...member.apps]),
  });
}

// Checks a parsed snapshot's shape and returns it in the form the library uses. Freshness and generation
// are the reader's business; this is only "is it a format-1 snapshot".
function parseSnapshot(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('malformed', 'the snapshot is not a JSON object');
  if (data.format !== FORMAT) fail('format', `the snapshot is format ${data.format}, not ${FORMAT}`);
  if (!isText(data.household)) fail('malformed', 'household is missing');
  if (!Number.isSafeInteger(data.generation) || data.generation < 1) fail('malformed', 'generation must be a positive whole number');
  const writtenAt = isText(data.written_at) ? Date.parse(data.written_at) : NaN;
  if (!Number.isFinite(writtenAt)) fail('malformed', 'written_at is not a time');
  if (!isCount(data.global_epoch)) fail('malformed', 'global_epoch must be a whole number');
  if (!Array.isArray(data.keys)) fail('malformed', 'keys must be a list');
  if (!Array.isArray(data.members)) fail('malformed', 'members must be a list');
  const keys = new Map(data.keys.map(importKey));
  if (keys.size !== data.keys.length) fail('malformed', 'two keys share a kid');
  const members = data.members.map(validMember);
  const byUserId = new Map(members.map((member) => [member.userId, member]));
  if (byUserId.size !== members.length) fail('malformed', 'two members share a user_id');
  if (new Set(members.map((member) => member.login)).size !== members.length) fail('malformed', 'two members share a login');
  return Object.freeze({
    household: data.household,
    generation: data.generation,
    writtenAt,
    globalEpoch: data.global_epoch,
    keys,
    members: Object.freeze(members),
    byUserId,
  });
}

// Every directory from the top down to the snapshot's own: a real directory, not a symlink, owned by root
// (or, for the last one, the Home Base user) and writable by no one else. Whoever can write a directory on
// the way could swap what lies below it. Directories at or above trustedRoot are not checked; that exists
// for tests, which can't build their tree under root-owned directories.
function checkDirectories(dir, { homeBaseUid, trustedRoot }) {
  const chain = [];
  for (let current = dir; ; current = path.dirname(current)) {
    if (trustedRoot && (current === trustedRoot || !current.startsWith(`${trustedRoot}${path.sep}`))) break;
    chain.unshift(current);
    if (current === path.dirname(current)) break;
  }
  for (const current of chain) {
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      fail('missing', `${current} does not exist`);
    }
    if (stat.isSymbolicLink()) fail('untrusted', `${current} is a symlink`);
    if (!stat.isDirectory()) fail('untrusted', `${current} is not a directory`);
    const allowed = current === dir ? stat.uid === homeBaseUid : stat.uid === 0;
    if (!allowed) fail('untrusted', `${current} is owned by uid ${stat.uid}`);
    if (stat.mode & WRITABLE_BY_OTHERS) fail('untrusted', `${current} is writable by group or others`);
  }
}

// Opens the file by descriptor without following a symlink, and checks the descriptor, not the path, so
// what is checked is what is read.
function readTrustedFile(file, { homeBaseUid }) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === 'ENOENT') fail('missing', `${file} does not exist`);
    if (error.code === 'ELOOP' || error.code === 'EMLINK') fail('untrusted', `${file} is a symlink`);
    fail('unreadable', `${file}: ${error.code || error.message}`);
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) fail('untrusted', `${file} is not a regular file`);
    if (stat.uid !== homeBaseUid) fail('untrusted', `${file} is owned by uid ${stat.uid}`);
    if (stat.mode & WRITABLE_BY_OTHERS) fail('untrusted', `${file} is writable by group or others`);
    if (stat.nlink !== 1) fail('untrusted', `${file} has ${stat.nlink} links`);
    if (stat.size > MAX_BYTES) fail('malformed', `${file} is larger than ${MAX_BYTES} bytes`);
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

// createSnapshotReader({ homeBaseUid, file, ... }).current() returns { ok: true, snapshot } or
// { ok: false, reason, message }. It re-reads the file at most every recheckMs, checks the age of what it
// holds on every call, and never accepts a generation lower than one it has seen.
function createSnapshotReader({
  homeBaseUid,
  file = DEFAULT_SNAPSHOT_PATH,
  now = Date.now,
  maxAgeMs = MAX_AGE_MS,
  recheckMs = RECHECK_MS,
  trustedRoot = null,
} = {}) {
  if (!Number.isSafeInteger(homeBaseUid) || homeBaseUid < 0) throw new Error('createSnapshotReader needs the Home Base user\'s uid');
  if (homeBaseUid === 0) throw new Error('the Home Base user is never root');
  const resolved = path.resolve(file);
  let highestGeneration = 0;
  let checkedAt = -Infinity;
  let last = null;

  function load() {
    checkDirectories(path.dirname(resolved), { homeBaseUid, trustedRoot: trustedRoot && path.resolve(trustedRoot) });
    let data;
    try {
      data = JSON.parse(readTrustedFile(resolved, { homeBaseUid }));
    } catch (error) {
      if (error instanceof SnapshotError) throw error;
      fail('malformed', 'the snapshot is not JSON');
    }
    const snapshot = parseSnapshot(data);
    if (snapshot.generation < highestGeneration) fail('rollback', `generation ${snapshot.generation} is older than ${highestGeneration}`);
    highestGeneration = snapshot.generation;
    return snapshot;
  }

  function current() {
    const at = now();
    if (at - checkedAt >= recheckMs || at < checkedAt) {
      checkedAt = at;
      try {
        last = { ok: true, snapshot: load() };
      } catch (error) {
        if (!(error instanceof SnapshotError)) throw error;
        last = { ok: false, reason: error.reason, message: error.message };
      }
    }
    if (!last.ok) return last;
    const age = at - last.snapshot.writtenAt;
    if (age > maxAgeMs) return { ok: false, reason: 'stale', message: `the snapshot is ${Math.round(age / 1000)} s old` };
    if (age < -MAX_FUTURE_MS) return { ok: false, reason: 'future', message: 'the snapshot was written in the future' };
    return last;
  }

  return { current, file: resolved };
}

// Home Base's side: replace the snapshot atomically. The new file is created next to the old one (never
// following a symlink, never reusing a name), synced, renamed over it, and the directory synced, so a
// reader sees the old file or the new one, whole. The content is checked with the reader's own rules first.
function writeSnapshot(data, { file = DEFAULT_SNAPSHOT_PATH } = {}) {
  parseSnapshot(data);
  const resolved = path.resolve(file);
  const dir = path.dirname(resolved);
  const temp = path.join(dir, `.${path.basename(resolved)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}`);
  const body = `${JSON.stringify(data, null, 2)}\n`;
  const fd = fs.openSync(temp, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644);
  try {
    fs.writeSync(fd, body);
    fs.fchmodSync(fd, 0o644);
    fs.fsyncSync(fd);
  } catch (error) {
    fs.closeSync(fd);
    fs.rmSync(temp, { force: true });
    throw error;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(temp, resolved);
  } catch (error) {
    fs.rmSync(temp, { force: true });
    throw error;
  }
  const dirFd = fs.openSync(dir, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(dirFd);
  } finally {
    fs.closeSync(dirFd);
  }
}

module.exports = {
  DEFAULT_SNAPSHOT_PATH,
  SnapshotError,
  createSnapshotReader,
  parseSnapshot,
  writeSnapshot,
};
