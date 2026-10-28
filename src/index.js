const { createRequestGuard, normalizeOrigin } = require('./guards');
const { guardExpress, guardHttp, refusalBody } = require('./adapters');
const { DEFAULT_SNAPSHOT_PATH, SnapshotError, createSnapshotReader, parseSnapshot, writeSnapshot } = require('./snapshot');
const { authMode, createIdentity, requireSocketListen, resolveMember } = require('./identity');

module.exports = {
  DEFAULT_SNAPSHOT_PATH,
  SnapshotError,
  authMode,
  createIdentity,
  createRequestGuard,
  createSnapshotReader,
  guardExpress,
  guardHttp,
  normalizeOrigin,
  parseSnapshot,
  refusalBody,
  requireSocketListen,
  resolveMember,
  writeSnapshot,
};
