const { createRequestGuard, normalizeOrigin } = require('./guards');
const { guardExpress, guardHttp, refusalBody } = require('./adapters');
const { DEFAULT_SNAPSHOT_PATH, SnapshotError, createSnapshotReader, parseSnapshot, readOwnedFile, writeSnapshot } = require('./snapshot');
const { authMode, createIdentity, requireSocketListen, resolveMember } = require('./identity');
const { ACTION_HEADER, COOKIE_NAME, POLICY, assuranceCookie, assuranceExpress, createAssurance, policyFor, requestDigest, sendAssuranceRefusal } = require('./assurance');
const { createRedeemer, redemptionSocket } = require('./redeem');
const { signToken, verifyToken } = require('./tokens');

module.exports = {
  ACTION_HEADER,
  COOKIE_NAME,
  DEFAULT_SNAPSHOT_PATH,
  POLICY,
  SnapshotError,
  assuranceCookie,
  assuranceExpress,
  authMode,
  createAssurance,
  createIdentity,
  createRedeemer,
  createRequestGuard,
  createSnapshotReader,
  guardExpress,
  guardHttp,
  normalizeOrigin,
  parseSnapshot,
  policyFor,
  readOwnedFile,
  redemptionSocket,
  refusalBody,
  requestDigest,
  requireSocketListen,
  resolveMember,
  sendAssuranceRefusal,
  signToken,
  verifyToken,
  writeSnapshot,
};
