const { createRequestGuard, normalizeOrigin } = require('./guards');
const { guardExpress, guardHttp, refusalBody } = require('./adapters');
const { DEFAULT_SNAPSHOT_PATH, SnapshotError, createSnapshotReader, parseSnapshot, readOwnedFile, writeSnapshot } = require('./snapshot');
const { authMode, createIdentity, requireSocketListen, resolveMember } = require('./identity');
const { ACTION_HEADER, COOKIE_NAME, POLICY, assuranceCookie, assuranceExpress, createAssurance, policyFor, requestDigest, sendAssuranceRefusal } = require('./assurance');
const { createRedeemer, redemptionSocket } = require('./redeem');
const { OAUTH_COOKIE_NAME, createMemoryStateStore, createOAuthFlow, pkceChallenge } = require('./oauth');
const { signToken, verifyToken } = require('./tokens');
const { ATTESTATION_ROOTS, attestationRoot, createMemoryChallengeStore, createWebAuthn, credentialKind, loadRoots, mergeCredentialUpdate } = require('./webauthn');

module.exports = {
  ACTION_HEADER,
  ATTESTATION_ROOTS,
  COOKIE_NAME,
  DEFAULT_SNAPSHOT_PATH,
  OAUTH_COOKIE_NAME,
  POLICY,
  SnapshotError,
  assuranceCookie,
  assuranceExpress,
  attestationRoot,
  authMode,
  createAssurance,
  createIdentity,
  createMemoryChallengeStore,
  createMemoryStateStore,
  createOAuthFlow,
  createRedeemer,
  createRequestGuard,
  createSnapshotReader,
  createWebAuthn,
  credentialKind,
  guardExpress,
  guardHttp,
  loadRoots,
  mergeCredentialUpdate,
  normalizeOrigin,
  parseSnapshot,
  pkceChallenge,
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
