const { APP_ATTEST_ROOTS, AppAttestError, verifyAssertion, verifyAttestation } = require('./appattest');
const { createRequestGuard, normalizeOrigin } = require('./guards');
const { HANDOFF_COOKIE_PREFIX, appInstanceClientData, appInstanceReason, createHandoff, createMemoryHandoffStore, handoffClientData, handoffCookie } = require('./handoff');
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
  APP_ATTEST_ROOTS,
  AppAttestError,
  ATTESTATION_ROOTS,
  COOKIE_NAME,
  DEFAULT_SNAPSHOT_PATH,
  HANDOFF_COOKIE_PREFIX,
  OAUTH_COOKIE_NAME,
  POLICY,
  SnapshotError,
  appInstanceClientData,
  appInstanceReason,
  assuranceCookie,
  assuranceExpress,
  attestationRoot,
  authMode,
  createAssurance,
  createHandoff,
  createIdentity,
  createMemoryChallengeStore,
  createMemoryHandoffStore,
  createMemoryStateStore,
  createOAuthFlow,
  createRedeemer,
  createRequestGuard,
  createSnapshotReader,
  createWebAuthn,
  credentialKind,
  guardExpress,
  guardHttp,
  handoffClientData,
  handoffCookie,
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
  verifyAssertion,
  verifyAttestation,
  verifyToken,
  writeSnapshot,
};
