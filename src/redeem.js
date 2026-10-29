// Redeeming an action token (wire contract, section 9; D19). The app asks Home Base over its own socket,
// /run/sovereign-identity/<app id>.sock, so the socket the request arrives on tells Home Base which app is
// asking. Home Base consumes the token's jti and rechecks the member. Anything but a clear yes is a
// refusal: an error answer, an unexpected one, no answer within the timeout, or no Home Base at all.

const http = require('node:http');

const SOCKET_DIR = '/run/sovereign-identity';
const TIMEOUT_MS = 3_000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const REFUSALS = new Map([[409, 'replayed'], [403, 'not_authorized'], [400, 'invalid']]);

function redemptionSocket(appId) {
  if (typeof appId !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(appId)) throw new Error(`not an app ID: ${appId}`);
  return `${SOCKET_DIR}/${appId}.sock`;
}

// createRedeemer({ appId }) returns redeem({ token, policy, target, digest }), which resolves to
// { redeemed: true } or { redeemed: false, reason } (replayed, not_authorized, invalid or unavailable) and
// never rejects.
function createRedeemer({ appId, socketPath = redemptionSocket(appId), timeoutMs = TIMEOUT_MS } = {}) {
  return function redeem({ token, policy, target, digest }) {
    const body = JSON.stringify({ token, policy, target, digest });
    return new Promise((resolve) => {
      let settled = false;
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        req.destroy();
        resolve(result);
      };
      const unavailable = () => finish({ redeemed: false, reason: 'unavailable' });
      const req = http.request({
        socketPath,
        method: 'POST',
        path: '/v1/redeem',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
        agent: false,
      }, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (chunk) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) return unavailable();
          chunks.push(chunk);
        });
        res.on('end', () => {
          if (res.statusCode !== 200) return finish({ redeemed: false, reason: REFUSALS.get(res.statusCode) || 'unavailable' });
          let answer;
          try {
            answer = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          } catch {
            return unavailable();
          }
          return finish(answer?.redeemed === true ? { redeemed: true } : { redeemed: false, reason: 'unavailable' });
        });
        res.on('error', unavailable);
      });
      // One deadline for the whole exchange: connecting, sending and the full answer.
      const timer = setTimeout(unavailable, timeoutMs);
      req.on('error', unavailable);
      req.end(body);
    });
  };
}

module.exports = { createRedeemer, redemptionSocket };
