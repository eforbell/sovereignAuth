const { createRequestGuard, normalizeOrigin } = require('./guards');
const { guardExpress, guardHttp, refusalBody } = require('./adapters');

module.exports = {
  createRequestGuard,
  guardExpress,
  guardHttp,
  normalizeOrigin,
  refusalBody,
};
