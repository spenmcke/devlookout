'use strict';

const crypto = require('node:crypto');

function createUpdateChannelHttp({ store } = {}) {
  if (!store || typeof store.get !== 'function') throw new Error('Update channel store is required');
  return async function updateChannelHttp(req, res, url) {
    const match = /^\/v1\/updates\/(stable|cli-stable)$/.exec(url.pathname);
    if (!match) return false;
    if (url.search || url.hash || !['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(404, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end();
      return true;
    }
    const manifest = await store.get(match[1]);
    if (!manifest) {
      res.writeHead(404, { 'Cache-Control': 'public, max-age=30', 'X-Content-Type-Options': 'nosniff' }).end();
      return true;
    }
    const body = Buffer.from(`${JSON.stringify(manifest)}\n`);
    const etag = `"sha256-${crypto.createHash('sha256').update(body).digest('hex')}"`;
    const common = { 'Cache-Control': 'public, max-age=30', 'X-Content-Type-Options': 'nosniff', ETag: etag };
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, common).end();
      return true;
    }
    res.writeHead(200, { ...common, 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length });
    if (req.method === 'HEAD') res.end(); else res.end(body);
    return true;
  };
}

module.exports = { createUpdateChannelHttp };
