'use strict';

const https = require('node:https');

const MAXIMUM_REQUEST_BYTES = 6 * 1024 * 1024;

function validateCaPem(caPem) {
  if (typeof caPem !== 'string' || !caPem.includes('-----BEGIN CERTIFICATE-----') || caPem.includes('PRIVATE KEY') || Buffer.byteLength(caPem) > 1024 * 1024) throw new Error('Collector CA bundle is invalid');
  return caPem;
}

async function postJson(target, body, { authorization = null, caPem = null, fetchImpl = globalThis.fetch, httpsRequestImpl = https.request, timeoutMs = 15000, maximumResponseBytes = 1024 * 1024 } = {}) {
  const url = target instanceof URL ? target : new URL(target);
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1', '::1'].includes(url.hostname)) throw new Error('Collector transport requires HTTPS outside loopback');
  if (url.username || url.password) throw new Error('Collector transport URL must not contain credentials');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || !Number.isSafeInteger(maximumResponseBytes) || maximumResponseBytes < 1) throw new Error('Collector transport bounds are invalid');
  if (typeof fetchImpl !== 'function' || typeof httpsRequestImpl !== 'function') throw new Error('Collector transport implementation is invalid');
  if (authorization !== null && (typeof authorization !== 'string' || !authorization)) throw new Error('Collector authorization header is invalid');
  const serialized = JSON.stringify(body);
  if (Buffer.byteLength(serialized) > MAXIMUM_REQUEST_BYTES) throw new Error('Collector request exceeds configured bound');
  const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(serialized), ...(authorization ? { Authorization: authorization } : {}) };
  if (!caPem) {
    const response = await fetchImpl(url, { method: 'POST', headers, body: serialized, signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
    if (!response.ok) throw new Error(`Collector request failed with status ${response.status}`);
    let text;
    if (response.body && typeof response.body[Symbol.asyncIterator] === 'function') {
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body) {
        const bytes = Buffer.from(chunk);
        size += bytes.length;
        if (size > maximumResponseBytes) {
          await response.body.cancel?.().catch?.(() => {});
          throw new Error('Collector response exceeds configured bound');
        }
        chunks.push(bytes);
      }
      text = Buffer.concat(chunks, size).toString('utf8');
    } else {
      if (typeof response.text !== 'function') throw new Error('Collector response body is unavailable');
      text = await response.text();
      if (Buffer.byteLength(text) > maximumResponseBytes) throw new Error('Collector response exceeds configured bound');
    }
    try { return JSON.parse(text); }
    catch { throw new Error('Collector response is not valid JSON'); }
  }
  validateCaPem(caPem);
  return new Promise((resolve, reject) => {
    const request = httpsRequestImpl(url, { method: 'POST', headers, ca: caPem, rejectUnauthorized: true, timeout: timeoutMs }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        const bytes = Buffer.from(chunk);
        size += bytes.length;
        if (size > maximumResponseBytes) request.destroy(new Error('Collector response exceeds configured bound'));
        else chunks.push(bytes);
      });
      response.on('end', () => {
        if (!Number.isInteger(response.statusCode) || response.statusCode < 200 || response.statusCode >= 300) return reject(new Error(`Collector request failed with status ${response.statusCode || 'unknown'}`));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('Collector response is not valid JSON')); }
      });
    });
    request.once('timeout', () => request.destroy(new Error('Collector request timed out')));
    request.once('error', reject);
    request.end(serialized);
  });
}

module.exports = { MAXIMUM_REQUEST_BYTES, validateCaPem, postJson };
