'use strict';

function stripHuJsonComments(input) {
  let output = '';
  let inString = false;
  let escaped = false;
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    const next = input[index + 1];
    if (inString) {
      output += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; output += char; continue; }
    if (char === '/' && next === '/') {
      while (index < input.length && input[index] !== '\n') index += 1;
      output += '\n';
      continue;
    }
    if (char === '/' && next === '*') {
      index += 2;
      while (index < input.length && !(input[index] === '*' && input[index + 1] === '/')) index += 1;
      index += 1;
      continue;
    }
    output += char;
  }
  if (inString) throw new Error('Invalid HuJSON: unterminated string');
  return output;
}

function removeTrailingCommas(input) {
  let output = '';
  let inString = false;
  let escaped = false;
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];
    if (inString) {
      output += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; output += char; continue; }
    if (char === ',') {
      let cursor = index + 1;
      while (/\s/.test(input[cursor] || '')) cursor += 1;
      if (input[cursor] === '}' || input[cursor] === ']') continue;
    }
    output += char;
  }
  return output;
}

function parseHuJson(input) {
  if (typeof input !== 'string') throw new TypeError('HuJSON input must be a string');
  return JSON.parse(removeTrailingCommas(stripHuJsonComments(input)));
}

async function readLimitedText(response, maximumBytes) {
  if (!response.body || typeof response.body[Symbol.asyncIterator] !== 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maximumBytes) throw new Error('Tailscale API response exceeds configured size limit');
    return text;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > maximumBytes) {
      await response.body.cancel?.().catch?.(() => {});
      throw new Error('Tailscale API response exceeds configured size limit');
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

class TailscaleClient {
  constructor({ tokenProvider, authMode = 'api-token', baseUrl = 'https://api.tailscale.com', timeoutMs = 15000, maximumResponseBytes = 10 * 1024 * 1024, fetchImpl = globalThis.fetch } = {}) {
    if (typeof tokenProvider !== 'function') throw new TypeError('TailscaleClient requires an async tokenProvider');
    if (!['api-token', 'oauth'].includes(authMode)) throw new Error('authMode must be api-token or oauth');
    if (typeof fetchImpl !== 'function') throw new TypeError('TailscaleClient requires fetch support');
    this.tokenProvider = tokenProvider;
    this.authMode = authMode;
    this.baseUrl = new URL(baseUrl);
    if (this.baseUrl.protocol !== 'https:' && !['localhost', '127.0.0.1', '::1'].includes(this.baseUrl.hostname)) throw new Error('Tailscale API base URL must use HTTPS');
    if (this.baseUrl.username || this.baseUrl.password) throw new Error('Tailscale API base URL must not contain credentials');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || !Number.isSafeInteger(maximumResponseBytes) || maximumResponseBytes < 1024) throw new Error('Tailscale API limits are invalid');
    this.timeoutMs = timeoutMs;
    this.maximumResponseBytes = maximumResponseBytes;
    this.fetchImpl = fetchImpl;
  }

  async request(apiPath, { accept = 'application/json', signal = undefined } = {}) {
    if (typeof apiPath !== 'string' || !apiPath.startsWith('/api/')) throw new Error('Tailscale API path must be an absolute API path');
    const token = await this.tokenProvider();
    if (typeof token !== 'string' || !token) throw new Error('Tailscale credential provider returned no credential');
    const authorization = this.authMode === 'oauth' ? `Bearer ${token}` : `Basic ${Buffer.from(`${token}:`).toString('base64')}`;
    const url = new URL(apiPath, this.baseUrl);
    if (url.origin !== this.baseUrl.origin) throw new Error('Tailscale API request may not change origin');
    if (signal !== undefined && !(signal instanceof AbortSignal)) throw new TypeError('Tailscale API request signal is invalid');
    const timeoutSignal = AbortSignal.timeout(this.timeoutMs);
    const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
    const response = await this.fetchImpl(url, { method: 'GET', headers: { Accept: accept, Authorization: authorization, 'User-Agent': 'lookout/0.1' }, signal: requestSignal, redirect: 'error' });
    const declared = response.headers.get('content-length');
    if (declared && (!/^\d+$/.test(declared) || Number(declared) > this.maximumResponseBytes)) throw new Error('Tailscale API response exceeds configured size limit');
    const text = await readLimitedText(response, this.maximumResponseBytes);
    if (!response.ok) throw new Error(`Tailscale API request failed with status ${response.status}`);
    return text;
  }

  async listDevices(tailnet) {
    if (typeof tailnet !== 'string' || !tailnet || tailnet.length > 512) throw new Error('tailnet identifier is invalid');
    return JSON.parse(await this.request(`/api/v2/tailnet/${encodeURIComponent(tailnet)}/devices`));
  }

  async listUsers(tailnet) {
    if (typeof tailnet !== 'string' || !tailnet || tailnet.length > 512) throw new Error('tailnet identifier is invalid');
    return JSON.parse(await this.request(`/api/v2/tailnet/${encodeURIComponent(tailnet)}/users`));
  }

  async getPolicy(tailnet) {
    if (typeof tailnet !== 'string' || !tailnet || tailnet.length > 512) throw new Error('tailnet identifier is invalid');
    return parseHuJson(await this.request(`/api/v2/tailnet/${encodeURIComponent(tailnet)}/acl`, { accept: 'application/hujson, application/json' }));
  }

  async listLogs(tailnet, logType, { start, end, signal } = {}) {
    if (typeof tailnet !== 'string' || !tailnet || tailnet.length > 512) throw new Error('tailnet identifier is invalid');
    if (!['network', 'configuration'].includes(logType)) throw new Error('Tailscale log type must be network or configuration');
    for (const [name, value] of Object.entries({ start, end })) {
      if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) throw new Error(`Tailscale log ${name} must be an RFC3339 timestamp`);
    }
    if (Date.parse(start) > Date.parse(end)) throw new Error('Tailscale log start must not be after end');
    const query = new URLSearchParams({ start, end });
    const response = JSON.parse(await this.request(`/api/v2/tailnet/${encodeURIComponent(tailnet)}/logging/${logType}?${query}`, { signal }));
    if (!response || !Array.isArray(response.logs)) throw new Error('Tailscale log response is invalid');
    return response.logs;
  }

  async listNetworkLogs(tailnet, options) {
    return this.listLogs(tailnet, 'network', options);
  }

  async listConfigurationLogs(tailnet, options) {
    return this.listLogs(tailnet, 'configuration', options);
  }
}

module.exports = { stripHuJsonComments, removeTrailingCommas, parseHuJson, readLimitedText, TailscaleClient };
