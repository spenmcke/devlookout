'use strict';

const INDEX_URL = 'https://docs.devlookout.com/llms.txt';
const CANONICAL_ORIGIN = 'https://docs.devlookout.com';

async function boundedText(response, maximumBytes) {
  const declared = response.headers.get('content-length');
  if (declared && Number(declared) > maximumBytes) throw new Error('Documentation response is too large');
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Documentation response has no body');
  const chunks = []; let size = 0;
  while (true) {
    const { done, value } = await reader.read(); if (done) break;
    size += value.byteLength;
    if (size > maximumBytes) { await reader.cancel(); throw new Error('Documentation response is too large'); }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

function canonicalMarkdownUrl(value) {
  let url;
  try { url = new URL(value); } catch { return null; }
  if (url.protocol !== 'https:' || url.host !== 'docs.devlookout.com' || url.username || url.password || url.search || url.hash || !url.pathname.endsWith('.md') || url.pathname.includes('..')) return null;
  return url;
}

function parseIndex(text) {
  const entries = []; const seen = new Set();
  const pattern = /^\s*[-*]\s+\[([^\]\r\n]{1,200})\]\((https:\/\/docs\.devlookout\.com\/[^\s)]+\.md)\)(?::\s*([^\r\n]{0,500}))?\s*$/gm;
  for (const match of text.matchAll(pattern)) {
    const markdownUrl = canonicalMarkdownUrl(match[2]);
    if (!markdownUrl || seen.has(markdownUrl.href)) continue;
    seen.add(markdownUrl.href);
    entries.push({ title: match[1].trim(), description: (match[3] || '').trim(), markdownUrl: markdownUrl.href, url: `${CANONICAL_ORIGIN}${markdownUrl.pathname.slice(0, -3) || '/'}` });
  }
  return entries;
}

function terms(value) { return new Set(String(value || '').toLowerCase().match(/[a-z0-9][a-z0-9_-]{1,}/g) || []); }
function rankEntries(entries, query) {
  const queryTerms = terms(query);
  return entries.map((entry) => {
    const titleTerms = terms(entry.title); const descriptionTerms = terms(entry.description); const pathTerms = terms(new URL(entry.markdownUrl).pathname);
    let score = 0;
    for (const term of queryTerms) { if (titleTerms.has(term)) score += 8; if (descriptionTerms.has(term)) score += 3; if (pathTerms.has(term)) score += 5; }
    return { entry, score };
  }).sort((left, right) => right.score - left.score || left.entry.markdownUrl.localeCompare(right.entry.markdownUrl)).slice(0, 4).map(({ entry }) => entry);
}

class LookoutDocsRetriever {
  constructor({ fetchImpl = globalThis.fetch, indexUrl = INDEX_URL, clock = () => Date.now(), cacheMs = 5 * 60 * 1000, timeoutMs = 10000 } = {}) {
    const parsed = new URL(indexUrl);
    if (parsed.href !== INDEX_URL) throw new Error('Lookout documentation index must use the canonical URL');
    this.fetch = fetchImpl; this.clock = clock; this.cacheMs = Math.min(cacheMs, 5 * 60 * 1000); this.timeoutMs = timeoutMs; this.cache = null;
  }

  async _index(signal) {
    if (this.cache && this.cache.expiresAt > this.clock()) return this.cache.entries;
    const response = await this.fetch(INDEX_URL, { headers: { Accept: 'text/plain' }, redirect: 'manual', signal });
    if (response.status !== 200 || response.redirected || !/^text\/(?:plain|markdown)(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Lookout Documentation index is unavailable');
    const entries = parseIndex(await boundedText(response, 256 * 1024));
    if (!entries.length) throw new Error('Lookout Documentation index is invalid');
    this.cache = { entries, expiresAt: this.clock() + this.cacheMs };
    return entries;
  }

  async retrieve(query) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const entries = await this._index(controller.signal);
      const selected = rankEntries(entries, query);
      const references = []; let aggregate = 0;
      for (const entry of selected) {
        const parsed = canonicalMarkdownUrl(entry.markdownUrl);
        if (!parsed || !entries.some((item) => item.markdownUrl === parsed.href)) continue;
        const response = await this.fetch(parsed, { headers: { Accept: 'text/markdown, text/plain;q=0.9' }, redirect: 'manual', signal: controller.signal });
        if (response.status !== 200 || response.redirected || !/^text\/(?:plain|markdown)(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Lookout Documentation page is unavailable');
        const markdown = await boundedText(response, 64 * 1024);
        const bytes = Buffer.byteLength(markdown);
        if (aggregate + bytes > 128 * 1024) break;
        aggregate += bytes;
        references.push({ title: entry.title, url: entry.url, markdown });
      }
      return references;
    } catch (error) {
      if (error?.name === 'AbortError' || controller.signal.aborted) throw new Error('Lookout Documentation retrieval timed out');
      throw new Error('Lookout Documentation retrieval is unavailable');
    } finally { clearTimeout(timer); }
  }
}

module.exports = { LookoutDocsRetriever, parseLookoutDocsIndex: parseIndex, rankLookoutDocsEntries: rankEntries, canonicalMarkdownUrl, boundedDocumentationText: boundedText, LOOKOUT_DOCS_INDEX_URL: INDEX_URL };
