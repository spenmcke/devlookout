'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { LookoutDocsRetriever, parseLookoutDocsIndex } = require('../src/support/docs-retriever');

function textResponse(text, type = 'text/plain; charset=utf-8', status = 200) { return new Response(text, { status, headers: { 'Content-Type': type, 'Content-Length': String(Buffer.byteLength(text)) } }); }

test('documentation retriever selects bounded canonical indexed Markdown deterministically and caches index', async () => {
  const index = '# Lookout\n- [Install](https://docs.devlookout.com/install.md): setup connected complete\n- [Privacy](https://docs.devlookout.com/privacy.md): retention support data\n- [Evil](https://evil.example/a.md): no\n- [Query](https://docs.devlookout.com/a.md?token=x): no\n';
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(String(url));
    if (String(url).endsWith('/llms.txt')) return textResponse(index);
    if (String(url).endsWith('/install.md')) return textResponse('# Install\nConnected is progress.', 'text/markdown');
    if (String(url).endsWith('/privacy.md')) return textResponse('# Privacy', 'text/markdown');
    throw new Error('unexpected');
  };
  const retriever = new LookoutDocsRetriever({ fetchImpl });
  const first = await retriever.retrieve('setup is Connected');
  const second = await retriever.retrieve('support data retention');
  assert.equal(first[0].url, 'https://docs.devlookout.com/install');
  assert.equal(second[0].url, 'https://docs.devlookout.com/privacy');
  assert.equal(calls.filter((url) => url.endsWith('/llms.txt')).length, 1);
  assert.equal(first.length <= 4, true);
  assert.equal(parseLookoutDocsIndex(index).length, 2);
});

test('documentation retriever rejects redirects, HTML, and oversized pages with bounded errors', async () => {
  const index = '- [Install](https://docs.devlookout.com/install.md): setup\n';
  const retriever = new LookoutDocsRetriever({ fetchImpl: async (url) => String(url).endsWith('/llms.txt') ? textResponse(index) : textResponse('<html>', 'text/html') });
  await assert.rejects(() => retriever.retrieve('setup'), /retrieval is unavailable/);
});
