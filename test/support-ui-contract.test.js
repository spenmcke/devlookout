'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const repository = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(repository, 'public/index.html'), 'utf8');
const app = fs.readFileSync(path.join(repository, 'public/app.js'), 'utf8');
const api = fs.readFileSync(path.join(repository, 'public/api.js'), 'utf8');
const distribution = fs.readFileSync(path.join(repository, 'hosting/distribution-server.js'), 'utf8');
const hostedApi = fs.readFileSync(path.join(repository, 'src/hosting/saas-api.js'), 'utf8');
const accountDelete = fs.readFileSync(path.join(repository, 'src/onboarding/account-delete.js'), 'utf8');

test('Settings Support AI section exposes one complete MCP setup action without separate URL or token controls', () => {
  assert.ok(html.indexOf('id="supportAiSettings"') > html.indexOf('id="settingsAccountEmail"'));
  assert.ok(html.indexOf('id="supportAiSettings"') < html.indexOf('settings-danger-zone'));
  assert.doesNotMatch(html, /Connect an alert channel|id="notificationInstructions"/);
  const supportSection = html.slice(html.indexOf('id="supportAiSettings"'), html.indexOf('settings-danger-zone'));
  for (const value of ['Connect your coding agent', 'Copy the complete MCP setup in one click', 'id="copySupportMcpSetupButton"', 'Copy to your coding agent to access Lookout AI support agent', 'id="supportMcpSetupTerminal"', 'id="supportMcpSetupPreview"', 'This setup includes your Support token', 'trusted local coding agent', 'id="supportMcpSetupStatus"', 'data-ph-no-capture']) assert.ok(supportSection.includes(value));
  assert.equal((supportSection.match(/<button\b/g) || []).length, 1);
  assert.equal((supportSection.match(/class="settings-copy-button"/g) || []).length, 1);
  for (const obsolete of ['Remote MCP server URL', 'Copy URL', 'id="supportMcpUrl"', 'id="supportAccountToken"', 'id="toggleSupportTokenButton"', 'id="copySupportTokenButton"', '>Show<', '>Copy token<']) assert.ok(!supportSection.includes(obsolete));
  assert.doesNotMatch(html, /docs\.devlookout\.com\/agent-support/);
  assert.match(api, /supportAccountToken: \(\) => get\('\/v1\/support\/account-token'\)/);
  assert.match(hostedApi, /url\.pathname === '\/v1\/support\/account-token'/);
  assert.match(api, /supportTokens: \(\) => get\('\/v1\/support\/tokens'\)/);
  assert.match(api, /createSupportToken/);
  assert.match(api, /revokeSupportToken/);
});

test('complete MCP setup is fetched on demand, copied with required connection details, and then cleared', () => {
  const settingsRenderer = app.slice(app.indexOf('async function renderSettingsSession'), app.indexOf('function clearSupportAccountToken'));
  const supportImplementation = app.slice(app.indexOf('function clearSupportAccountToken'), app.indexOf('function validStoredSetup'));
  assert.doesNotMatch(settingsRenderer, /supportAccountToken|loadSupportAccountToken/);
  assert.doesNotMatch(supportImplementation, /localStorage|sessionStorage|setAttribute|dataset\.[A-Za-z]*token|history|location/);
  assert.match(supportImplementation, /async function copySupportMcpSetup\(\)/);
  assert.match(supportImplementation, /await LookoutApi\.supportAccountToken\(\)/);
  assert.match(supportImplementation, /state\.supportAccountToken = result\.token/);
  for (const value of ['https://app.devlookout.com/support/mcp', 'Streamable HTTP', 'Bearer token', 'not OAuth', 'ask_lookout_support', 'check_lookout_support']) assert.ok(supportImplementation.includes(value));
  assert.match(supportImplementation, /MCP setup copied/);
  assert.match(supportImplementation, /finally \{[\s\S]*clearSupportAccountToken\(\)/);
  assert.doesNotMatch(supportImplementation, /\.value\s*=\s*(?:result\.token|state\.supportAccountToken)/);
  assert.doesNotMatch(supportImplementation, /capture\([^)]*result\.token/i);
  assert.match(app, /state\.view === 'settings' && view !== 'settings'\) clearSupportAccountToken\(\)/);
  assert.match(app, /clearSupportAccountToken\(\);[\s\S]*LookoutApi\.deleteAccount\(\)/);
  assert.match(app, /id="copySupportMcpSetupButton"|#copySupportMcpSetupButton/);
  assert.match(distribution, /deleteHostedAccount/);
  assert.ok(accountDelete.indexOf('supportStore.deleteTenantSupport(tenantId)') < accountDelete.indexOf('deleteAuthUser(userId)'));
});
