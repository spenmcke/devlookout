#!/usr/bin/env node
'use strict';

const { loadConfig } = require('../src/config');
const { configuredLiveApi, runLiveLinuxValidation } = require('../src/validation/live-linux');

async function main() {
  const [address, user, knownHostsFile, identityFile] = process.argv.slice(2);
  if (!address || !user || !knownHostsFile || !identityFile) throw new Error('Usage: lookout validate-live-linux <target-ip> <ssh-user> <private-known-hosts-file> <private-identity-file>');
  if (process.platform !== 'linux') throw new Error('Live Linux validation must run on the installed Linux central node');
  const config = loadConfig();
  const api = await configuredLiveApi(config, process.env.LOOKOUT_ADMIN_TOKEN_FILE || '/etc/lookout/admin-token');
  const report = await runLiveLinuxValidation({ address, user, knownHostsFile, identityFile, api });
  console.log(JSON.stringify(report, null, 2));
  if (!report.passed) process.exitCode = 1;
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
