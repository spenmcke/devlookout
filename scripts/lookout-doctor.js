#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { loadConfig } = require('../src/config');
const { protectorFromEnvironment } = require('../src/security/data-protector');
const { runDoctor } = require('../src/operations/doctor');

async function main() {
  const filename = process.env.LOOKOUT_CONFIG ? path.resolve(process.env.LOOKOUT_CONFIG) : null;
  const report = await runDoctor({
    config: loadConfig({ filename }),
    protector: protectorFromEnvironment(),
    sensitiveFiles: { config: filename, masterKey: process.env.LOOKOUT_MASTER_KEY_FILE ? path.resolve(process.env.LOOKOUT_MASTER_KEY_FILE) : null }
  });
  console.log(JSON.stringify(report, null, 2));
  if (report.status === 'fail') process.exitCode = 1;
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
