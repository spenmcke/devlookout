#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { signManifest } = require('../src/update/manifest');

const [payloadFile, outputFile] = process.argv.slice(2);
if (!payloadFile || !outputFile) throw new Error('Usage: sign-update-manifest <payload.json> <signed-manifest.json>');
const keyId = process.env.LOOKOUT_UPDATE_SIGNING_KEY_ID;
const privateKeyPem = process.env.LOOKOUT_UPDATE_SIGNING_PRIVATE_KEY_PEM;
if (!keyId || !privateKeyPem) throw new Error('Update signing environment is incomplete');
const payload = JSON.parse(fs.readFileSync(path.resolve(payloadFile), 'utf8'));
const signed = signManifest(payload, { keyId, privateKeyPem });
fs.writeFileSync(path.resolve(outputFile), `${JSON.stringify(signed)}\n`, { mode: 0o600, flag: 'wx' });
