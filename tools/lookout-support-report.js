#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const DEFAULT_ORIGIN = 'https://app.devlookout.com';
const GITLEAKS_VERSION = '8.30.1';
const GITLEAKS_ASSETS = Object.freeze({
  'darwin-arm64': ['gitleaks_8.30.1_darwin_arm64.tar.gz', 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'],
  'darwin-x64': ['gitleaks_8.30.1_darwin_x64.tar.gz', 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'],
  'linux-arm64': ['gitleaks_8.30.1_linux_arm64.tar.gz', 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'],
  'linux-x64': ['gitleaks_8.30.1_linux_x64.tar.gz', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'],
  'win32-arm64': ['gitleaks_8.30.1_windows_arm64.zip', 'b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f'],
  'win32-x64': ['gitleaks_8.30.1_windows_x64.zip', 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e']
});

function fail(message) { throw new Error(message); }
function sleep(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }
function commandQuote(value) { return process.platform === 'win32' ? `'${String(value).replaceAll("'", "''")}'` : `'${String(value).replaceAll("'", "'\\''")}'`; }

async function privateDirectory(directory) {
  const target = path.resolve(directory);
  await fsp.mkdir(target, { recursive: true, mode: 0o700 });
  const stat = await fsp.lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('Support report state directory is unsafe');
  if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.geteuid?.())) fail('Support report state directory must be private and owned by the current user');
  return target;
}

async function readPrivate(filename, label, maximum = 64 * 1024) {
  const handle = await fsp.open(path.resolve(filename), fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum) fail(`${label} is invalid`);
    if (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || stat.uid !== process.geteuid?.())) fail(`${label} must be private and owned by the current user`);
    return handle.readFile('utf8');
  } finally { await handle.close(); }
}

async function writePrivate(filename, contents) {
  const target = path.resolve(filename);
  const temporary = `${target}.${process.pid}.${crypto.randomUUID()}.tmp`;
  await fsp.writeFile(temporary, contents, { mode: 0o600, flag: 'wx' });
  try { await fsp.rename(temporary, target); }
  finally { await fsp.rm(temporary, { force: true }); }
  return target;
}

async function request(url, options, attempts = 5) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(15000) });
      const text = await response.text();
      if (Buffer.byteLength(text) > 64 * 1024) fail('Lookout support response is too large');
      if (!response.ok) {
        const error = new Error(`Lookout support returned HTTP ${response.status}`);
        error.retryable = response.status === 429 || response.status >= 500;
        throw error;
      }
      try { return JSON.parse(text); } catch { fail('Lookout support returned invalid JSON'); }
    } catch (error) {
      lastError = error;
      if (error.retryable === false || attempt + 1 >= attempts) break;
      await sleep(Math.min(8000, 500 * (2 ** attempt)) + crypto.randomInt(0, 250));
    }
  }
  throw lastError;
}

async function survey({ origin, tokenFile, setupToken, stateRoot, submitCommand } = {}) {
  let requestBody;
  if (setupToken !== undefined) {
    if (!/^lst_[A-Za-z0-9_-]{43}$/.test(setupToken)) fail('Setup token is invalid');
    requestBody = { setup_token: setupToken };
  } else {
    const supportToken = (await readPrivate(tokenFile, 'Support token file', 256)).trim();
    if (!/^ldw_[A-Za-z0-9_-]{43}$/.test(supportToken)) fail('Support token file is invalid');
    requestBody = { support_token: supportToken };
  }
  const result = await request(new URL('/v1/setup-support/surveys', origin), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'lookout-support-report/1' },
    body: JSON.stringify(requestBody)
  });
  if (!/^diag_[A-Za-z0-9_-]{32}$/.test(result?.report_id || '') || !/^ldr_[A-Za-z0-9_-]{43}$/.test(result?.submission_token || '') || typeof result?.survey !== 'string') fail('Lookout support returned an invalid survey');
  const directory = await privateDirectory(path.join(stateRoot, result.report_id));
  const surveyFile = await writePrivate(path.join(directory, 'survey.txt'), result.survey);
  await writePrivate(path.join(directory, 'submission.json'), `${JSON.stringify({
    schemaVersion: 1,
    reportId: result.report_id,
    submissionToken: result.submission_token,
    idempotencyKey: crypto.randomBytes(24).toString('base64url'),
    origin: origin.toString()
  })}\n`);
  process.stdout.write(`Support survey created at ${surveyFile}\n`);
  process.stdout.write('Complete every section in that file, then run the submit operation:\n');
  process.stdout.write(`${submitCommand || `node ${commandQuote(path.resolve(process.argv[1]))} submit`} ${commandQuote(surveyFile)}\n`);
  return { reportId: result.report_id, surveyFile };
}

async function downloadGitleaks(stateRoot) {
  const override = process.env.LOOKOUT_GITLEAKS;
  if (override) return path.resolve(override);
  const asset = GITLEAKS_ASSETS[`${process.platform}-${process.arch}`];
  if (!asset) fail(`Gitleaks is not available for ${process.platform}/${process.arch}`);
  const directory = await privateDirectory(path.join(stateRoot, 'tools', `gitleaks-${GITLEAKS_VERSION}`));
  const executable = path.join(directory, process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks');
  try {
    const stat = await fsp.lstat(executable);
    if (stat.isFile() && !stat.isSymbolicLink()) return executable;
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const [name, digest] = asset;
  const response = await fetch(`https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${name}`, { redirect: 'follow', signal: AbortSignal.timeout(60000) });
  if (!response.ok) fail(`Gitleaks download returned HTTP ${response.status}`);
  const archive = Buffer.from(await response.arrayBuffer());
  if (archive.length < 1024 || archive.length > 32 * 1024 * 1024 || crypto.createHash('sha256').update(archive).digest('hex') !== digest) fail('Gitleaks download failed checksum verification');
  const archiveFile = path.join(directory, name);
  await fsp.writeFile(archiveFile, archive, { mode: 0o600, flag: 'wx' });
  try {
    const extraction = process.platform === 'win32'
      ? spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', 'Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force', archiveFile, directory], { stdio: 'ignore', timeout: 60000 })
      : spawnSync('tar', ['-xzf', archiveFile, '-C', directory, 'gitleaks'], { stdio: 'ignore', timeout: 60000 });
    if (extraction.error || extraction.status !== 0) fail('Gitleaks archive extraction failed');
    const stat = await fsp.lstat(executable);
    if (!stat.isFile() || stat.isSymbolicLink()) fail('Gitleaks executable is invalid');
    if (process.platform !== 'win32') await fsp.chmod(executable, 0o700);
    return executable;
  } finally { await fsp.rm(archiveFile, { force: true }); }
}

async function redactWithGitleaks(text, stateRoot) {
  const gitleaks = await downloadGitleaks(stateRoot);
  const work = await privateDirectory(path.join(stateRoot, 'scan'));
  const report = path.join(work, `findings-${crypto.randomUUID()}.json`);
  try {
    await fsp.writeFile(report, '', { mode: 0o600, flag: 'wx' });
    const scan = spawnSync(gitleaks, ['stdin', '--no-banner', '--no-color', '--report-format', 'json', '--report-path', report], { input: text, encoding: 'utf8', stdio: ['pipe', 'ignore', 'ignore'], timeout: 30000, maxBuffer: 1024 * 1024 });
    if (scan.error || ![0, 1].includes(scan.status)) fail('Gitleaks could not scan the support survey');
    if (scan.status === 0) return text;
    const reportStat = await fsp.lstat(report);
    if (!reportStat.isFile() || reportStat.isSymbolicLink()) fail('Gitleaks findings file is invalid');
    if (process.platform !== 'win32') await fsp.chmod(report, 0o600);
    const raw = await readPrivate(report, 'Gitleaks findings', 1024 * 1024);
    let findings;
    try { findings = JSON.parse(raw); } catch { fail('Gitleaks returned invalid findings'); }
    if (!Array.isArray(findings) || !findings.length) fail('Gitleaks reported an unreadable secret finding');
    let sanitized = text;
    for (const finding of findings) {
      const secret = finding?.Secret;
      const rule = String(finding?.RuleID || 'secret').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 64) || 'secret';
      if (typeof secret !== 'string' || !secret) fail('Gitleaks returned an invalid secret finding');
      sanitized = sanitized.split(secret).join(`[REDACTED:gitleaks:${rule}]`);
    }
    const verify = spawnSync(gitleaks, ['stdin', '--no-banner', '--no-color', '--redact=100'], { input: sanitized, encoding: 'utf8', stdio: ['pipe', 'ignore', 'ignore'], timeout: 30000, maxBuffer: 1024 * 1024 });
    if (verify.error || verify.status !== 0) fail('The support survey still contains a possible secret after filtering');
    return sanitized;
  } finally { await fsp.rm(report, { force: true }); }
}

async function submit({ surveyFile, stateRoot }) {
  const surveyPath = path.resolve(surveyFile);
  const directory = path.dirname(surveyPath);
  const text = await readPrivate(surveyPath, 'Support survey', 32 * 1024);
  const metadataText = await readPrivate(path.join(directory, 'submission.json'), 'Support report submission state', 4096);
  let metadata;
  try { metadata = JSON.parse(metadataText); } catch { fail('Support report submission state is invalid'); }
  if (metadata.schemaVersion !== 1 || !/^diag_[A-Za-z0-9_-]{32}$/.test(metadata.reportId || '') || !/^ldr_[A-Za-z0-9_-]{43}$/.test(metadata.submissionToken || '') || !/^[A-Za-z0-9_-]{16,128}$/.test(metadata.idempotencyKey || '')) fail('Support report submission state is invalid');
  let reportOrigin;
  try { reportOrigin = new URL(metadata.origin); } catch { fail('Support report submission origin is invalid'); }
  const loopback = process.env.LOOKOUT_ALLOW_INSECURE_LOOPBACK === '1' && reportOrigin.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(reportOrigin.hostname);
  if ((!loopback && reportOrigin.protocol !== 'https:') || reportOrigin.username || reportOrigin.password || reportOrigin.search || reportOrigin.hash || (reportOrigin.pathname !== '/' && reportOrigin.pathname !== '')) fail('Support report submission origin is invalid');
  const sanitized = await redactWithGitleaks(text, stateRoot);
  const result = await request(new URL(`/v1/setup-support/surveys/${metadata.reportId}`, reportOrigin), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${metadata.submissionToken}`,
      'Content-Type': 'text/plain; charset=utf-8',
      Accept: 'application/json',
      'Idempotency-Key': metadata.idempotencyKey,
      'User-Agent': 'lookout-support-report/1'
    },
    body: sanitized
  });
  if (result?.accepted !== true || result.report_id !== metadata.reportId) fail('Lookout support did not acknowledge the report');
  await fsp.rm(path.join(directory, 'submission.json'), { force: true });
  await fsp.rm(surveyPath, { force: true });
  process.stdout.write(`Support report ${metadata.reportId} was received. Tell the user what failed and that the Lookout team will reach out to help.\n`);
  return { accepted: true, reportId: metadata.reportId };
}

async function main() {
  if (!['survey', 'submit'].includes(process.argv[2]) || !process.argv[3] || process.argv.length !== 4) fail('Usage: lookout-support-report.js survey SUPPORT_TOKEN_FILE | submit SURVEY_FILE');
  const origin = new URL(process.env.LOOKOUT_SETUP_ORIGIN || DEFAULT_ORIGIN);
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.search || origin.hash) fail('Lookout support origin must be an HTTPS origin');
  const stateRoot = await privateDirectory(process.env.LOOKOUT_SUPPORT_STATE_DIR || path.join(os.homedir(), '.lookout', 'support'));
  if (process.argv[2] === 'survey') await survey({ origin, tokenFile: process.argv[3], stateRoot });
  else await submit({ surveyFile: process.argv[3], stateRoot });
}

if (require.main === module) main().catch((error) => { process.stderr.write(`lookout-support: ${error.message}\n`); process.exitCode = 1; });

module.exports = { survey, submit, redactWithGitleaks, downloadGitleaks, privateDirectory, readPrivate };
