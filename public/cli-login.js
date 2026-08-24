'use strict';

const requestId = new URLSearchParams(window.location.search).get('request');
const card = document.querySelector('.auth-card');
const title = document.querySelector('#cliTitle');
const message = document.querySelector('#cliMessage');
const status = document.querySelector('#cliStatus');
const approve = document.querySelector('#cliApprove');
const scope = document.querySelector('#cliScope');
const verification = document.querySelector('#cliVerification');
const verificationFields = document.querySelector('#cliVerificationFields');
const loginCommand = document.querySelector('#cliLoginCommand');
const copyCommand = document.querySelector('#cliCopyCommand');
const copyCommandLabel = document.querySelector('#cliCopyCommandLabel');

const EXPIRED_REQUEST_MESSAGE = 'This CLI login request is unavailable or expired.';
const EXPIRED_REQUEST_INSTRUCTION = 'This CLI login request is unavailable or expired. Please run lookout login again.';

copyCommand.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText('lookout login');
    copyCommandLabel.textContent = 'Copied';
  } catch {
    copyCommandLabel.textContent = 'Copy failed';
  }
});

async function initialize() {
  if (!/^cla_[A-Za-z0-9_-]{32}$/.test(requestId || '')) throw new Error('This CLI login request is invalid.');
  const session = await LookoutAuth.session();
  if (!session) {
    const next = `${window.location.pathname}${window.location.search}`;
    window.location.replace(`/signup?next=${encodeURIComponent(next)}`);
    return;
  }
  const response = await fetch(`/v1/cli-authorizations/${encodeURIComponent(requestId)}`, { headers: { Accept: 'application/json' }, cache: 'no-store' });
  if (!response.ok) throw new Error(EXPIRED_REQUEST_MESSAGE);
  const request = await response.json();
  const email = session.user?.email || session.email || 'your signed-in account';
  const vms = request.installation_scope?.vms || [];
  message.textContent = `Allow one Lookout deployment for ${email}? This permission expires at ${new Date(request.expires_at).toLocaleTimeString()}.`;
  scope.textContent = [`Selected VMs (${vms.length}):`, ...vms.map((vm) => `- ${vm.name || vm.id}: ${vm.address || 'address unavailable'}${vm.id === request.installation_scope?.central_vm_id ? ' (central)' : ''}`)].join('\n');
  scope.hidden = false;
  approve.hidden = false;
  approve.addEventListener('click', async () => {
    approve.disabled = true;
    status.textContent = 'Authorizing...';
    const headers = await LookoutAuth.authorizationHeaders();
    headers['Content-Type'] = 'application/json';
    const result = await fetch(`/v1/cli-authorizations/${encodeURIComponent(requestId)}/approve`, { method: 'POST', headers, body: JSON.stringify({ verification_code: verification.value }) });
    if (!result.ok) throw new Error('The CLI authorization could not be completed.');
    const body = await result.json();
    window.location.assign(body.redirect_uri);
  }, { once: true });
}

initialize().catch((error) => {
  const expired = error.message === EXPIRED_REQUEST_MESSAGE;
  approve.hidden = true;
  scope.hidden = true;
  verificationFields.hidden = true;
  title.textContent = expired ? 'Login session expired' : error.message;
  message.textContent = expired ? EXPIRED_REQUEST_INSTRUCTION : '';
  message.hidden = !expired;
  loginCommand.hidden = !expired;
  card.classList.toggle('cli-expired-card', expired);
  message.classList.toggle('cli-expired-message', expired);
  status.textContent = '';
});
