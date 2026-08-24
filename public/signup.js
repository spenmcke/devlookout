'use strict';

const config = window.__LOOKOUT_AUTH__ || {};
const configError = document.querySelector('#authConfigError');
const googleButton = document.querySelector('#googleButton');
const emailToggleButton = document.querySelector('#emailToggleButton');
const emailForm = document.querySelector('#emailForm');
const otpForm = document.querySelector('#otpForm');
const emailInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const emailSubmit = document.querySelector('#emailSubmit');
const otpInput = document.querySelector('#otp');
const otpEmail = document.querySelector('#otpEmail');
const resendButton = document.querySelector('#resendButton');
const authTitle = document.querySelector('#authTitle');
const authSubtitle = document.querySelector('#authSubtitle');
const authMessage = document.querySelector('#authMessage');
let pendingEmail = '';
let authClient = null;

function showMessage(message, isError = false) {
  authMessage.textContent = message;
  authMessage.classList.toggle('error', isError);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  const labelTarget = button.querySelector('[data-button-label]') || button;
  labelTarget.dataset.label ||= labelTarget.textContent;
  labelTarget.textContent = busy ? label : labelTarget.dataset.label;
}

function goToApp(session) {
  if (session && typeof LookoutAnalytics !== 'undefined') LookoutAnalytics.identify(session.user);
  const next = new URLSearchParams(window.location.search).get('next');
  const safeNext = typeof next === 'string' && /^\/cli-login\?request=cla_[A-Za-z0-9_-]{32}$/.test(next) ? next : '/';
  window.location.replace(safeNext);
}

function showOtp(email) {
  pendingEmail = email;
  otpEmail.textContent = email;
  emailForm.hidden = true;
  emailToggleButton.hidden = true;
  googleButton.hidden = true;
  document.querySelector('.auth-divider').hidden = true;
  otpForm.hidden = false;
  authTitle.textContent = 'Enter verification code';
  authSubtitle.textContent = '';
  otpInput.focus();
}

if (!config.configured || !window.supabase?.createClient) {
  configError.textContent = 'Authentication is not configured. Set LOOKOUT_SUPABASE_URL and LOOKOUT_SUPABASE_PUBLISHABLE_KEY on the Lookout server.';
  configError.hidden = false;
  googleButton.disabled = true;
  emailToggleButton.disabled = true;
  emailForm.querySelectorAll('input, button').forEach((element) => { element.disabled = true; });
} else {
  authClient = window.supabase.createClient(config.supabaseUrl, config.publishableKey, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
  });
  authClient.auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_IN' && session) goToApp(session);
  });
  authClient.auth.getSession().then(({ data }) => {
    if (data.session) goToApp(data.session);
  });
}

emailToggleButton.addEventListener('click', () => {
  emailToggleButton.hidden = true;
  emailForm.hidden = false;
  emailInput.focus();
});

googleButton.addEventListener('click', async () => {
  if (!authClient) return;
  setBusy(googleButton, true, 'Opening Google...');
  const { error } = await authClient.auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo: `${window.location.origin}${window.location.pathname}${window.location.search}` }
  });
  if (error) {
    showMessage(error.message, true);
    setBusy(googleButton, false);
  }
});

emailForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!authClient) return;
  const email = emailInput.value.trim();
  const password = passwordInput.value;
  setBusy(emailSubmit, true, 'Sending code...');
  showMessage('');
  const result = await authClient.auth.signUp({ email, password, options: { emailRedirectTo: `${window.location.origin}${window.location.pathname}${window.location.search}` } });
  setBusy(emailSubmit, false);
  if (result.error) return showMessage(result.error.message, true);
  if (result.data.session) return goToApp(result.data.session);
  showOtp(email);
});

otpForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!authClient) return;
  const button = document.querySelector('#otpSubmit');
  setBusy(button, true, 'Verifying...');
  showMessage('');
  const { data, error } = await authClient.auth.verifyOtp({ email: pendingEmail, token: otpInput.value.trim(), type: 'email' });
  setBusy(button, false);
  if (error) return showMessage(error.message, true);
  if (data.session) goToApp(data.session);
});

resendButton.addEventListener('click', async () => {
  if (!authClient || !pendingEmail) return;
  setBusy(resendButton, true, 'Sending...');
  const { error } = await authClient.auth.resend({ type: 'signup', email: pendingEmail, options: { emailRedirectTo: `${window.location.origin}${window.location.pathname}${window.location.search}` } });
  setBusy(resendButton, false);
  showMessage(error ? error.message : 'A new code is on its way.', Boolean(error));
});
