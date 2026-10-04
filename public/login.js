'use strict';

// Client-side validation is for user experience only. An attacker can skip it
// entirely (curl, Burp, devtools), so server.js repeats every check.

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const MAX_EMAIL_LENGTH = 254;

/**
 * Required check: email contains "@" and password is at least 8 characters.
 * Returns an object of field -> error message (empty object means valid).
 */
function validateLogin(email, password) {
  const errors = {};

  if (typeof email !== 'string' || !email.includes('@')) {
    errors.email = 'Email must contain an "@" symbol.';
  } else if (email.length > MAX_EMAIL_LENGTH) {
    errors.email = 'Email is too long.';
  } else if (!/^[^\s@<>"'`]+@[^\s@<>"'`]+\.[^\s@<>"'`]+$/.test(email)) {
    errors.email = 'Please enter a valid email address.';
  }

  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    errors.password = `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  } else if (password.length > MAX_PASSWORD_LENGTH) {
    errors.password = `Password must be at most ${MAX_PASSWORD_LENGTH} characters.`;
  }

  return errors;
}

// Always write untrusted text with textContent, never innerHTML, so any
// markup in a message or email is rendered as text instead of executed (XSS).
function showFieldError(field, message) {
  const input = document.getElementById(field);
  const errorEl = document.getElementById(`${field}-error`);
  errorEl.textContent = message || '';
  input.setAttribute('aria-invalid', message ? 'true' : 'false');
}

function setStatus(message, ok) {
  const status = document.getElementById('form-status');
  status.textContent = message;
  status.className = ok ? 'ok' : 'fail';
}

function showAccount(email) {
  document.getElementById('account-email').textContent = email;
  document.getElementById('login-view').hidden = true;
  document.getElementById('account-view').hidden = false;
}

function showLogin() {
  document.getElementById('account-view').hidden = true;
  document.getElementById('login-view').hidden = false;
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const submitBtn = document.getElementById('submit-btn');

  // If the session cookie is still valid, skip the login form.
  fetch('/api/me', { credentials: 'same-origin' })
    .then((r) => (r.ok ? r.json() : null))
    .then((user) => { if (user) showAccount(user.email); })
    .catch(() => {});

  // Live feedback as the user leaves each field.
  emailInput.addEventListener('blur', () => {
    showFieldError('email', validateLogin(emailInput.value.trim(), passwordInput.value).email);
  });
  passwordInput.addEventListener('blur', () => {
    showFieldError('password', validateLogin(emailInput.value.trim(), passwordInput.value).password);
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    setStatus('', true);

    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const errors = validateLogin(email, password);

    showFieldError('email', errors.email);
    showFieldError('password', errors.password);
    if (Object.keys(errors).length > 0) return;

    submitBtn.disabled = true;
    try {
      // The session token comes back as an HttpOnly cookie, so this script
      // (or an injected one) can never read it. Nothing goes in localStorage.
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ email, password })
      });

      const data = await response.json().catch(() => ({}));

      if (response.ok) {
        form.reset();
        showAccount(data.email);
      } else if (data.errors) {
        showFieldError('email', data.errors.email);
        showFieldError('password', data.errors.password);
        setStatus('Please fix the errors above.', false);
      } else {
        setStatus(data.message || 'Login failed. Please try again.', false);
      }
    } catch {
      setStatus('Network error. Please try again.', false);
    } finally {
      passwordInput.value = '';
      submitBtn.disabled = false;
    }
  });

  document.getElementById('logout-btn').addEventListener('click', async () => {
    await fetch('/api/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin'
    }).catch(() => {});
    showLogin();
    setStatus('You have been logged out.', true);
  });
});
