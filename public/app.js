const authModal = document.querySelector('#auth-modal');
const bookingModal = document.querySelector('#booking-modal');
const securityModal = document.querySelector('#security-modal');
const loginForm = document.querySelector('#login-form');
const registerForm = document.querySelector('#register-form');
const codeForm = document.querySelector('#code-form');
const authMessage = document.querySelector('#form-message');
const bookingMessage = document.querySelector('#booking-message');
const securityMessage = document.querySelector('#security-message');
let currentUser = null;
let csrfToken = '';
let authChallenge = '';
let authMode = 'login';
let toastTimer;

function showToast(message) {
  const toast = document.querySelector('#toast');
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 3200);
}

document.querySelector('#sign-out').addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', { method: 'POST', body: '{}' });
    currentUser = null;
    csrfToken = '';
    document.querySelector('#profile-name').textContent = 'Sarah M.';
    document.querySelector('#profile-avatar').textContent = 'S';
    document.querySelector('#greeting').firstChild.textContent = 'Good morning, Sarah ';
    document.querySelector('#sign-out').classList.add('hidden');
    document.querySelector('#appointment-list').replaceChildren();
    document.querySelector('#appointment-list').classList.add('hidden');
    document.querySelector('#empty-appointments').classList.remove('hidden');
    document.querySelector('.page-wrap').classList.remove('admin-view');
    document.querySelector('#admin-panel').classList.add('hidden');
    document.querySelectorAll('[data-view="administration"]').forEach((item) => item.classList.add('hidden'));
    document.querySelector('.mobile-nav').classList.remove('admin-enabled');
    securityModal.close();
    showToast('You have signed out securely.');
  } catch (error) {
    setMessage(securityMessage, error.message, true);
  }
});

function setMessage(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle('error', isError);
}

async function api(url, options = {}) {
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers };
  if (csrfToken && options.method && !['GET', 'HEAD'].includes(options.method)) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || payload.message || 'Something went wrong. Please try again.');
  return payload;
}

function showAuth(mode = 'login') {
  authMode = mode;
  authChallenge = '';
  delete codeForm.dataset.verification;
  codeForm.querySelector('button').innerHTML = 'Verify and sign in <span>→</span>';
  document.querySelector('#resend-code').classList.add('hidden');
  loginForm.reset();
  registerForm.reset();
  codeForm.reset();
  loginForm.classList.toggle('hidden', mode !== 'login');
  registerForm.classList.toggle('hidden', mode !== 'register');
  codeForm.classList.add('hidden');
  document.querySelector('#auth-title').textContent = mode === 'register' ? 'Create your account' : 'Sign in to your account';
  document.querySelector('#auth-description').textContent = mode === 'register'
    ? 'Join Harbor Health for a simpler way to manage your care.'
    : 'Your care is right where you left it.';
  document.querySelector('#auth-toggle').classList.toggle('hidden', mode === 'code');
  document.querySelector('#show-register').textContent = mode === 'register' ? 'Sign in' : 'Create an account';
  document.querySelector('#auth-toggle').firstChild.textContent = mode === 'register' ? 'Already with Harbor? ' : 'New to Harbor? ';
  authModal.showModal();
  setMessage(authMessage, '');
}

document.querySelector('#open-account').addEventListener('click', () => {
  if (!currentUser) return showAuth();
  securityModal.showModal();
});

document.querySelector('#show-register').addEventListener('click', () => {
  showAuth(authMode === 'register' ? 'login' : 'register');
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(loginForm));
  try {
    const response = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(data) });
    authChallenge = response.challenge;
    loginForm.classList.add('hidden');
    codeForm.classList.remove('hidden');
    document.querySelector('#auth-title').textContent = 'One last security check';
    document.querySelector('#auth-description').textContent = response.message;
    document.querySelector('#code-prompt').firstChild.textContent = response.method === 'email'
      ? 'Code sent to your email'
      : 'Authenticator app code';
    document.querySelector('#auth-toggle').classList.add('hidden');
    setMessage(authMessage, '');
    codeForm.elements.code.focus();
  } catch (error) {
    setMessage(authMessage, error.message, true);
  }
});

codeForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (codeForm.dataset.verification === 'true') {
    try {
      const response = await api('/api/auth/verify-email', {
        method: 'POST',
        body: JSON.stringify({ challenge: authChallenge, code: codeForm.elements.code.value })
      });
      delete codeForm.dataset.verification;
      codeForm.querySelector('button').innerHTML = 'Verify and sign in <span>→</span>';
      document.querySelector('#resend-code').classList.add('hidden');
      if (response.user) signIn(response);
      else {
        authModal.close();
        showToast(response.message);
      }
    } catch (error) {
      setMessage(authMessage, error.message, true);
    }
    return;
  }
  try {
    const response = await api('/api/auth/complete-login', {
      method: 'POST',
      body: JSON.stringify({ challenge: authChallenge, code: codeForm.elements.code.value })
    });
    signIn(response);
  } catch (error) {
    setMessage(authMessage, error.message, true);
  }
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const response = await api('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(Object.fromEntries(new FormData(registerForm)))
    });
    authChallenge = response.challenge;
    registerForm.classList.add('hidden');
    codeForm.classList.remove('hidden');
    document.querySelector('#auth-title').textContent = 'Check your email';
    document.querySelector('#auth-description').textContent = response.message;
    document.querySelector('#code-prompt').firstChild.textContent = 'Email verification code';
    document.querySelector('#auth-toggle').classList.add('hidden');
    codeForm.dataset.verification = 'true';
    codeForm.querySelector('button').textContent = 'Verify email and continue';
    document.querySelector('#resend-code').classList.remove('hidden');
    setMessage(authMessage, '');
    codeForm.elements.code.focus();
  } catch (error) {
    setMessage(authMessage, error.message, true);
  }
});

document.querySelector('#resend-code').addEventListener('click', async () => {
  try {
    const response = await api('/api/auth/resend-verification', {
      method: 'POST',
      body: JSON.stringify({ challenge: authChallenge })
    });
    authChallenge = response.challenge;
    setMessage(authMessage, response.message);
  } catch (error) {
    setMessage(authMessage, error.message, true);
  }
});

function signIn(response) {
  currentUser = response.user;
  csrfToken = response.csrfToken;
  displayUser(currentUser);
  authModal.close();
  showToast(`Welcome${currentUser.name ? `, ${currentUser.name.split(' ')[0]}` : ''}. You're securely signed in.`);
  loadAppointments();
}

function displayUser(user) {
  const firstName = user.name.split(' ')[0];
  document.querySelector('#profile-name').textContent = user.name;
  document.querySelector('#profile-avatar').textContent = firstName.charAt(0).toUpperCase();
  document.querySelector('#greeting').firstChild.textContent = `Good morning, ${firstName} `;
  document.querySelector('#sign-out').classList.remove('hidden');
  const isAdmin = ['admin', 'super_admin'].includes(user.role);
  document.querySelectorAll('[data-view="administration"]').forEach((item) => item.classList.toggle('hidden', !isAdmin));
  document.querySelector('.mobile-nav').classList.toggle('admin-enabled', isAdmin);
}

document.querySelectorAll('[data-open-booking]').forEach((button) => button.addEventListener('click', async () => {
  if (!currentUser) {
    showAuth();
    setMessage(authMessage, 'Sign in or create an account to request an appointment.');
    return;
  }
  bookingModal.showModal();
  try {
    const { doctors } = await api('/api/doctors');
    const select = document.querySelector('#booking-form select[name="doctorId"]');
    select.replaceChildren(new Option('Choose a doctor', ''));
    doctors.forEach((doctor) => select.add(new Option(doctor.name, doctor.id)));
  } catch (error) {
    setMessage(bookingMessage, error.message, true);
  }
}));

document.querySelector('#booking-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const form = event.currentTarget;
    const values = Object.fromEntries(new FormData(form));
    const response = await api('/api/appointments', {
      method: 'POST',
      body: JSON.stringify({ ...values, startsAt: new Date(values.startsAt).toISOString() })
    });
    setMessage(bookingMessage, 'Your appointment request has been sent. Your care team will be in touch.');
    form.reset();
    showToast(`Appointment requested for ${new Date(response.appointment.starts_at).toLocaleDateString()}.`);
    await loadAppointments();
  } catch (error) {
    setMessage(bookingMessage, error.message, true);
  }
});

async function loadAppointments() {
  if (!currentUser) return;
  try {
    const { appointments } = await api('/api/appointments');
    if (!appointments.length) {
      document.querySelector('#appointment-list').classList.add('hidden');
      document.querySelector('#empty-appointments').classList.remove('hidden');
      return;
    }
    document.querySelector('#empty-appointments').classList.add('hidden');
    const list = document.querySelector('#appointment-list');
    list.classList.remove('hidden');
    list.replaceChildren();
    appointments.slice(0, 3).forEach((appointment) => {
      const date = new Date(appointment.starts_at);
      const article = document.createElement('article');
      article.className = 'appointment-item';
      const tile = document.createElement('div');
      tile.className = 'date-tile date-tile-green';
      const month = document.createElement('span');
      month.textContent = date.toLocaleString(undefined, { month: 'short' }).toUpperCase();
      const day = document.createElement('strong');
      day.textContent = String(date.getDate()).padStart(2, '0');
      tile.append(month, day);
      const info = document.createElement('div');
      info.className = 'appointment-info';
      const title = document.createElement('strong');
      title.textContent = appointment.reason;
      const doctor = document.createElement('span');
      doctor.textContent = `Dr. ${appointment.doctor_name}`;
      const time = document.createElement('span');
      time.textContent = `${date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })} · ${appointment.status}`;
      info.append(title, doctor, time);
      article.append(tile, info);
      list.append(article);
    });
  } catch {
    showToast('Your appointment list could not be refreshed just now.');
  }
}

async function loadAdminPanel() {
  if (!currentUser || !['admin', 'super_admin'].includes(currentUser.role)) return;
  const status = document.querySelector('#admin-status');
  try {
    const { users } = await api('/api/admin/users');
    const table = document.querySelector('#admin-users');
    table.replaceChildren();
    users.forEach((user) => {
      const row = document.createElement('tr');
      const person = document.createElement('td');
      const name = document.createElement('strong');
      name.textContent = user.name;
      const email = document.createElement('span');
      email.textContent = user.email;
      person.append(name, email);

      const roleCell = document.createElement('td');
      if (currentUser.role === 'super_admin' && !user.deleted_at && user.id !== currentUser.id) {
        const role = document.createElement('select');
        role.className = 'admin-role';
        role.setAttribute('aria-label', `Role for ${user.name}`);
        role.dataset.userRole = user.id;
        ['patient', 'doctor', 'admin', 'super_admin'].forEach((value) => {
          const option = new Option(value.replace('_', ' '), value, false, value === user.role);
          role.add(option);
        });
        roleCell.append(role);
      } else {
        roleCell.textContent = user.role.replace('_', ' ');
      }

      const state = document.createElement('td');
      if (user.deleted_at) state.textContent = 'Deactivated';
      else if (user.role === 'doctor' && !user.approved_at) state.textContent = 'Awaiting approval';
      else state.textContent = 'Active';

      const action = document.createElement('td');
      if (!user.deleted_at && user.role === 'doctor' && !user.approved_at) {
        const approve = document.createElement('button');
        approve.type = 'button';
        approve.className = 'admin-action';
        approve.textContent = 'Approve';
        approve.dataset.adminAction = 'approve';
        approve.dataset.userId = user.id;
        action.append(approve);
      } else if (!user.deleted_at && !['admin', 'super_admin'].includes(user.role)) {
        const deactivate = document.createElement('button');
        deactivate.type = 'button';
        deactivate.className = 'admin-action admin-action-muted';
        deactivate.textContent = 'Deactivate';
        deactivate.dataset.adminAction = 'deactivate';
        deactivate.dataset.userId = user.id;
        action.append(deactivate);
      }
      row.append(person, roleCell, state, action);
      table.append(row);
    });
    const { entries } = await api('/api/admin/audit');
    const auditList = document.querySelector('#audit-list');
    auditList.replaceChildren();
    entries.slice(0, 8).forEach((entry) => {
      const item = document.createElement('div');
      item.className = 'audit-item';
      const eventName = document.createElement('strong');
      eventName.textContent = entry.action.replaceAll('.', ' ');
      const eventTime = document.createElement('span');
      eventTime.textContent = new Date(entry.created_at).toLocaleString();
      item.append(eventName, eventTime);
      auditList.append(item);
    });
    status.textContent = '';
    status.classList.remove('error');
  } catch (error) {
    status.textContent = error.message;
    status.classList.add('error');
  }
}

document.querySelector('#admin-users').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-admin-action]');
  if (!button) return;
  if (button.dataset.adminAction === 'deactivate' &&
      !confirm('Deactivate this account? Its records will be retained for audit.')) return;
  const path = button.dataset.adminAction === 'approve'
    ? `/api/admin/users/${button.dataset.userId}/approve`
    : `/api/admin/users/${button.dataset.userId}`;
  try {
    await api(path, {
      method: button.dataset.adminAction === 'approve' ? 'PATCH' : 'DELETE',
      body: button.dataset.adminAction === 'approve' ? '{}' : undefined
    });
    await loadAdminPanel();
  } catch (error) {
    const status = document.querySelector('#admin-status');
    status.textContent = error.message;
    status.classList.add('error');
  }
});

document.querySelector('#admin-users').addEventListener('change', async (event) => {
  const select = event.target.closest('[data-user-role]');
  if (!select) return;
  try {
    await api(`/api/admin/users/${select.dataset.userRole}/role`, {
      method: 'PATCH',
      body: JSON.stringify({ role: select.value })
    });
    showToast('Account role updated.');
    await loadAdminPanel();
  } catch (error) {
    const status = document.querySelector('#admin-status');
    status.textContent = error.message;
    status.classList.add('error');
  }
});

document.querySelector('#refresh-admin').addEventListener('click', loadAdminPanel);

document.querySelector('#start-totp').addEventListener('click', async () => {
  try {
    const result = await api('/api/auth/totp/setup', { method: 'POST', body: '{}' });
    document.querySelector('#totp-qr').src = result.qrCode;
    document.querySelector('#qr-panel').classList.remove('hidden');
    setMessage(securityMessage, result.message);
  } catch (error) {
    setMessage(securityMessage, error.message, true);
  }
});

document.querySelector('#totp-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const response = await api('/api/auth/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({ code: event.currentTarget.elements.code.value })
    });
    setMessage(securityMessage, response.message);
    document.querySelector('#qr-panel').classList.add('hidden');
  } catch (error) {
    setMessage(securityMessage, error.message, true);
  }
});

document.querySelector('#dose-button').addEventListener('click', (event) => {
  event.currentTarget.textContent = 'Taken ✓';
  event.currentTarget.classList.add('taken');
  event.currentTarget.disabled = true;
  showToast('Medication marked as taken. Well done!');
});

const navLabels = {
  overview: 'Overview', appointments: 'Appointments', 'care-team': 'My care team',
  records: 'Health records', messages: 'Messages', medications: 'Medications', settings: 'Settings',
  administration: 'Administration'
};
document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {
  const view = button.dataset.view;
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
  document.querySelectorAll('.mobile-nav button').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
  document.querySelector('#current-crumb').textContent = navLabels[view] || 'Overview';
  const adminView = view === 'administration' && currentUser && ['admin', 'super_admin'].includes(currentUser.role);
  document.querySelector('.page-wrap').classList.toggle('admin-view', Boolean(adminView));
  document.querySelector('#admin-panel').classList.toggle('hidden', !adminView);
  if (adminView) loadAdminPanel();
  else if (view !== 'overview') showToast(`${navLabels[view]} will be available as your care team enables it.`);
}));

document.querySelector('#dose-button').setAttribute('aria-label', 'Mark evening medication as taken');
document.querySelector('#booking-form input[name="startsAt"]').min = new Date(Date.now() + 60 * 60 * 1000).toISOString().slice(0, 16);
const sampleDates = [4, 13].map((daysAhead) => {
  const date = new Date();
  date.setDate(date.getDate() + daysAhead);
  return date;
});
document.querySelector('#next-visit-date').textContent = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric'
}).format(sampleDates[0]);
document.querySelectorAll('#appointment-list .date-tile').forEach((tile, index) => {
  tile.querySelector('span').textContent = sampleDates[index].toLocaleString(undefined, { month: 'short' }).toUpperCase();
  tile.querySelector('strong').textContent = String(sampleDates[index].getDate()).padStart(2, '0');
});
document.querySelector('#today-label').textContent = new Intl.DateTimeFormat(undefined, {
  weekday: 'long', month: 'long', day: 'numeric', year: 'numeric'
}).format(new Date()).toUpperCase();
api('/api/me')
  .then((response) => {
    currentUser = response.user;
    csrfToken = response.csrfToken;
    displayUser(currentUser);
    loadAppointments();
  })
  .catch(() => {});
