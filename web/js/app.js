/* ROXEXPay Dashboard — app.js */

// ─── State ─────────────────────────────────────────────────────────
let merchant = JSON.parse(localStorage.getItem('roxexpay_merchant') || 'null');
let payments = JSON.parse(localStorage.getItem('roxexpay_payments') || '[]');

const API_BASE = window.location.origin;

// ─── Init ──────────────────────────────────────────────────────────
(function init() {
  // Check if URL has #signup hash
  if (window.location.hash === '#signup') showSignup();

  if (merchant) {
    enterDashboard();
  }
})();

// ─── Auth ──────────────────────────────────────────────────────────
function showLogin() {
  document.getElementById('login-form').style.display = 'block';
  document.getElementById('signup-form').style.display = 'none';
}

function showSignup() {
  document.getElementById('login-form').style.display = 'none';
  document.getElementById('signup-form').style.display = 'block';
}

function handleLogin() {
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  if (!email || !password) return alert('Please enter email and password.');

  // Check localStorage for registered merchants
  const stored = JSON.parse(localStorage.getItem('roxexpay_merchants') || '{}');
  const account = stored[email];

  if (!account || account.password !== password) {
    return alert('Invalid email or password.');
  }

  merchant = account;
  localStorage.setItem('roxexpay_merchant', JSON.stringify(merchant));
  payments = JSON.parse(localStorage.getItem('roxexpay_payments_' + merchant.id) || '[]');
  enterDashboard();
}

function handleSignup() {
  const name = document.getElementById('signup-name').value.trim();
  const email = document.getElementById('signup-email').value.trim();
  const password = document.getElementById('signup-password').value;
  const country = document.getElementById('signup-country').value;

  if (!name) return alert('Please enter your business name.');
  if (!email) return alert('Please enter your email.');
  if (password.length < 8) return alert('Password must be at least 8 characters.');
  if (!country) return alert('Please select your country.');

  // Check if already registered
  const stored = JSON.parse(localStorage.getItem('roxexpay_merchants') || '{}');
  if (stored[email]) return alert('An account with this email already exists.');

  // Generate merchant
  const id = 'merch_' + randomHex(12);
  merchant = {
    id: id,
    name: name,
    email: email,
    password: password,
    country: country,
    currency: 'EUR',
    webhook: '',
    keys: {
      secret: 'sk_live_' + randomHex(16),
      public: 'pk_live_' + randomHex(16)
    },
    balance: 0,
    created: Date.now()
  };

  stored[email] = merchant;
  localStorage.setItem('roxexpay_merchants', JSON.stringify(stored));
  localStorage.setItem('roxexpay_merchant', JSON.stringify(merchant));
  payments = [];
  localStorage.setItem('roxexpay_payments_' + merchant.id, '[]');
  enterDashboard();
}

function logout() {
  merchant = null;
  payments = [];
  localStorage.removeItem('roxexpay_merchant');
  document.getElementById('auth-screen').style.display = 'block';
  document.getElementById('dashboard-screen').style.display = 'none';
  document.getElementById('nav-logout').style.display = 'none';
  document.getElementById('nav-user').textContent = '';
  showLogin();
}

// ─── Dashboard Entry ───────────────────────────────────────────────
function enterDashboard() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('dashboard-screen').style.display = 'block';
  document.getElementById('nav-logout').style.display = 'inline-block';
  document.getElementById('nav-user').textContent = merchant.name;

  // Load payments for this merchant
  payments = JSON.parse(localStorage.getItem('roxexpay_payments_' + merchant.id) || '[]');

  updateDashboard();
  showSection('overview');
  loadSettings();
  loadApiKeys();
}

// ─── Navigation ────────────────────────────────────────────────────
function showSection(name) {
  const sections = ['overview', 'payments', 'pos', 'api-keys', 'settings'];
  sections.forEach(function(s) {
    const el = document.getElementById('section-' + s);
    if (el) el.style.display = s === name ? 'block' : 'none';
  });

  // Update sidebar active state
  const links = document.querySelectorAll('.dash-sidebar a');
  links.forEach(function(a, i) {
    a.classList.toggle('active', sections[i] === name);
  });
}

// ─── Dashboard Data ────────────────────────────────────────────────
function updateDashboard() {
  const balance = payments.reduce(function(sum, p) {
    return p.status === 'succeeded' ? sum + p.net : sum;
  }, 0);

  const today = new Date().toDateString();
  const todayRevenue = payments.reduce(function(sum, p) {
    return (p.status === 'succeeded' && new Date(p.created).toDateString() === today)
      ? sum + p.amount : sum;
  }, 0);

  const totalSaved = payments.reduce(function(sum, p) {
    return p.status === 'succeeded' ? sum + p.saved : sum;
  }, 0);

  const successCount = payments.filter(function(p) { return p.status === 'succeeded'; }).length;

  document.getElementById('dash-balance').textContent = formatMoney(balance);
  document.getElementById('dash-today').textContent = formatMoney(todayRevenue);
  document.getElementById('dash-today-change').textContent = successCount > 0 ? successCount + ' today' : '';
  document.getElementById('dash-txcount').textContent = payments.length;
  document.getElementById('dash-saved').textContent = formatMoney(totalSaved);

  renderRecentPayments();
  renderAllPayments();
}

function renderRecentPayments() {
  const tbody = document.getElementById('recent-payments-body');
  if (payments.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);padding:40px">No payments yet. Integrate the API to start receiving payments.</td></tr>';
    return;
  }

  const recent = payments.slice(-5).reverse();
  tbody.innerHTML = recent.map(function(p) {
    return '<tr>' +
      '<td style="font-family:monospace;font-size:13px">' + p.id + '</td>' +
      '<td><strong>' + formatMoney(p.amount) + '</strong></td>' +
      '<td style="color:var(--text-light)">' + formatMoney(p.fee) + '</td>' +
      '<td>' + statusBadge(p.status) + '</td>' +
      '<td>' + (p.description || '—') + '</td>' +
      '<td style="color:var(--text-light)">' + timeAgo(p.created) + '</td>' +
      '</tr>';
  }).join('');
}

function renderAllPayments() {
  const tbody = document.getElementById('all-payments-body');
  if (payments.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-light);padding:40px">No payments yet.</td></tr>';
    return;
  }

  const sorted = payments.slice().reverse();
  tbody.innerHTML = sorted.map(function(p) {
    const stripeFee = Math.round(p.amount * 0.029) + 30;
    return '<tr>' +
      '<td style="font-family:monospace;font-size:13px">' + p.id + '</td>' +
      '<td><strong>' + formatMoney(p.amount) + '</strong></td>' +
      '<td>' + p.currency + '</td>' +
      '<td style="color:var(--text-light)">' + formatMoney(p.fee) + '</td>' +
      '<td><strong>' + formatMoney(p.net) + '</strong></td>' +
      '<td style="color:var(--danger);text-decoration:line-through">' + formatMoney(stripeFee) + '</td>' +
      '<td style="color:var(--success);font-weight:600">' + formatMoney(p.saved) + '</td>' +
      '<td>' + statusBadge(p.status) + '</td>' +
      '</tr>';
  }).join('');
}

// ─── Payments ──────────────────────────────────────────────────────
function createTestPayment() {
  const amounts = [500, 1000, 1500, 2000, 2500, 5000, 7500, 10000, 15000, 25000];
  const descriptions = ['Order #' + Math.floor(Math.random() * 9000 + 1000), 'Subscription renewal', 'Product purchase', 'Service fee', 'Invoice payment', 'Monthly plan', 'Premium upgrade'];
  const amount = amounts[Math.floor(Math.random() * amounts.length)];
  const desc = descriptions[Math.floor(Math.random() * descriptions.length)];
  const fee = Math.max(1, Math.round(amount * 0.01));
  const stripeFee = Math.round(amount * 0.029) + 30;

  const payment = {
    id: 'pay_' + randomHex(12),
    amount: amount,
    currency: merchant.currency || 'EUR',
    fee: fee,
    net: amount - fee,
    saved: stripeFee - fee,
    status: 'succeeded',
    description: desc,
    created: Date.now()
  };

  payments.push(payment);
  savePayments();
  updateDashboard();
}

// ─── POS ───────────────────────────────────────────────────────────
function openPOS() {
  document.getElementById('pos-modal').style.display = 'flex';
  document.getElementById('pos-amount').value = '';
  document.getElementById('pos-qr').style.display = 'none';
  document.getElementById('pos-amount').focus();
}

function closePOS() {
  document.getElementById('pos-modal').style.display = 'none';
}

function posCharge() {
  const amountStr = document.getElementById('pos-amount').value.trim();
  const currency = document.getElementById('pos-currency').value;
  const amount = parseAmount(amountStr);

  if (!amount || amount < 1) return alert('Please enter a valid amount.');

  const fee = Math.max(1, Math.round(amount * 0.01));
  const stripeFee = Math.round(amount * 0.029) + 30;
  const payId = 'pay_' + randomHex(12);

  // Show QR
  const qr = document.getElementById('pos-qr');
  qr.style.display = 'block';
  document.getElementById('pos-status').innerHTML =
    '<span style="color:var(--warning)">Waiting for payment...</span>';

  // Simulate payment after 2 seconds
  setTimeout(function() {
    const payment = {
      id: payId,
      amount: amount,
      currency: currency,
      fee: fee,
      net: amount - fee,
      saved: stripeFee - fee,
      status: 'succeeded',
      description: 'POS payment',
      created: Date.now()
    };

    payments.push(payment);
    savePayments();
    updateDashboard();

    document.getElementById('pos-status').innerHTML =
      '<span style="color:var(--success)">&#10003; Payment received! ' + formatMoney(amount) + ' ' + currency + '</span>';

    setTimeout(function() { closePOS(); }, 2000);
  }, 2000);
}

// ─── Send to Mobile ────────────────────────────────────────────────
function openSendMobile() {
  document.getElementById('send-modal').style.display = 'flex';
  document.getElementById('send-phone').value = '';
  document.getElementById('send-amount').value = '';
  document.getElementById('send-note').value = '';
}

function closeSendMobile() {
  document.getElementById('send-modal').style.display = 'none';
}

function sendPayment() {
  const phone = document.getElementById('send-phone').value.trim();
  const amountStr = document.getElementById('send-amount').value.trim();
  const currency = document.getElementById('send-currency').value;
  const note = document.getElementById('send-note').value.trim();
  const amount = parseAmount(amountStr);

  if (!phone) return alert('Please enter a phone number.');
  if (!amount || amount < 1) return alert('Please enter a valid amount.');

  const fee = Math.max(1, Math.round(amount * 0.01));
  const payment = {
    id: 'pay_' + randomHex(12),
    amount: amount,
    currency: currency,
    fee: fee,
    net: amount - fee,
    saved: Math.round(amount * 0.029) + 30 - fee,
    status: 'succeeded',
    description: 'Sent to ' + phone + (note ? ' — ' + note : ''),
    created: Date.now()
  };

  payments.push(payment);
  savePayments();
  updateDashboard();
  closeSendMobile();
  alert('Payment of ' + formatMoney(amount) + ' ' + currency + ' sent to ' + phone);
}

function requestPayment() {
  const phone = document.getElementById('send-phone').value.trim();
  const amountStr = document.getElementById('send-amount').value.trim();
  const currency = document.getElementById('send-currency').value;
  const note = document.getElementById('send-note').value.trim();
  const amount = parseAmount(amountStr);

  if (!phone) return alert('Please enter a phone number.');
  if (!amount || amount < 1) return alert('Please enter a valid amount.');

  const payment = {
    id: 'pay_' + randomHex(12),
    amount: amount,
    currency: currency,
    fee: 0,
    net: amount,
    saved: 0,
    status: 'pending',
    description: 'Requested from ' + phone + (note ? ' — ' + note : ''),
    created: Date.now()
  };

  payments.push(payment);
  savePayments();
  updateDashboard();
  closeSendMobile();
  alert('Payment request of ' + formatMoney(amount) + ' ' + currency + ' sent to ' + phone);
}

// ─── Payment Links ─────────────────────────────────────────────────
function createPaymentLink() {
  document.getElementById('link-modal').style.display = 'flex';
  document.getElementById('link-amount').value = '';
  document.getElementById('link-desc').value = '';
  document.getElementById('link-result').style.display = 'none';
}

function generateLink() {
  const amountStr = document.getElementById('link-amount').value.trim();
  const currency = document.getElementById('link-currency').value;
  const desc = document.getElementById('link-desc').value.trim();
  const amount = parseAmount(amountStr);

  if (!amount || amount < 1) return alert('Please enter a valid amount.');

  const linkId = randomHex(8);
  const url = 'https://pay.roxexpay.io/link/' + linkId + '?a=' + amount + '&c=' + currency + (desc ? '&d=' + encodeURIComponent(desc) : '');

  document.getElementById('link-url').textContent = url;
  document.getElementById('link-result').style.display = 'block';
}

function copyLink() {
  const url = document.getElementById('link-url').textContent;
  navigator.clipboard.writeText(url).then(function() {
    alert('Link copied to clipboard!');
  });
}

function shareWhatsApp() {
  const url = document.getElementById('link-url').textContent;
  window.open('https://wa.me/?text=' + encodeURIComponent('Pay here: ' + url), '_blank');
}

function closeLinkModal() {
  document.getElementById('link-modal').style.display = 'none';
}

// ─── API Keys ──────────────────────────────────────────────────────
function loadApiKeys() {
  if (!merchant) return;
  document.getElementById('secret-key-display').textContent = 'sk_live_' + '\u2022'.repeat(16);
  document.getElementById('public-key-display').textContent = 'pk_live_' + '\u2022'.repeat(16);
  document.getElementById('curl-key').textContent = merchant.keys.secret;
}

function toggleKey(type) {
  const el = document.getElementById(type === 'secret' ? 'secret-key-display' : 'public-key-display');
  const key = type === 'secret' ? merchant.keys.secret : merchant.keys.public;
  const hidden = (type === 'secret' ? 'sk_live_' : 'pk_live_') + '\u2022'.repeat(16);

  if (el.textContent === hidden) {
    el.textContent = key;
    el.parentElement.querySelector('button').textContent = 'Hide';
  } else {
    el.textContent = hidden;
    el.parentElement.querySelector('button').textContent = 'Reveal';
  }
}

// ─── Settings ──────────────────────────────────────────────────────
function loadSettings() {
  if (!merchant) return;
  document.getElementById('settings-name').value = merchant.name;
  document.getElementById('settings-email').value = merchant.email;
  document.getElementById('settings-currency').value = merchant.currency || 'EUR';
  document.getElementById('settings-webhook').value = merchant.webhook || '';
}

function saveSettings() {
  merchant.name = document.getElementById('settings-name').value.trim();
  merchant.email = document.getElementById('settings-email').value.trim();
  merchant.currency = document.getElementById('settings-currency').value;
  merchant.webhook = document.getElementById('settings-webhook').value.trim();

  // Update stored merchants registry
  const stored = JSON.parse(localStorage.getItem('roxexpay_merchants') || '{}');
  stored[merchant.email] = merchant;
  localStorage.setItem('roxexpay_merchants', JSON.stringify(stored));
  localStorage.setItem('roxexpay_merchant', JSON.stringify(merchant));

  document.getElementById('nav-user').textContent = merchant.name;
  alert('Settings saved.');
}

// ─── Helpers ───────────────────────────────────────────────────────
function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function formatMoney(cents) {
  const neg = cents < 0;
  const abs = Math.abs(cents);
  const str = (abs / 100).toFixed(2);
  return (neg ? '-' : '') + '$' + str.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function parseAmount(str) {
  if (!str) return 0;
  const cleaned = str.replace(/[^0-9.,]/g, '').replace(',', '.');
  const num = parseFloat(cleaned);
  if (isNaN(num)) return 0;
  return Math.round(num * 100);
}

function statusBadge(status) {
  const cls = status === 'succeeded' ? 'status-succeeded' : status === 'pending' ? 'status-pending' : 'status-failed';
  return '<span class="status-badge ' + cls + '">' + status + '</span>';
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
  if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
  return new Date(ts).toLocaleDateString();
}

function savePayments() {
  localStorage.setItem('roxexpay_payments_' + merchant.id, JSON.stringify(payments));
}

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) overlay.style.display = 'none';
  });
});
