// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — Módulo de Autenticação
// ═══════════════════════════════════════════════════════════════

'use strict';

// ── API URL (Google Apps Script) ─────────────────────────────
// A URL é armazenada em partes e montada em runtime para dificultar
// a extração automática por crawlers/scrapers de source estático.
var API_URL = (function() {
  const _p = [
    'https://script.google.com',
    '/macros/s/',
    'AKfycbxMBIJ9Wt1uaFP1rKrc7-TOiQH',
    'av5s_-Zx4brkJmwjmj7XjaNJf8UTOTJ',
    '5Ws6Cy1Ik',
    '/exec'
  ];
  return _p.join('');
})();

// ── Credenciais de acesso ────────────────────────────────────
const CREDENTIALS = {
  admin:  'U2FsdGVkX2+3vH8h5qVQ...hash-admin-aqui...',
  membro: 'U2FsdGVkX2+8kL2m9pTR...hash-membro-aqui...'
};

// ── Rate limiting ─────────────────────────────────────────────
const _loginState = {
  tentativas: 0,
  bloqueadoAte: 0,
  timeouts: [0, 30000, 120000, 300000, 900000] // progressivo
};

function _loginBloqueado() {
  const agora = Date.now();
  if (_loginState.bloqueadoAte > agora) {
    const resto = Math.ceil((_loginState.bloqueadoAte - agora) / 1000);
    return `Aguarde ${resto}s antes de tentar novamente.`;
  }
  return null;
}

function _registrarFalha() {
  _loginState.tentativas++;
  const delay = _loginState.timeouts[Math.min(_loginState.tentativas, _loginState.timeouts.length - 1)];
  if (delay) {
    _loginState.bloqueadoAte = Date.now() + delay;
  }
}

function _resetarFalhas() {
  _loginState.tentativas = 0;
  _loginState.bloqueadoAte = 0;
}

// ── Derivação de chave PBKDF2 ─────────────────────────────────
async function _derivarChave(senha, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(senha), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', iterations: 200000, salt: enc.encode(salt) },
    keyMaterial, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function _gerarHashCredencial(senha, papel) {
  const salt = papel === 'admin' ? 'lapa-admin-salt-2024' : 'lapa-membro-salt-2024';
  return await _derivarChave(senha, salt);
}

function _comparacaoSegura(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── Estado da sessão ─────────────────────────────────────────
let currentRole  = null;   // 'admin' | 'membro' | null
let selectedRole = 'admin';

function selectRole(role) {
  selectedRole = role;
  document.querySelectorAll('.role-card').forEach(c => c.classList.remove('selected'));
  document.querySelector(`.role-card[data-role="${role}"]`)?.classList.add('selected');
}

function loginSuccess(role) {
  currentRole = role;
  localStorage.setItem('lapa-role', role);
  localStorage.setItem('lapa-login-time', Date.now().toString());
  _resetarFalhas();
  
  document.getElementById('login-section')?.classList.add('hidden');
  document.getElementById('app-container')?.classList.remove('hidden');
  document.getElementById('user-role-display')?.textContent = role === 'admin' ? 'Administrador' : 'Membro';
  
  showPage('home');
  _updateNavBadges({ eventos: [], ouvidoria: [], financeiro: [] });
  _updateLastRefresh();
  
  showToastLogin();
}

function doLogout() {
  currentRole = null;
  localStorage.removeItem('lapa-role');
  localStorage.removeItem('lapa-login-time');
  document.getElementById('app-container')?.classList.add('hidden');
  document.getElementById('login-section')?.classList.remove('hidden');
  document.getElementById('login-senha').value = '';
  clearLoginError();
  showPage('login');
}

function showLoginError(msg) {
  const err = document.getElementById('login-error');
  if (err) {
    err.textContent = msg;
    err.style.display = 'block';
  }
}

function clearLoginError() {
  const err = document.getElementById('login-error');
  if (err) {
    err.style.display = 'none';
    err.textContent = '';
  }
}

function togglePassVisibility() {
  const input = document.getElementById('login-senha');
  const icon = document.getElementById('toggle-pass-icon');
  if (input && icon) {
    input.type = input.type === 'password' ? 'text' : 'password';
    icon.className = input.type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
  }
}

function showToastLogin() {
  setTimeout(() => {
    const role = currentRole === 'admin' ? 'Administrador' : 'Membro';
    showToast(`Bem-vindo, ${role}!`, 'success');
  }, 500);
}

function isAdmin() { return currentRole === 'admin'; }

function requireAdmin(action) {
  if (!isAdmin()) {
    showToast('Acesso restrito a administradores.', 'error');
    return false;
  }
  return action();
}

// Exportar funções públicas
window.auth = {
  API_URL,
  CREDENTIALS,
  loginSuccess,
  doLogout,
  showLoginError,
  clearLoginError,
  togglePassVisibility,
  showToastLogin,
  isAdmin,
  requireAdmin,
  selectRole,
  getCurrentRole: () => currentRole,
  getSelectedRole: () => selectedRole,
  deriveKey: _derivarChave,
  generateHash: _gerarHashCredencial,
  checkLock: _loginBloqueado,
  registerFailure: _registrarFalha
};
