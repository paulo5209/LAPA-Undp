'use strict';
// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — JavaScript Principal
// ═══════════════════════════════════════════════════════════════

// ── API URL (Google Apps Script) ─────────────────────────────
// A URL é armazenada em partes e montada em runtime para dificultar
// a extração automática por crawlers/scrapers de source estático.
// Isso não substitui autenticação no servidor — é apenas ofuscação
// de primeira camada para evitar exposição trivial no source.
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
// Armazenadas como PBKDF2-HMAC-SHA256 com salt fixo por papel.
// Para trocar as senhas:
//   1. Abra o console do navegador nesta página após o login.
//   2. Execute: await _gerarHashCredencial('sua-nova-senha', 'admin')
//      (ou 'membro') e copie o resultado para CREDENTIALS aqui.
// NÃO armazene senhas em texto — nem em comentários.
const CREDENTIALS = {
  admin: {
    // PBKDF2(senha, salt, 200000 iter, SHA-256) → hex
    salt: 'lapa-adm-2026-s1',
    hash: '' // preenchido via _inicializarCredenciais() na primeira execução
  },
  membro: {
    salt: 'lapa-mbr-2026-s1',
    hash: ''
  }
};

// ── Rate limiting ─────────────────────────────────────────────
const _loginState = {
  tentativas:    0,
  bloqueadoAte:  0,
  maxTentativas: 5,
  // Backoff progressivo: 30s → 2min → 5min → 15min após max tentativas
  _delays: [30, 120, 300, 900],
  _ciclo:  0,
};

function _loginBloqueado() {
  return Date.now() < _loginState.bloqueadoAte;
}

function _registrarFalha() {
  _loginState.tentativas++;
  if (_loginState.tentativas >= _loginState.maxTentativas) {
    const delay = _loginState._delays[
      Math.min(_loginState._ciclo, _loginState._delays.length - 1)
    ];
    _loginState.bloqueadoAte = Date.now() + delay * 1000;
    _loginState.tentativas   = 0;
    _loginState._ciclo++;
    return delay;
  }
  return 0;
}

function _resetarFalhas() {
  _loginState.tentativas   = 0;
  _loginState.bloqueadoAte = 0;
  _loginState._ciclo       = 0;
}

// ── Derivação de chave PBKDF2 ─────────────────────────────────
async function _derivarChave(senha, salt) {
  const enc  = new TextEncoder();
  const base = await crypto.subtle.importKey(
    'raw', enc.encode(senha), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 200000 },
    base, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Utilitário para gerar novo hash ao trocar senhas (use no console)
async function _gerarHashCredencial(senha, papel) {
  const salt = CREDENTIALS[papel]?.salt;
  if (!salt) { console.error('Papel inválido:', papel); return; }
  const h = await _derivarChave(senha, salt);
  console.log(`Hash para ${papel}:\n${h}\nCopie este valor para CREDENTIALS.${papel}.hash`);
  return h;
}

// Inicialização: preenche hashes no objeto CREDENTIALS em runtime
// a partir de valores codificados — sem expor senhas no source.
// Os valores abaixo são o resultado de PBKDF2(senha, salt, 200000, SHA-256).
// Para regenerar após trocar a senha, use _gerarHashCredencial() no console.
(function _inicializarCredenciais() {
  // Hashes PBKDF2 — NÃO são as senhas; não revelam a senha original.
  const _h = [
    // admin — PBKDF2(senha, 'lapa-adm-2026-s1', 200000, SHA-256)
    'dcb4570b2c33df21c4164826450424d5' +
    'b4bb9b9692fa505a51484960ad7a542b',
    // membro — PBKDF2(senha, 'lapa-mbr-2026-s1', 200000, SHA-256)
    '29b8aacfedc506440b5b4acf29acc2fe' +
    '50a06fe7b4b9a2cec976adf22d45a9df',
  ];
  CREDENTIALS.admin.hash  = _h[0];
  CREDENTIALS.membro.hash = _h[1];
})();

// Comparação segura em tempo constante (evita timing attacks)
function _comparacaoSegura(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ══════════════════════════════════════════════════════════════
//  SISTEMA DE LOGIN
// ══════════════════════════════════════════════════════════════

let currentRole  = null;   // 'admin' | 'membro' | null
let selectedRole = 'admin';

function selectRole(role) {
  selectedRole = role;
  document.getElementById('tab-admin').classList.toggle('active', role === 'admin');
  document.getElementById('tab-membro').classList.toggle('active', role === 'membro');
  clearLoginError();
  document.getElementById('login-senha').focus();
}

async function doLogin() {
  const btn = document.getElementById('login-btn');

  // ── Rate limiting ─────────────────────────────────────────
  if (_loginBloqueado()) {
    const restante = Math.ceil((_loginState.bloqueadoAte - Date.now()) / 1000);
    const min = Math.floor(restante / 60);
    const seg = restante % 60;
    const tempo = min > 0 ? `${min}m ${seg}s` : `${seg}s`;
    showLoginError(`Muitas tentativas. Aguarde ${tempo} antes de tentar novamente.`);
    return;
  }

  const senha = document.getElementById('login-senha').value.trim();
  if (!senha) { showLoginError('Digite sua senha para continuar.'); return; }

  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verificando…';

  try {
    // Exige crypto.subtle (HTTPS); aborta sem fallback inseguro em plaintext
    if (!crypto?.subtle) {
      showLoginError('Seu navegador não suporta criptografia segura. Acesse via HTTPS.');
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Entrar';
      return;
    }

    const cred = CREDENTIALS[selectedRole];
    const hash = await _derivarChave(senha, cred.salt);

    if (_comparacaoSegura(hash, cred.hash)) {
      _resetarFalhas();
      loginSuccess(selectedRole);
    } else {
      const delay = _registrarFalha();
      const restantes = _loginState.maxTentativas - _loginState.tentativas;
      if (delay > 0) {
        const min = Math.floor(delay / 60);
        const seg = delay % 60;
        const tempo = min > 0 ? `${min}m ${seg}s` : `${seg}s`;
        showLoginError(`Senha incorreta. Conta bloqueada por ${tempo} após múltiplas tentativas.`);
      } else {
        showLoginError(
          `Senha incorreta. ${restantes} tentativa${restantes !== 1 ? 's' : ''} restante${restantes !== 1 ? 's' : ''}.`
        );
      }
      document.getElementById('login-senha').classList.add('error');
      btn.disabled = false;
      btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Entrar';
    }
  } catch(e) {
    showLoginError('Erro ao verificar credenciais. Tente novamente.');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Entrar';
  }
}

function loginSuccess(role) {
  currentRole = role;
  sessionStorage.setItem('lapa-role', role);

  // Atualiza UI de acordo com o papel
  document.body.classList.toggle('is-admin', role === 'admin');

  // Atualiza badge na topbar
  const badge = document.getElementById('topbar-role-badge');
  if (badge) {
    badge.style.display = '';
    badge.className = 'role-badge ' + role;
    badge.innerHTML = role === 'admin'
      ? '<i class="fas fa-shield-alt"></i> Admin'
      : '<i class="fas fa-user"></i> Membro';
  }

  // Atualiza user card na sidebar
  const nameEl = document.querySelector('.user-info .name');
  const roleEl = document.querySelector('.user-info .role');
  const avatarEl = document.querySelector('.sidebar-footer .avatar');
  if (nameEl) nameEl.textContent = role === 'admin' ? 'Diretoria' : 'Membro';
  if (roleEl) roleEl.textContent = role === 'admin' ? 'Administrador' : 'Membro LAPA';
  if (avatarEl) avatarEl.textContent = role === 'admin' ? 'D' : 'M';
  // Esconde tela de login
  const screen = document.getElementById('login-screen');
  screen.style.transition = 'opacity .4s ease';
  screen.style.opacity = '0';
  setTimeout(() => { screen.style.display = 'none'; }, 400);

  // Inicializa dashboard
  applyTheme();
  setupSearch();
  setupFilters();
  setupInlineValidation();
  bindModalButtons();
  loadHomeStats();
  _restaurarDocsStatic(); // Seguro: executada após autenticação confirmada

  showToast('Bem-vindo' + (role === 'admin' ? ', Administrador!' : ' à LAPA!'), 'success');
  _aplicarTodosIndicadores();
}

function doLogout() {
  customConfirm({
    title: 'Sair do sistema',
    message: 'Deseja realmente encerrar sua sessão?',
    confirmLabel: 'Sair',
    icon: 'fa-sign-out-alt',
    iconColor: 'var(--coral)',
    onConfirm: () => {
      currentRole = null;
      sessionStorage.removeItem('lapa-role');
      document.body.classList.remove('is-admin');
      document.getElementById('login-senha').value = '';
      document.getElementById('login-senha').classList.remove('error');
      clearLoginError();
      selectRole('admin');
      const screen = document.getElementById('login-screen');
      screen.style.display = 'flex';
      screen.style.opacity = '0';
      setTimeout(() => { screen.style.transition = 'opacity .4s ease'; screen.style.opacity = '1'; }, 10);
    }
  });
}

function showLoginError(msg) {
  document.getElementById('login-error-msg').textContent = msg;
  document.getElementById('login-error').classList.add('show');
}

function clearLoginError() {
  document.getElementById('login-error').classList.remove('show');
  const inp = document.getElementById('login-senha');
  if (inp) inp.classList.remove('error');
}

function togglePassVisibility() {
  const inp  = document.getElementById('login-senha');
  const icon = document.getElementById('toggle-pass-icon');
  if (inp.type === 'password') {
    inp.type = 'text';
    icon.className = 'fas fa-eye-slash toggle-pass';
  } else {
    inp.type = 'password';
    icon.className = 'fas fa-eye toggle-pass';
  }
}

function showToastLogin() {
  showToast('Entre em contato com a Secretaria da LAPA para redefinir sua senha.', 'info');
}

// ══════════════════════════════════════════════════════════════
//  CONTROLE DE PERMISSÕES (admin x membro)
// ══════════════════════════════════════════════════════════════

function isAdmin() { return currentRole === 'admin'; }

/**
 * Verifica se o usuário é admin antes de executar uma ação.
 * Se não for, exibe toast e retorna false.
 */
function requireAdmin(action) {
  if (isAdmin()) return true;
  showToast('Apenas administradores podem ' + (action || 'realizar esta ação') + '.', 'warning');
  return false;
}

// ══════════════════════════════════════════════════════════════
//  MAPEAMENTO DE PÁGINAS
// ══════════════════════════════════════════════════════════════

const pageMap = {
  home:       'Início',
  agenda:     'Agenda & Eventos',
  membros:    'Membros',
  documentos: 'Documentos',
  secretaria: 'Secretaria',
  tesouraria: 'Tesouraria',
  marketing:  'Marketing & Comunicação',
  pesquisa:   'Pesquisa Científica',
  extensao:   'Extensão Universitária',
  ensino:     'Ensino',
  ouvidoria:  'Ouvidoria',
  relatorios: 'Relatórios & Indicadores',
};

// ══════════════════════════════════════════════════════════════
//  NAVEGAÇÃO
// ══════════════════════════════════════════════════════════════

function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const target = document.getElementById('page-' + id);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.remove('active');
    const oc = item.getAttribute('onclick') || '';
    if (oc.includes("'" + id + "'")) item.classList.add('active');
  });

  document.getElementById('page-title').textContent = pageMap[id] || id;
  document.querySelector('.content').scrollTop = 0;

  const loaders = {
    home:       loadHomeStats,
    membros:    loadMembros,
    secretaria: loadSecretaria,
    tesouraria: loadTesouraria,
    agenda:     loadAgenda,
    pesquisa:   loadPesquisa,
    extensao:   loadExtensao,
    ensino:     loadEnsino,
    ouvidoria:  loadOuvidoria,
    marketing:  loadMarketing,
    documentos: loadDocumentos,
    relatorios: loadRelatorios,
  };
  if (loaders[id]) loaders[id]();
}

function switchTab(el, panelId) {
  const parent = el.parentElement;
  parent.querySelectorAll('.inner-tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  const contentArea = parent.parentElement;
  contentArea.querySelectorAll('.inner-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById(panelId);
  if (panel) panel.classList.add('active');
}

// ══════════════════════════════════════════════════════════════
//  MODAIS
// ══════════════════════════════════════════════════════════════

function openModal(id) {
  // Modais de edição/criação exigem admin
  const adminModals = ['modal-add-membro','modal-nova-ata','modal-lancamento',
    'modal-novo-evento','modal-novo-projeto','modal-novo-curso',
    'modal-nova-acao','modal-novo-parceiro','modal-nova-corr','modal-new-task',
    'modal-upload-doc','modal-edit-membro','modal-edit-evento',
    'modal-edit-projeto','modal-edit-ata','modal-configuracoes',
    'modal-edit-doc-static'];
  if (adminModals.includes(id) && !isAdmin()) {
    showToast('Apenas administradores podem adicionar ou editar dados.', 'warning');
    return;
  }
  const m = document.getElementById(id);
  if (m) { m.classList.add('open'); m.querySelector('input,textarea,select')?.focus(); }
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (m) { m.classList.remove('open'); clearModalForm(id); }
}

function clearModalForm(id) {
  const m = document.getElementById(id);
  if (!m) return;
  m.querySelectorAll('input:not([type=file])').forEach(i => { if(i.type !== 'button') i.value = ''; });
  m.querySelectorAll('textarea').forEach(t => t.value = '');
  m.querySelectorAll('select').forEach(s => s.selectedIndex = 0);
  // Reset btn state
  const btn = m.querySelector('.btn-primary');
  if (btn) btn.disabled = false;
}

document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', function(e) {
    if (e.target === this) closeModal(this.id);
  });
});

// ESC fecha modal aberto
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(m => closeModal(m.id));
  }
  if (e.key === 'Enter' && document.getElementById('login-screen').style.display !== 'none'
      && document.getElementById('login-screen').style.opacity !== '0') {
    doLogin();
  }
});

// ══════════════════════════════════════════════════════════════
//  TEMA CLARO / ESCURO
// ══════════════════════════════════════════════════════════════

let lightMode = localStorage.getItem('lapa-theme') === 'light';

function toggleTheme() {
  lightMode = !lightMode;
  localStorage.setItem('lapa-theme', lightMode ? 'light' : 'dark');
  applyTheme();
}

function applyTheme() {
  const r = document.documentElement;
  if (lightMode) {
    r.style.setProperty('--bg',     '#f0f4f8');
    r.style.setProperty('--bg2',    '#e4ecf5');
    r.style.setProperty('--bg3',    '#d8e4f0');
    r.style.setProperty('--card',   '#ffffff');
    r.style.setProperty('--card2',  '#f0f4f8');
    r.style.setProperty('--text',   '#1a2330');
    r.style.setProperty('--text2',  '#3a5068');
    r.style.setProperty('--text3',  '#6a8aaa');
    r.style.setProperty('--border',  'rgba(30,80,130,.15)');
    r.style.setProperty('--border2', 'rgba(30,80,130,.25)');
  } else {
    r.style.setProperty('--bg',     '#0d1117');
    r.style.setProperty('--bg2',    '#131920');
    r.style.setProperty('--bg3',    '#1a2330');
    r.style.setProperty('--card',   '#1e2a38');
    r.style.setProperty('--card2',  '#243041');
    r.style.setProperty('--text',   '#e8eff8');
    r.style.setProperty('--text2',  '#8fa8c8');
    r.style.setProperty('--text3',  '#556880');
    r.style.setProperty('--border',  'rgba(100,160,220,.12)');
    r.style.setProperty('--border2', 'rgba(100,160,220,.22)');
  }
}

// ══════════════════════════════════════════════════════════════
//  TOAST
// ══════════════════════════════════════════════════════════════

function showToast(message, type = 'success') {
  const colors = { success:'var(--sage)', error:'var(--coral)', info:'var(--teal)', warning:'var(--gold)' };
  const icons  = { success:'fa-check-circle', error:'fa-exclamation-circle', info:'fa-info-circle', warning:'fa-exclamation-triangle' };

  // Remove toasts anteriores do mesmo tipo para não acumular
  document.querySelectorAll('.lasm-toast').forEach(t => t.remove());

  const toast = document.createElement('div');
  toast.className = 'lasm-toast';
  toast.style.cssText = `
    position:fixed; bottom:24px; right:24px; z-index:99999;
    background:var(--card); border:1px solid ${colors[type]};
    border-left:4px solid ${colors[type]};
    color:var(--text); padding:14px 20px;
    border-radius:10px; font-size:14px;
    display:flex; align-items:center; gap:10px;
    box-shadow:0 8px 32px rgba(0,0,0,.45);
    animation:slideInToast .3s ease;
    max-width:380px; font-family:'DM Sans',sans-serif;
  `;
  toast.innerHTML = `<i class="fas ${icons[type]}" style="color:${colors[type]};font-size:16px;flex-shrink:0"></i><span>${message}</span>`;

  if (!document.querySelector('#toast-anim-style')) {
    const s = document.createElement('style');
    s.id = 'toast-anim-style';
    s.textContent = '@keyframes slideInToast{from{opacity:0;transform:translateX(100px)}to{opacity:1;transform:translateX(0)}}';
    document.head.appendChild(s);
  }

  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'opacity .35s';
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 350);
  }, 3800);
}

// ══════════════════════════════════════════════════════════════
//  CONTADOR ANIMADO
// ══════════════════════════════════════════════════════════════

function animateCounter(el, target, prefix = '', suffix = '') {
  if (!el) return;
  let cur = 0;
  const step = Math.max(1, Math.floor(target / 50));
  const timer = setInterval(() => {
    cur = Math.min(cur + step, target);
    el.textContent = prefix + cur + suffix;
    if (cur >= target) clearInterval(timer);
  }, 25);
}

// ══════════════════════════════════════════════════════════════
//  API
// ══════════════════════════════════════════════════════════════

// ─── Cache de respostas (TTL: 30s) ────────────────────────
const _apiCache = {};
const _apiCacheTTL = 30000;
function _cacheKey(p){ return JSON.stringify(p); }

async function apiGet(params) {
  if (!API_URL || API_URL.includes('COLE_A_URL')) return null;
  const key = _cacheKey(params);
  const now = Date.now();
  if (_apiCache[key] && (now - _apiCache[key].ts < _apiCacheTTL)) {
    return _apiCache[key].data;
  }
  try {
    const url  = API_URL + '?' + new URLSearchParams(params).toString();
    const resp = await fetch(url);
    const data = await resp.json();
    if (!data.success) throw new Error(data.error || 'Erro desconhecido');
    _apiCache[key] = { data: data.data, ts: now };
    return data.data;
  } catch (e) {
    console.warn('API GET falhou:', e.message);
    return null;
  }
}

async function apiPost(payload) {
  if (!API_URL || API_URL.includes('COLE_A_URL')) return null;
  try {
    const resp = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    if (!data.success) throw new Error(data.error || 'Erro desconhecido');
    // Invalida cache da sheet afetada para forçar re-fetch
    if (payload.sheet) {
      const sheetKey = JSON.stringify({ action: 'getAll', sheet: payload.sheet });
      delete _apiCache[sheetKey];
    }
    return data.data;
  } catch (e) {
    throw e;
  }
}

// ══════════════════════════════════════════════════════════════
//  MODAL DE CONFIRMAÇÃO CUSTOMIZADO — substitui window.confirm
// ══════════════════════════════════════════════════════════════

let _confirmCallback = null;

function customConfirm({ title, message, confirmLabel = 'Confirmar', cancelLabel = 'Cancelar',
                          icon = 'fa-exclamation-triangle', iconColor = 'var(--coral)', danger = true, onConfirm }) {
  _confirmCallback = onConfirm;
  const wrap  = document.getElementById('modal-confirm');
  const ico   = document.getElementById('confirm-icon');
  const icoW  = document.getElementById('confirm-icon-wrap');
  const tit   = document.getElementById('confirm-title');
  const msg   = document.getElementById('confirm-message');
  const okBtn = document.getElementById('confirm-ok-btn');
  const canBtn= document.getElementById('confirm-cancel-btn');

  ico.className = 'fas ' + icon;
  ico.style.color = iconColor;
  icoW.style.background = danger ? 'rgba(244,63,94,.12)' : 'rgba(239,68,68,.12)';
  icoW.style.borderColor = danger ? 'rgba(244,63,94,.25)' : 'rgba(239,68,68,.25)';
  tit.textContent  = title   || 'Confirmar ação';
  msg.textContent  = message || 'Tem certeza?';
  okBtn.textContent = confirmLabel;
  okBtn.className   = 'btn ' + (danger ? 'btn-danger' : 'btn-primary');
  canBtn.textContent = cancelLabel;

  wrap.classList.add('open');
  okBtn.focus();
}

document.addEventListener('DOMContentLoaded', () => {
  const okBtn = document.getElementById('confirm-ok-btn');
  if (okBtn) {
    okBtn.addEventListener('click', () => {
      closeModal('modal-confirm');
      if (typeof _confirmCallback === 'function') {
        _confirmCallback();
        _confirmCallback = null;
      }
    });
  }
});

// ══════════════════════════════════════════════════════════════
//  BUSCA GLOBAL — DROPDOWN COMPLETO (todos os módulos)
// ══════════════════════════════════════════════════════════════

let _searchDebounceTimer = null;
let _allDataCache = {};  // cache local para busca

function setupSearch() {
  const input    = document.getElementById('global-search-input');
  const dropdown = document.getElementById('global-search-dropdown');
  if (!input || !dropdown) return;

  // Fechar ao clicar fora
  document.addEventListener('click', e => {
    if (!document.getElementById('global-search-wrap')?.contains(e.target)) {
      dropdown.classList.remove('open');
    }
  });

  input.addEventListener('focus', () => {
    if (input.value.trim().length >= 2) dropdown.classList.add('open');
  });

  input.addEventListener('input', () => {
    clearTimeout(_searchDebounceTimer);
    const val = input.value.trim();
    if (val.length < 2) { dropdown.classList.remove('open'); return; }
    _searchDebounceTimer = setTimeout(() => _runGlobalSearch(val), 220);
  });

  input.addEventListener('keydown', e => {
    if (e.key === 'Escape') { dropdown.classList.remove('open'); input.value = ''; }
  });
}

async function _runGlobalSearch(q) {
  const dropdown = document.getElementById('global-search-dropdown');
  if (!dropdown) return;

  dropdown.innerHTML = `<div class="search-no-results"><i class="fas fa-spinner fa-spin"></i> Buscando…</div>`;
  dropdown.classList.add('open');

  const term = q.toLowerCase();
  const results = {};

  // Sheets a buscar
  const sheets = [
    { key: 'Membros',           label: 'Membros',        icon: 'fa-user',           color: 'var(--teal)',     badge: 'teal',    page: 'membros',    fields: ['Nome','Matricula','Setor','Cargo'] },
    { key: 'Eventos',           label: 'Eventos',        icon: 'fa-calendar-check', color: 'var(--lavender)', badge: 'lav',     page: 'agenda',     fields: ['Titulo','Tipo','Local','Responsavel'] },
    { key: 'Atas',              label: 'Atas',           icon: 'fa-file-alt',       color: 'var(--gold)',     badge: 'gold',    page: 'secretaria', fields: ['Titulo','Status'] },
    { key: 'Financeiro',        label: 'Financeiro',     icon: 'fa-receipt',        color: 'var(--sage)',     badge: 'sage',    page: 'tesouraria', fields: ['Descricao','Categoria','Tipo'] },
    { key: 'Pesquisas',         label: 'Projetos',       icon: 'fa-flask',          color: 'var(--coral)',    badge: 'coral',   page: 'pesquisa',   fields: ['Titulo','Status','Descricao'] },
    { key: 'Cursos',            label: 'Cursos',         icon: 'fa-graduation-cap', color: 'var(--lavender)', badge: 'lav',     page: 'ensino',     fields: ['Titulo','Status'] },
    { key: 'Parceiros',         label: 'Parceiros',      icon: 'fa-handshake',      color: 'var(--sky)',      badge: 'sky',     page: 'extensao',   fields: ['Nome','Area','Status'] },
    { key: 'TarefasMarketing',  label: 'Conteúdo',       icon: 'fa-bullhorn',       color: 'var(--lavender)', badge: 'lav',     page: 'marketing',  fields: ['Titulo','Formato','Status'] },
    { key: 'Documentos',        label: 'Documentos',     icon: 'fa-folder-open',    color: 'var(--gold)',     badge: 'gold',    page: 'documentos', fields: ['fileName','Nome','categoria','Categoria'] },
  ];

  // Busca em paralelo com cache
  await Promise.all(sheets.map(async s => {
    try {
      let data = _allDataCache[s.key];
      if (!data) {
        data = await apiGet({ action: 'getAll', sheet: s.key });
        if (data) _allDataCache[s.key] = data;
      }
      if (!data) return;
      const hits = data.filter(row =>
        s.fields.some(f => String(row[f] || '').toLowerCase().includes(term))
      ).slice(0, 4);
      if (hits.length) results[s.key] = { ...s, hits };
    } catch(_) {}
  }));

  // Busca em docs estáticos (não estão na API)
  const staticDocs = [];
  document.querySelectorAll('#docs-static-grid .doc-card').forEach(card => {
    const nome = (card.getAttribute('data-nome') || '').toLowerCase();
    if (nome.includes(term)) {
      staticDocs.push({ _nome: card.querySelector('.doc-static-nome')?.textContent || nome, _cat: card.getAttribute('data-cat') || '' });
    }
  });
  if (staticDocs.length) {
    results['_static_docs'] = {
      label: 'Documentos', icon: 'fa-folder-open', color: 'var(--gold)', page: 'documentos',
      hits: staticDocs.map(d => ({ _display: d._nome, _sub: d._cat }))
    };
  }

  // Render
  const keys = Object.keys(results);
  if (keys.length === 0) {
    dropdown.innerHTML = `<div class="search-no-results">
      <i class="fas fa-search"></i>
      Nenhum resultado encontrado para "<strong>${esc(q)}</strong>"
    </div>`;
    return;
  }

  let html = '';
  keys.forEach(k => {
    const s = results[k];
    html += `<div class="search-group-label"><i class="fas ${s.icon}" style="color:${s.color};margin-right:5px"></i>${s.label}</div>`;
    s.hits.forEach(row => {
      const title = row._display || row.Titulo || row.Nome || row.Descricao || row.fileName || '—';
      const sub   = row._sub   || row.Setor || row.Tipo || row.Status || row.Categoria || row.categoria || '';
      html += `<div class="search-result-item" onclick="closeSearchAndGo('${s.page}')">
        <div class="search-result-icon" style="background:rgba(0,0,0,.12);color:${s.color}">
          <i class="fas ${s.icon}"></i>
        </div>
        <div>
          <div class="search-result-title">${esc(String(title))}</div>
          ${sub ? `<div class="search-result-sub">${esc(String(sub))}</div>` : ''}
        </div>
      </div>`;
    });
  });

  dropdown.innerHTML = html;
}

function closeSearchAndGo(page) {
  const dropdown = document.getElementById('global-search-dropdown');
  const input    = document.getElementById('global-search-input');
  if (dropdown) dropdown.classList.remove('open');
  if (input) input.value = '';
  showPage(page);
}

// ══════════════════════════════════════════════════════════════
//  FILTROS DE MEMBROS
// ══════════════════════════════════════════════════════════════

function setupFilters() {
  // Filtro de setor + status na página Membros — usa IDs estáveis
  const mbrSetor  = document.getElementById('mbr-filter-setor');
  const mbrStatus = document.getElementById('mbr-filter-status');
  if (mbrSetor)  mbrSetor.addEventListener('change',  filterMembros);
  if (mbrStatus) mbrStatus.addEventListener('change', filterMembros);

  // Conecta o campo de busca local de membros ao filterMembros paginado
  const mbrBusca = document.querySelector('#page-membros .search-box input');
  if (mbrBusca) {
    mbrBusca.addEventListener('input', () => { _membrosPagina = 1; _renderMembrosTable(); });
  }

  // Filtro de setor na Secretaria (sec-membros-ctrl) — select + input de busca
  const secSetor = document.getElementById('sec-filter-setor');
  const secBusca = document.getElementById('sec-filter-busca');
  if (secSetor) secSetor.addEventListener('change', filterSecMembros);
  if (secBusca) secBusca.addEventListener('input',  filterSecMembros);
}

/**
 * Filtra as linhas da tabela em #sec-membros-ctrl
 * usando o select de setor e o input de busca textual.
 */
function filterSecMembros() {
  const setor = document.getElementById('sec-filter-setor')?.value || 'Todos os setores';
  const busca = (document.getElementById('sec-filter-busca')?.value || '').toLowerCase().trim();

  document.querySelectorAll('#sec-membros-ctrl tbody tr').forEach(row => {
    const txt      = row.textContent.toLowerCase();
    const setorOk  = setor === 'Todos os setores' || txt.includes(setor.toLowerCase());
    const buscaOk  = !busca || txt.includes(busca);
    row.style.display = (setorOk && buscaOk) ? '' : 'none';
  });
}

function filterMembros() {
  const setor  = document.getElementById('mbr-filter-setor')?.value  || 'Todos os setores';
  const status = document.getElementById('mbr-filter-status')?.value || 'Todos os status';

  document.querySelectorAll('#members-table tr:not(#members-empty)').forEach(row => {
    const rowText = row.textContent;
    const setorOk  = setor  === 'Todos os setores'  || rowText.includes(setor);
    const statusOk = status === 'Todos os status'   || rowText.includes(status);
    row.style.display = (setorOk && statusOk) ? '' : 'none';
  });
}

// ══════════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════════

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formatDate(val) {
  if (!val) return '—';
  const d = new Date(val + 'T00:00:00');
  return isNaN(d) ? String(val) : d.toLocaleDateString('pt-BR');
}

function setorCor(setor) {
  const map = {
    'Pesquisa':   {bg:'rgba(239,68,68,.15)',  fg:'var(--teal)',    bd:'rgba(239,68,68,.3)',  badge:'teal'},
    'Marketing':  {bg:'rgba(249,115,22,.15)', fg:'var(--lavender)',bd:'rgba(249,115,22,.3)', badge:'lav'},
    'Tesouraria': {bg:'rgba(232,196,106,.15)', fg:'var(--gold)',    bd:'rgba(232,196,106,.3)', badge:'gold'},
    'Extensão':   {bg:'rgba(106,179,232,.15)', fg:'var(--sky)',     bd:'rgba(106,179,232,.3)', badge:'sky'},
    'Ensino':     {bg:'rgba(107,191,160,.15)', fg:'var(--sage)',    bd:'rgba(107,191,160,.3)', badge:'sage'},
    'Secretaria': {bg:'rgba(224,122,122,.15)', fg:'var(--coral)',   bd:'rgba(224,122,122,.3)', badge:'coral'},
    'Palestra':   {bg:'rgba(239,68,68,.15)',  fg:'var(--teal)',    bd:'rgba(239,68,68,.3)',  badge:'teal'},
    'Workshop':   {bg:'rgba(232,196,106,.15)', fg:'var(--gold)',    bd:'rgba(232,196,106,.3)', badge:'gold'},
    'Reunião':    {bg:'rgba(249,115,22,.15)', fg:'var(--lavender)',bd:'rgba(249,115,22,.3)', badge:'lav'},
    'Jornada':    {bg:'rgba(107,191,160,.15)', fg:'var(--sage)',    bd:'rgba(107,191,160,.3)', badge:'sage'},
  };
  return map[setor] || {bg:'rgba(239,68,68,.15)',fg:'var(--teal)',bd:'rgba(239,68,68,.3)',badge:'teal'};
}

function statusBadge(s) {
  const map = {
    'Ativo':'sage','Ativa':'sage','Aprovada':'teal','Realizado':'sage',
    'Confirmado':'teal','Publicado':'sage','Em andamento':'lav',
    'Planejado':'gold','Planejada':'gold','Aguardando':'gold',
    'Pendente assinatura':'gold','Pendente':'coral','Afastado':'coral','Encerrado':'coral',
  };
  return map[s] || 'teal';
}

function setLoadingMsg(containerId, msg = 'Carregando…') {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = `<div style="text-align:center;padding:28px;color:var(--text3)"><i class="fas fa-spinner fa-spin" style="margin-right:8px"></i>${msg}</div>`;
}

function setEmptyMsg(containerId, icon, msg) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = `<div style="text-align:center;padding:32px;color:var(--text3)"><i class="fas ${icon}" style="font-size:28px;display:block;margin-bottom:12px;opacity:.3"></i>${msg}</div>`;
}

// ══════════════════════════════════════════════════════════════
//  LOADER — HOME
// ══════════════════════════════════════════════════════════════

async function loadHomeStats() {
  try {
    // Carrega tudo em paralelo — muito mais rápido
    const [membros, financeiro, eventos, pesquisas] = await Promise.all([
      apiGet({ action: 'getAll', sheet: 'Membros' }),
      apiGet({ action: 'getAll', sheet: 'Financeiro' }),
      apiGet({ action: 'getAll', sheet: 'Eventos' }),
      apiGet({ action: 'getAll', sheet: 'Pesquisas' }),
    ]);

    // ── Counters do hero — calculados dos dados reais ─────
    const membrosAtivos = membros ? membros.filter(m => m.Status === 'Ativo').length : null;
    const hoje = new Date(); hoje.setHours(0,0,0,0);
    const inicioSem = new Date(hoje.getFullYear(), hoje.getMonth() <= 5 ? 0 : 6, 1);
    const eventosSem = eventos
      ? eventos.filter(e => { const d = new Date((e.Data||'')+'T00:00:00'); return d >= inicioSem; }).length
      : null;
    const projAtivos = pesquisas
      ? pesquisas.filter(p => !['Publicado','Encerrado'].includes(p.Status)).length
      : null;

    const cntMembros  = document.getElementById('cnt-membros');
    const cntEventos  = document.getElementById('cnt-eventos');
    const cntProjetos = document.getElementById('cnt-projetos');
    const cntAnos     = document.getElementById('cnt-anos');
    if (cntMembros)  { if (membrosAtivos  !== null) animateCounter(cntMembros,  membrosAtivos);  else cntMembros.textContent  = '—'; }
    if (cntEventos)  { if (eventosSem     !== null) animateCounter(cntEventos,  eventosSem);     else cntEventos.textContent  = '—'; }
    if (cntProjetos) { if (projAtivos     !== null) animateCounter(cntProjetos, projAtivos);     else cntProjetos.textContent = '—'; }

    // Calcula anos de existência a partir da sheet Configuracoes (chave: ano_fundacao)
    if (cntAnos) {
      try {
        const cfgs = await _carregarConfiguracoes();
        const anoFund = parseInt(cfgs['ano_fundacao']?.valor);
        if (anoFund && anoFund > 1900) {
          const anos = new Date().getFullYear() - anoFund;
          animateCounter(cntAnos, anos);
        } else {
          cntAnos.textContent = '—';
        }
      } catch(_) { cntAnos.textContent = '—'; }
    }

    // ── Saldo em caixa (home) — calculado da sheet Financeiro ──
    const saldoEl  = document.getElementById('home-saldo-val');
    const saldoChEl= document.getElementById('home-saldo-change');
    if (financeiro && financeiro.length > 0) {
      let saldo = 0, recMes = 0, despMes = 0;
      const hoje = new Date();
      financeiro.forEach(m => {
        const v    = parseFloat(m.Valor) || 0;
        const isRec= String(m.Tipo).toLowerCase() === 'receita';
        saldo += isRec ? v : -v;
        const d = new Date((m.Data || '') + 'T00:00:00');
        if (!isNaN(d) && d.getMonth()===hoje.getMonth() && d.getFullYear()===hoje.getFullYear()) {
          if (isRec) recMes += v; else despMes += v;
        }
      });
      const fmt = v => 'R$ ' + Math.abs(v).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});
      if (saldoEl)  saldoEl.textContent = fmt(saldo);
      if (saldoChEl) {
        const diff = recMes - despMes;
        saldoChEl.innerHTML = diff >= 0
          ? '<i class="fas fa-arrow-up"></i>' + fmt(diff) + ' este mês'
          : '<i class="fas fa-arrow-down"></i>' + fmt(diff) + ' este mês';
        saldoChEl.className = 'stat-change ' + (diff >= 0 ? 'up' : 'down');
      }
    } else {
      if (saldoEl) saldoEl.textContent = '—';
      if (saldoChEl) saldoChEl.innerHTML = '<i class="fas fa-minus"></i> sem dados';
    }

    // ── Próximo evento ──────────────────────────────────────
    const evVal = document.getElementById('home-evento-val');
    const evMeta= document.getElementById('home-evento-meta');
    if (eventos && eventos.length > 0) {
      const hoje = new Date(); hoje.setHours(0,0,0,0);
      const proximos = eventos
        .filter(e => e.Data && new Date(e.Data + 'T00:00:00') >= hoje)
        .sort((a,b) => new Date(a.Data) - new Date(b.Data));
      if (proximos.length > 0) {
        const ev = proximos[0];
        const d  = new Date(ev.Data + 'T00:00:00');
        if (evVal)  evVal.textContent = d.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'}).replace('.','');
        if (evMeta) evMeta.innerHTML  = '<i class="fas fa-map-marker-alt"></i> ' + (ev.Local || '—');
      } else {
        if (evVal)  evVal.textContent = '—';
        if (evMeta) evMeta.innerHTML  = '<i class="fas fa-calendar-check"></i> Sem próximos eventos';
      }
    } else {
      if (evVal)  evVal.textContent = '—';
      if (evMeta) evMeta.innerHTML  = '<i class="fas fa-minus"></i> —';
    }

    // ── Indicadores editáveis via API ─────────────────────────
    _aplicarTodosIndicadores();

    // ── Membros recentes ──────────────────────────────────────
    renderHomeMembros(membros);

    // ── Gráficos dinâmicos ────────────────────────────────────
    renderDonutSetor(membros);
    renderBarChart(membros);

    // ── Timeline de eventos recentes ──────────────────────────
    renderHomeTimeline(eventos);

    // ── Badges dinâmicos da sidebar ───────────────────────────
    const ouvidoria = await apiGet({ action: 'getAll', sheet: 'Ouvidoria' });
    _updateNavBadges({ eventos, ouvidoria, financeiro });

    // ── Timestamp da última atualização ──────────────────────
    _updateLastRefresh();

  } catch(e) { console.warn('loadHomeStats:', e); }
}

function renderHomeTimeline(eventos) {
  const list = document.getElementById('home-timeline-list');
  if (!list) return;

  const tl_colors = ['teal','lav','gold','sage','coral'];
  const tl_icons  = ['fa-first-aid','fa-users','fa-heartbeat','fa-book-open','fa-calendar-check'];

  if (!eventos || eventos.length === 0) {
    list.innerHTML = '<li style="color:var(--text3);font-size:13px;padding:12px 0">Nenhum evento cadastrado. <span style="cursor:pointer;color:var(--teal)" onclick="showPage(\'agenda\')">Adicionar →</span></li>';
    return;
  }

  const hoje = new Date(); hoje.setHours(0,0,0,0);
  const proximos = eventos
    .filter(e => e.Data && new Date(e.Data + 'T00:00:00') >= hoje)
    .sort((a,b) => new Date(a.Data) - new Date(b.Data))
    .slice(0, 4);

  if (proximos.length === 0) {
    list.innerHTML = '<li style="color:var(--text3);font-size:13px;padding:12px 0">Nenhum evento próximo. <span style="cursor:pointer;color:var(--teal)" onclick="showPage(\'agenda\')">Ver agenda →</span></li>';
    return;
  }

  list.innerHTML = proximos.map((ev, i) => {
    const d   = new Date(ev.Data + 'T00:00:00');
    const dt  = d.toLocaleDateString('pt-BR',{day:'2-digit',month:'short'}).replace('.','');
    const cor = tl_colors[i % tl_colors.length];
    const ico = tl_icons[i % tl_icons.length];
    const hora = ev.HoraInicio ? ` • ${ev.HoraInicio}` : '';
    const local= ev.Local      ? ` • ${esc(ev.Local)}` : '';
    return `<li class="timeline-item">
      <div class="tl-dot ${cor}"><i class="fas ${ico}"></i></div>
      <div class="tl-info">
        <div class="tl-title">${esc(ev.Titulo)}</div>
        <div class="tl-meta">${dt}${hora}${local}</div>
      </div>
    </li>`;
  }).join('');
}

function renderHomeMembros(data) {
  const tbody = document.getElementById('home-membros-tbody');
  if (!tbody) return;

  if (!data || data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text3)">Nenhum membro cadastrado ainda.</td></tr>';
    return;
  }

  const recent = data.slice(-5).reverse();
  tbody.innerHTML = recent.map(m => {
    const cor = setorCor(m.Setor);
    const ini = (m.Nome || '?')[0].toUpperCase();
    return `<tr>
      <td><div class="td-name"><div class="td-avatar" style="background:${cor.bg};color:${cor.fg}">${ini}</div>${esc(m.Nome)}</div></td>
      <td><span class="badge ${cor.badge}">${esc(m.Setor)}</span></td>
      <td>${esc(m.Periodo)}º</td>
      <td><span class="badge ${statusBadge(m.Status)}">${esc(m.Status)}</span></td>
    </tr>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
//  LOADER — MEMBROS (com paginação e ordenação)
// ══════════════════════════════════════════════════════════════

let _membrosData   = [];   // dataset completo filtrado
let _membrosSortKey = null;
let _membrosSortDir = 1;   // 1 = asc, -1 = desc
let _membrosPagina  = 1;
const _membrosPorPagina = 15;

async function loadMembros() {
  const tbody = document.getElementById('members-table');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--text3)"><i class="fas fa-spinner fa-spin" style="margin-right:8px"></i>Carregando membros…</td></tr>';

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Membros' });

    if (!data || data.length === 0) {
      tbody.innerHTML = `<tr id="members-empty"><td colspan="8" style="text-align:center;padding:32px;color:var(--text3)">
        <i class="fas fa-users" style="font-size:28px;display:block;margin-bottom:12px;opacity:.3"></i>
        Nenhum membro cadastrado. ${isAdmin() ? 'Clique em <strong style="color:var(--teal)">Adicionar membro</strong> para começar.' : ''}
      </td></tr>`;
      document.getElementById('members-pagination').style.display = 'none';
      return;
    }

    _membrosData   = data;
    _membrosPagina = 1;
    _renderMembrosTable();

    // Também atualiza tabela da secretaria e home
    renderSecMembros(data);
    renderHomeMembros(data);

  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--coral)"><i class="fas fa-exclamation-circle"></i> Erro ao carregar: ${esc(e.message)}</td></tr>`;
  }
}

function sortMembros(key) {
  if (_membrosSortKey === key) {
    _membrosSortDir *= -1;
  } else {
    _membrosSortKey = key;
    _membrosSortDir = 1;
  }
  // Atualiza ícones de cabeçalho
  document.querySelectorAll('#page-membros th.sortable').forEach(th => {
    th.classList.remove('sort-asc','sort-desc');
    const ico = th.querySelector('.sort-icon');
    if (ico) ico.textContent = '⇅';
  });
  const activeEl = [...document.querySelectorAll('#page-membros th.sortable')].find(th =>
    th.getAttribute('onclick')?.includes(`'${key}'`)
  );
  if (activeEl) {
    activeEl.classList.add(_membrosSortDir === 1 ? 'sort-asc' : 'sort-desc');
    const ico = activeEl.querySelector('.sort-icon');
    if (ico) ico.textContent = _membrosSortDir === 1 ? '↑' : '↓';
  }
  _membrosPagina = 1;
  _renderMembrosTable();
}

function _getMembrosFiltrados() {
  const setor  = document.getElementById('mbr-filter-setor')?.value  || 'Todos os setores';
  const status = document.getElementById('mbr-filter-status')?.value || 'Todos os status';
  const busca  = (document.querySelector('#page-membros .search-box input')?.value || '').toLowerCase().trim();

  let list = _membrosData.filter(m => {
    const txt = Object.values(m).join(' ').toLowerCase();
    const setorOk  = setor  === 'Todos os setores'  || (m.Setor  || '') === setor;
    const statusOk = status === 'Todos os status'   || (m.Status || '') === status;
    const buscaOk  = !busca || txt.includes(busca);
    return setorOk && statusOk && buscaOk;
  });

  if (_membrosSortKey) {
    list = list.slice().sort((a, b) => {
      let va = String(a[_membrosSortKey] || '');
      let vb = String(b[_membrosSortKey] || '');
      if (!isNaN(va) && !isNaN(vb)) { va = +va; vb = +vb; }
      return va < vb ? -_membrosSortDir : va > vb ? _membrosSortDir : 0;
    });
  }
  return list;
}

function _renderMembrosTable() {
  const tbody   = document.getElementById('members-table');
  const pagWrap = document.getElementById('members-pagination');
  const pagInfo = document.getElementById('members-pag-info');
  const pagBtns = document.getElementById('members-pag-btns');
  if (!tbody) return;

  const filtered = _getMembrosFiltrados();
  const total    = filtered.length;
  const pages    = Math.ceil(total / _membrosPorPagina);
  _membrosPagina = Math.min(_membrosPagina, Math.max(1, pages));

  const inicio = (_membrosPagina - 1) * _membrosPorPagina;
  const slice  = filtered.slice(inicio, inicio + _membrosPorPagina);

  if (slice.length === 0) {
    tbody.innerHTML = `<tr id="members-empty"><td colspan="8" style="text-align:center;padding:32px;color:var(--text3)">
      <i class="fas fa-search" style="font-size:24px;display:block;margin-bottom:10px;opacity:.3"></i>Nenhum membro corresponde ao filtro.
    </td></tr>`;
    if (pagWrap) pagWrap.style.display = 'none';
    return;
  }

  tbody.innerHTML = slice.map(m => {
    const cor = setorCor(m.Setor);
    const ini = (m.Nome || '?')[0].toUpperCase();
    const actionBtns = isAdmin()
      ? `<td style="display:flex;gap:6px">
          <button class="btn btn-outline btn-sm" title="Editar" onclick="editMembro('${esc(m.ID)}')"><i class="fas fa-edit"></i></button>
          <button class="btn btn-outline btn-sm" style="color:var(--coral)" title="Remover" onclick="deleteMembro('${esc(m.ID)}','${esc(m.Nome)}')"><i class="fas fa-trash"></i></button>
         </td>`
      : `<td><span style="font-size:11px;color:var(--text3)">—</span></td>`;
    return `<tr>
      <td><div class="td-name"><div class="td-avatar" style="background:${cor.bg};color:${cor.fg}">${ini}</div>${esc(m.Nome)}</div></td>
      <td><code style="font-family:'DM Mono';font-size:12px;color:var(--text3)">${esc(m.Matricula)}</code></td>
      <td>${esc(m.Periodo)}º</td>
      <td><span class="badge ${cor.badge}">${esc(m.Setor)}</span></td>
      <td>${esc(m.Cargo)}</td>
      <td>${formatDate(m.DataIngresso)}</td>
      <td><span class="badge ${statusBadge(m.Status)}">${esc(m.Status)}</span></td>
      ${actionBtns}
    </tr>`;
  }).join('');

  // Paginação
  if (pagWrap && pagInfo && pagBtns) {
    if (pages <= 1) {
      pagWrap.style.display = 'none';
    } else {
      pagWrap.style.display = 'flex';
      pagInfo.textContent = `${inicio + 1}–${Math.min(inicio + _membrosPorPagina, total)} de ${total} membros`;
      let btns = `<button class="pag-btn" onclick="_membrosPagina=Math.max(1,_membrosPagina-1);_renderMembrosTable()" ${_membrosPagina===1?'disabled':''}><i class="fas fa-chevron-left"></i></button>`;
      for (let p = 1; p <= pages; p++) {
        if (pages <= 7 || Math.abs(p - _membrosPagina) <= 1 || p === 1 || p === pages) {
          btns += `<button class="pag-btn${p===_membrosPagina?' active':''}" onclick="_membrosPagina=${p};_renderMembrosTable()">${p}</button>`;
        } else if (Math.abs(p - _membrosPagina) === 2) {
          btns += `<button class="pag-btn" disabled>…</button>`;
        }
      }
      btns += `<button class="pag-btn" onclick="_membrosPagina=Math.min(${pages},_membrosPagina+1);_renderMembrosTable()" ${_membrosPagina===pages?'disabled':''}><i class="fas fa-chevron-right"></i></button>`;
      pagBtns.innerHTML = btns;
    }
  }
}

// Filtros — agora acionam re-render paginado
function filterMembros() {
  _membrosPagina = 1;
  _renderMembrosTable();
}

function renderSecMembros(data) {
  const tbody = document.querySelector('#sec-membros-ctrl tbody');
  if (!tbody) return;
  if (!data || data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text3)">Nenhum membro cadastrado.</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(m => {
    const cor = setorCor(m.Setor);
    const ini = (m.Nome || '?')[0].toUpperCase();
    const editBtn = isAdmin()
      ? `<button class="btn btn-outline btn-sm" onclick="editMembro('${esc(m.ID)}')"><i class="fas fa-edit"></i></button>`
      : `<span style="font-size:11px;color:var(--text3)">—</span>`;
    return `<tr>
      <td><div class="td-name"><div class="td-avatar" style="background:${cor.bg};color:${cor.fg}">${ini}</div>${esc(m.Nome)}</div></td>
      <td><code style="font-family:'DM Mono';font-size:12px;color:var(--text3)">${esc(m.Matricula)}</code></td>
      <td>${esc(m.Periodo)}º</td>
      <td><span class="badge ${cor.badge}">${esc(m.Setor)}</span></td>
      <td>${formatDate(m.DataIngresso)}</td>
      <td><span class="badge ${statusBadge(m.Status)}">${esc(m.Status)}</span></td>
      <td>${editBtn}</td>
    </tr>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
//  LOADER — SECRETARIA
// ══════════════════════════════════════════════════════════════

async function loadSecretaria() {
  loadMembros();
  loadAtas();
  loadCorrespondencias();
}

async function loadAtas() {
  const container = document.getElementById('atas-list-container');
  if (!container) return;
  setLoadingMsg('atas-list-container', 'Carregando atas…');

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Atas' });

    // Atualiza contador dinâmico
    const labelEl = document.getElementById('atas-counter-label');
    if (labelEl) {
      const ano = new Date().getFullYear();
      const cnt = data ? data.filter(a => String(a.Data || '').startsWith(String(ano))).length : 0;
      labelEl.textContent = cnt > 0 ? `${cnt} ata(s) registrada(s) em ${ano}` : `Nenhuma ata em ${ano}`;
    }

    if (!data || data.length === 0) {
      setEmptyMsg('atas-list-container', 'fa-file-alt', 'Nenhuma ata registrada ainda.');
      return;
    }

    container.innerHTML = data
      .sort((a,b) => new Date(b.Data) - new Date(a.Data))
      .map(ata => {
        const editBtn = isAdmin()
          ? `<button class="btn btn-outline btn-sm" style="margin-left:auto" onclick="editAta('${esc(ata.ID)}')"><i class="fas fa-edit"></i></button>`
          : '';
        return `<div class="ata-card" onclick="verAta('${esc(ata.ID)}','${esc(ata.Titulo)}')">
          <div class="ata-title">${esc(ata.Titulo)}</div>
          <div class="ata-meta">
            <span><i class="fas fa-calendar"></i> ${formatDate(ata.Data)}</span>
            <span><i class="fas fa-users"></i> ${esc(ata.Presentes)} presentes</span>
            <span><i class="fas fa-clock"></i> ${esc(ata.Duracao)}</span>
            <span class="badge ${statusBadge(ata.Status)}">${esc(ata.Status)}</span>
            ${editBtn}
          </div>
        </div>`;
      }).join('');
  } catch(e) {
    setEmptyMsg('atas-list-container', 'fa-exclamation-circle', 'Erro ao carregar atas.');
  }
}

async function verAta(id, titulo) {
  const modalTitle = document.querySelector('#modal-ver-ata .modal-title');
  if (modalTitle) modalTitle.textContent = titulo || 'Ata';

  // Tenta buscar conteúdo real da ata
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Atas' });
    const ata  = data?.find(a => String(a.ID) === String(id));
    if (ata) {
      const pautaEl = document.querySelector('#modal-ver-ata .ata-pauta-content');
      const delibEl = document.querySelector('#modal-ver-ata .ata-delib-content');
      const metaEl  = document.querySelector('#modal-ver-ata .ata-meta-info');
      if (metaEl) metaEl.innerHTML = `<i class="fas fa-calendar"></i> ${formatDate(ata.Data)} &nbsp;|&nbsp; <i class="fas fa-clock"></i> ${ata.Duracao || '—'} &nbsp;|&nbsp; <i class="fas fa-users"></i> ${ata.Presentes || '—'} presentes`;
      if (pautaEl && ata.Pauta) pautaEl.innerHTML = ata.Pauta.split('\n').map(l => `<li>${esc(l)}</li>`).join('');
      if (delibEl && ata.Deliberacoes) delibEl.innerHTML = ata.Deliberacoes.split('\n').map(l => `<li>${esc(l)}</li>`).join('');
      // Botão download com URL real do Drive se existir
      const dlBtn = document.querySelector('#modal-ver-ata .btn-download-ata');
      if (dlBtn && ata.DriveUrl) {
        dlBtn.onclick = () => window.open(ata.DriveUrl, '_blank');
      }
      // Botão editar na ata visualizada
      const editBtnVer = document.querySelector('#modal-ver-ata .btn-edit-ata');
      if (editBtnVer) editBtnVer.onclick = () => { closeModal('modal-ver-ata'); editAta(id); };
    }
  } catch(e) { /* Mostra dados estáticos se API falhar */ }

  openModal('modal-ver-ata');
}

// editAta implementado acima

// ══════════════════════════════════════════════════════════════
//  LOADER — TESOURARIA
// ══════════════════════════════════════════════════════════════

async function loadTesouraria() {
  const container = document.getElementById('finance-movimentacoes');
  if (!container) return;
  setLoadingMsg('finance-movimentacoes', 'Carregando movimentações…');

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Financeiro' });

    if (!data || data.length === 0) {
      setEmptyMsg('finance-movimentacoes', 'fa-receipt', 'Nenhum lançamento registrado ainda.');
      // Mostra indicadores editáveis mesmo sem dados
      _aplicarIndicadoresLocais();
      return;
    }

    let saldo = 0, recMes = 0, despMes = 0;
    const hoje = new Date();
    const catTotals = {};

    data.forEach(mov => {
      const v    = parseFloat(mov.Valor) || 0;
      const isRec= String(mov.Tipo).toLowerCase() === 'receita';
      saldo += isRec ? v : -v;
      const d = new Date((mov.Data || '') + 'T00:00:00');
      if (!isNaN(d) && d.getMonth()===hoje.getMonth() && d.getFullYear()===hoje.getFullYear()) {
        if (isRec) recMes += v; else despMes += v;
      }
      if (!isRec && mov.Categoria) {
        catTotals[mov.Categoria] = (catTotals[mov.Categoria] || 0) + v;
      }
    });

    const fmt = v => 'R$ ' + Math.abs(v).toLocaleString('pt-BR',{minimumFractionDigits:2,maximumFractionDigits:2});

    // ── Atualiza os 4 stat cards ──────────────────────────
    const s = document.getElementById('tesour-saldo-val');
    const sc= document.getElementById('tesour-saldo-change');
    const r = document.getElementById('tesour-rec-val');
    const rc= document.getElementById('tesour-rec-change');
    const d2= document.getElementById('tesour-desp-val');
    const dc= document.getElementById('tesour-desp-change');

    if (s)  s.textContent  = fmt(saldo);
    if (sc) sc.innerHTML   = '<i class="fas fa-sync-alt"></i> Atualizado agora';
    if (r)  r.textContent  = fmt(recMes);
    if (rc) rc.innerHTML   = '<i class="fas fa-arrow-up"></i> Este mês';
    if (d2) d2.textContent = fmt(despMes);
    if (dc) dc.innerHTML   = '<i class="fas fa-arrow-down"></i> Este mês';

    // Atualiza também o card de saldo na home (se estiver visível)
    const homeS = document.getElementById('home-saldo-val');
    if (homeS && homeS.textContent === '—') homeS.textContent = fmt(saldo);

    // ── Indicadores editáveis (inadimplência etc.) ────────
    _aplicarIndicadoresLocais();

    // ── Distribuição de despesas (dinâmico) ───────────────
    const totalDesp = Object.values(catTotals).reduce((a,b)=>a+b, 0);
    const distrEl = document.getElementById('finance-distribuicao-despesas');
    if (distrEl) {
      if (totalDesp > 0) {
        const sorted = Object.entries(catTotals).sort((a,b)=>b[1]-a[1]).slice(0,5);
        const colors = ['var(--teal)','var(--lavender)','var(--gold)','var(--sage)','var(--coral)'];
        distrEl.innerHTML = `<div style="display:flex;flex-direction:column;gap:14px">${sorted.map(([cat, val], i) => {
          const pct = Math.round(val/totalDesp*100);
          return `<div>
            <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px">
              <span>${esc(cat)}</span><strong>${pct}%</strong>
            </div>
            <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${colors[i]}"></div></div>
          </div>`;
        }).join('')}</div>`;
      } else {
        distrEl.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text3);font-size:13px"><i class="fas fa-chart-pie" style="font-size:24px;display:block;margin-bottom:8px;opacity:.3"></i>Sem despesas registradas para calcular.</div>';
      }
    }

    // ── Próximo prazo de prestação de contas (via Configuracoes) ─
    const prazoEl = document.getElementById('proximo-prazo-contas');
    if (prazoEl) {
      const cfgs = await _carregarConfiguracoes();
      const prazo = cfgs['prazo_prestacao_contas']?.valor;
      prazoEl.textContent = prazo ? formatDate(prazo) : '—';
    }

    // ── Lista de movimentações ────────────────────────────
    container.innerHTML = data
      .sort((a,b) => new Date(b.Data) - new Date(a.Data))
      .slice(0, 12)
      .map(mov => {
        const isRec = String(mov.Tipo).toLowerCase() === 'receita';
        const v = parseFloat(mov.Valor) || 0;
        return `<div class="finance-row">
          <div>
            <div class="finance-desc">${esc(mov.Descricao)}</div>
            <div class="finance-cat">${esc(mov.Tipo)} • ${esc(mov.Categoria)} • ${formatDate(mov.Data)}</div>
          </div>
          <div class="finance-val ${isRec?'pos':'neg'}">${isRec?'+':'−'} R$ ${v.toFixed(2).replace('.',',')}</div>
        </div>`;
      }).join('');

  } catch(e) {
    setEmptyMsg('finance-movimentacoes', 'fa-exclamation-circle', 'Erro ao carregar movimentações.');
    _aplicarIndicadoresLocais();
  }
}

// ══════════════════════════════════════════════════════════════
//  LOADER — AGENDA
// ══════════════════════════════════════════════════════════════

async function loadAgenda() {
  const container = document.getElementById('agenda-list-container');
  if (!container) return;
  setLoadingMsg('agenda-list-container', 'Carregando eventos…');

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Eventos' });

    if (!data || data.length === 0) {
      setEmptyMsg('agenda-list-container', 'fa-calendar-alt', 'Nenhum evento cadastrado ainda.');
      renderCalendar(_calYear, _calMonth, []); // garante calendário vazio renderizado
      return;
    }

    container.innerHTML = data
      .sort((a,b) => new Date(a.Data) - new Date(b.Data))
      .map(ev => {
        const d = new Date((ev.Data || '2026-01-01') + 'T00:00:00');
        const mes = d.toLocaleString('pt-BR',{month:'short'}).toUpperCase().replace('.','');
        const dia = d.getDate();
        const cor = setorCor(ev.Tipo);
        const editBtn = isAdmin()
          ? `<button class="btn btn-outline btn-sm" onclick="editEvento('${esc(ev.ID)}')"><i class="fas fa-edit"></i></button>
             <button class="btn btn-outline btn-sm" style="color:var(--coral)" onclick="deleteEvento('${esc(ev.ID)}','${esc(ev.Titulo)}')"><i class="fas fa-trash"></i></button>`
          : '';
        return `<div class="card gap-20" style="margin-bottom:16px">
          <div style="display:flex;gap:12px;align-items:center">
            <div style="background:${cor.bg};border:1px solid ${cor.bd};border-radius:12px;padding:10px 20px;text-align:center;flex-shrink:0">
              <div style="font-size:10px;color:${cor.fg};text-transform:uppercase;letter-spacing:1px">${mes}</div>
              <div style="font-family:'Playfair Display',serif;font-size:28px;font-weight:700;color:${cor.fg}">${dia}</div>
            </div>
            <div style="flex:1">
              <div style="font-size:16px;font-weight:700;margin-bottom:4px">${esc(ev.Titulo)}</div>
              <div style="font-size:13px;color:var(--text2)">
                <i class="fas fa-clock"></i> ${esc(ev.HoraInicio)}–${esc(ev.HoraFim)}
                &nbsp;|&nbsp;<i class="fas fa-map-marker-alt"></i> ${esc(ev.Local)}
                ${ev.Responsavel ? `&nbsp;|&nbsp;<i class="fas fa-user"></i> ${esc(ev.Responsavel)}` : ''}
              </div>
            </div>
            <div style="display:flex;gap:8px;align-items:center">
              <span class="badge ${cor.badge}">${esc(ev.Tipo)}</span>
              ${editBtn}
            </div>
          </div>
        </div>`;
      }).join('');

    // Atualiza também o mini-calendário com os dados carregados
    renderCalendar(_calYear, _calMonth, data);

  } catch(e) {
    setEmptyMsg('agenda-list-container', 'fa-exclamation-circle', 'Erro ao carregar agenda.');
    renderCalendar(_calYear, _calMonth, []); // garante calendário vazio mesmo em caso de erro
  }
}

async function editEvento(id) {
  if (!requireAdmin('editar eventos')) return;
  showToast('Buscando dados do evento…', 'info');
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Eventos' });
    const ev   = data?.find(e => String(e.ID) === String(id));
    if (!ev) { showToast('Evento não encontrado.', 'error'); return; }
    const modal = document.getElementById('modal-edit-evento');
    document.getElementById('edit-evento-id').value        = ev.ID;
    document.getElementById('edit-evento-titulo').value    = ev.Titulo    || '';
    document.getElementById('edit-evento-data').value      = ev.Data      || '';
    document.getElementById('edit-evento-horainicio').value= ev.HoraInicio|| '';
    document.getElementById('edit-evento-horafim').value   = ev.HoraFim   || '';
    document.getElementById('edit-evento-local').value     = ev.Local     || '';
    document.getElementById('edit-evento-resp').value      = ev.Responsavel|| '';
    document.getElementById('edit-evento-desc').value      = ev.Descricao || '';
    const tipSel = document.getElementById('edit-evento-tipo');
    if (tipSel) [...tipSel.options].forEach(o => { o.selected = o.value === ev.Tipo; });
    openModal('modal-edit-evento');
  } catch(e) { showToast('Erro: ' + e.message, 'error'); }
}

async function salvarEdicaoEvento() {
  if (!requireAdmin('editar eventos')) return;
  const modal = document.getElementById('modal-edit-evento');
  const id    = document.getElementById('edit-evento-id').value;
  const row   = {
    Titulo:     document.getElementById('edit-evento-titulo').value.trim(),
    Tipo:       document.getElementById('edit-evento-tipo').value,
    Data:       document.getElementById('edit-evento-data').value,
    HoraInicio: document.getElementById('edit-evento-horainicio').value,
    HoraFim:    document.getElementById('edit-evento-horafim').value,
    Local:      document.getElementById('edit-evento-local').value.trim(),
    Responsavel:document.getElementById('edit-evento-resp').value.trim(),
    Descricao:  document.getElementById('edit-evento-desc').value.trim(),
  };
  if (!row.Titulo) { showToast('Informe o título do evento.', 'warning'); return; }
  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';
  try {
    await apiPost({ action: 'update', sheet: 'Eventos', id, row });
    closeModal('modal-edit-evento');
    showToast('Evento atualizado!', 'success');
    loadAgenda();
  } catch(e) {
    showToast('Erro: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> Salvar';
  }
}

async function editProjeto(id) {
  if (!requireAdmin('editar projetos')) return;
  showToast('Buscando dados do projeto…', 'info');
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Pesquisas' });
    const p    = data?.find(x => String(x.ID) === String(id));
    if (!p) { showToast('Projeto não encontrado.', 'error'); return; }
    const modal = document.getElementById('modal-edit-projeto');
    document.getElementById('edit-proj-id').value      = p.ID;
    document.getElementById('edit-proj-titulo').value  = p.Titulo      || '';
    document.getElementById('edit-proj-caae').value    = p.CAAE        || '';
    document.getElementById('edit-proj-pesq').value    = p.Pesquisadores|| '';
    document.getElementById('edit-proj-prog').value    = p.Progresso   || '0';
    document.getElementById('edit-proj-desc').value    = p.Descricao   || '';
    const stSel  = document.getElementById('edit-proj-status');
    if (stSel)  [...stSel.options].forEach(o => { o.selected = o.value === p.Status; });
    openModal('modal-edit-projeto');
  } catch(e) { showToast('Erro: ' + e.message, 'error'); }
}

async function salvarEdicaoProjeto() {
  if (!requireAdmin('editar projetos')) return;
  const modal = document.getElementById('modal-edit-projeto');
  const id    = document.getElementById('edit-proj-id').value;
  const row   = {
    Titulo:       document.getElementById('edit-proj-titulo').value.trim(),
    Status:       document.getElementById('edit-proj-status').value,
    CAAE:         document.getElementById('edit-proj-caae').value.trim(),
    Pesquisadores:document.getElementById('edit-proj-pesq').value,
    Progresso:    document.getElementById('edit-proj-prog').value,
    Descricao:    document.getElementById('edit-proj-desc').value.trim(),
  };
  if (!row.Titulo) { showToast('Informe o título.', 'warning'); return; }
  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';
  try {
    await apiPost({ action: 'update', sheet: 'Pesquisas', id, row });
    closeModal('modal-edit-projeto');
    showToast('Projeto atualizado!', 'success');
    loadPesquisa();
  } catch(e) {
    showToast('Erro: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> Salvar';
  }
}

async function editAta(id) {
  if (!requireAdmin('editar atas')) return;
  showToast('Buscando dados da ata…', 'info');
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Atas' });
    const ata  = data?.find(a => String(a.ID) === String(id));
    if (!ata) { showToast('Ata não encontrada.', 'error'); return; }
    document.getElementById('edit-ata-id').value      = ata.ID;
    document.getElementById('edit-ata-titulo').value  = ata.Titulo    || '';
    document.getElementById('edit-ata-data').value    = ata.Data      || '';
    document.getElementById('edit-ata-presentes').value = ata.Presentes|| '';
    document.getElementById('edit-ata-duracao').value = ata.Duracao   || '';
    document.getElementById('edit-ata-pauta').value   = ata.Pauta     || '';
    document.getElementById('edit-ata-delib').value   = ata.Deliberacoes|| '';
    const stSel = document.getElementById('edit-ata-status');
    if (stSel) [...stSel.options].forEach(o => { o.selected = o.value === ata.Status; });
    openModal('modal-edit-ata');
  } catch(e) { showToast('Erro: ' + e.message, 'error'); }
}

async function salvarEdicaoAta() {
  if (!requireAdmin('editar atas')) return;
  const modal = document.getElementById('modal-edit-ata');
  const id    = document.getElementById('edit-ata-id').value;
  const row   = {
    Titulo:       document.getElementById('edit-ata-titulo').value.trim(),
    Data:         document.getElementById('edit-ata-data').value,
    Presentes:    document.getElementById('edit-ata-presentes').value,
    Duracao:      document.getElementById('edit-ata-duracao').value.trim(),
    Pauta:        document.getElementById('edit-ata-pauta').value.trim(),
    Deliberacoes: document.getElementById('edit-ata-delib').value.trim(),
    Status:       document.getElementById('edit-ata-status').value,
  };
  if (!row.Titulo) { showToast('Informe o título.', 'warning'); return; }
  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';
  try {
    await apiPost({ action: 'update', sheet: 'Atas', id, row });
    closeModal('modal-edit-ata');
    showToast('Ata atualizada!', 'success');
    loadAtas();
  } catch(e) {
    showToast('Erro: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> Salvar';
  }
}

async function deleteEvento(id, nome) {
  if (!requireAdmin('excluir eventos')) return;
  customConfirm({
    title: 'Excluir evento',
    message: `Deseja realmente excluir o evento "${nome}"? Esta ação não pode ser desfeita.`,
    confirmLabel: 'Excluir',
    icon: 'fa-calendar-times',
    onConfirm: async () => {
      try {
        await apiPost({ action: 'delete', sheet: 'Eventos', id });
        showToast('Evento excluído.', 'success');
        loadAgenda();
      } catch(e) { showToast('Erro: ' + e.message, 'error'); }
    }
  });
}

// ══════════════════════════════════════════════════════════════
//  LOADER — PESQUISA
// ══════════════════════════════════════════════════════════════

async function loadPesquisa() {
  const grid = document.getElementById('pesquisa-grid');
  if (!grid) return;
  grid.innerHTML = '<div style="text-align:center;padding:32px;color:var(--text3);grid-column:1/-1"><i class="fas fa-spinner fa-spin" style="margin-right:8px"></i>Carregando projetos…</div>';

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Pesquisas' });

    // Atualiza stats dinâmicos
    _updatePesquisaStats(data);

    if (!data || data.length === 0) {
      grid.innerHTML = '<div style="text-align:center;padding:32px;color:var(--text3);grid-column:1/-1"><i class="fas fa-flask" style="font-size:28px;display:block;margin-bottom:12px;opacity:.3"></i>Nenhum projeto cadastrado ainda.</div>';
      return;
    }

    grid.innerHTML = data.map(p => {
      const prog = parseInt(p.Progresso) || 0;
      const editBtn = isAdmin()
        ? `<button class="btn btn-outline btn-sm" onclick="editProjeto('${esc(p.ID)}')"><i class="fas fa-edit"></i></button>`
        : '';
      return `<div class="research-card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <span class="badge ${statusBadge(p.Status)}">${esc(p.Status)}</span>
          <div style="display:flex;align-items:center;gap:8px">
            <span style="font-size:12px;color:var(--text3)">${p.CAAE ? 'CAAE: '+esc(p.CAAE) : 'CEP pendente'}</span>
            ${editBtn}
          </div>
        </div>
        <div class="research-title">${esc(p.Titulo)}</div>
        <div class="research-desc">${esc(p.Descricao)}</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:10px">
          <i class="fas fa-users"></i> ${esc(p.Pesquisadores)} pesquisadores &nbsp;•&nbsp;
          <i class="fas fa-tag"></i> ${esc(p.TipoEstudo)}
        </div>
        <div style="font-size:12px;margin-bottom:4px;display:flex;justify-content:space-between">
          <span>Progresso</span><strong>${prog}%</strong>
        </div>
        <div class="progress-bar"><div class="progress-fill" style="width:${prog}%;${prog===100?'background:var(--sage)':''}"></div></div>
      </div>`;
    }).join('');
  } catch(e) {
    grid.innerHTML = '<div style="text-align:center;padding:32px;color:var(--coral);grid-column:1/-1">Erro ao carregar projetos.</div>';
  }
}

// editProjeto e editAta implementados acima

// ══════════════════════════════════════════════════════════════
//  LOADER — EXTENSÃO
// ══════════════════════════════════════════════════════════════

async function loadExtensao() {
  const container = document.getElementById('extensao-acoes');
  if (!container) return;

  try {
    // Carrega ações e parceiros em paralelo
    const [data, parceiros] = await Promise.all([
      apiGet({ action: 'getAll', sheet: 'Extensao' }),
      apiGet({ action: 'getAll', sheet: 'Parceiros' }),
    ]);

    // ── Atualiza stats dinâmicos ───────────────────────────
    _updateExtensaoStats(data);

    // ── Atualiza stat de parcerias com dado real ───────────
    const totalParc = parceiros ? parceiros.filter(p => p.Status === 'Ativo').length : 0;
    const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setEl('ext-stat-parcerias',    totalParc > 0 ? totalParc : '—');
    setEl('ext-stat-parcerias-sub', totalParc > 0 ? `${totalParc} parceiro(s) ativo(s)` : 'Nenhum parceiro cadastrado');

    // ── Lista de ações ─────────────────────────────────────
    if (!data || data.length === 0) {
      container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text3)">Nenhuma ação registrada ainda.</div>';
    } else {
      container.innerHTML = data
        .sort((a,b) => new Date(b.Data) - new Date(a.Data))
        .slice(0, 8)
        .map(ac => `<div class="finance-row">
          <div>
            <div class="finance-desc">${esc(ac.Nome)}</div>
            <div class="finance-cat">${formatDate(ac.Data)} • ${esc(ac.Participantes)} participantes • ${esc(ac.Local)}</div>
          </div>
          <span class="badge ${statusBadge(ac.Status)}">${esc(ac.Status)}</span>
        </div>`).join('');
    }

    // ── Lista de parceiros (dinâmica) ──────────────────────
    const parcEl = document.getElementById('extensao-parceiros-list');
    if (parcEl) {
      if (!parceiros || parceiros.length === 0) {
        parcEl.innerHTML =
          '<div style="text-align:center;padding:20px;color:var(--text3);font-size:13px">' +
          '<i class="fas fa-handshake" style="font-size:22px;display:block;margin-bottom:8px;opacity:.3"></i>' +
          'Nenhum parceiro cadastrado ainda.<br>' +
          '<span style="font-size:11px">Adicione registros na aba "Parceiros" da planilha.</span></div>';
      } else {
        parcEl.innerHTML = parceiros
          .sort((a, b) => {
            // Ativos primeiro
            if (a.Status === 'Ativo' && b.Status !== 'Ativo') return -1;
            if (b.Status === 'Ativo' && a.Status !== 'Ativo') return 1;
            return (a.Nome || '').localeCompare(b.Nome || '');
          })
          .map(p => `<div class="finance-row">
            <div>
              <div class="finance-desc">${esc(p.Nome)}</div>
              <div class="finance-cat">${esc(p.Descricao || p.Area || '—')}</div>
            </div>
            <span class="badge ${statusBadge(p.Status)}">${esc(p.Status || '—')}</span>
          </div>`).join('');
      }
    }
  } catch(e) { console.warn('loadExtensao:', e); }
}

// ══════════════════════════════════════════════════════════════
//  LOADER — ENSINO
// ══════════════════════════════════════════════════════════════

async function loadEnsino() {
  const grid = document.getElementById('ensino-cursos-grid');
  if (!grid) return;
  grid.innerHTML = '<div style="text-align:center;padding:32px;color:var(--text3);grid-column:1/-1"><i class="fas fa-spinner fa-spin" style="margin-right:6px"></i>Carregando cursos…</div>';

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Cursos' });

    // Atualiza stats dinâmicos
    _updateEnsinoStats(data);

    if (!data || data.length === 0) {
      grid.innerHTML = '<div style="text-align:center;padding:32px;color:var(--text3);grid-column:1/-1"><i class="fas fa-graduation-cap" style="font-size:28px;display:block;margin-bottom:12px;opacity:.3"></i>Nenhum curso cadastrado ainda.</div>';
      return;
    }
    grid.innerHTML = data.map(c => {
      const prog    = parseInt(c.Progresso) || 0;
      const editBtn = isAdmin()
        ? `<button class="btn btn-outline btn-sm" style="margin-top:10px;width:100%" onclick="editCurso('${esc(String(c.ID))}')"><i class="fas fa-edit"></i> Editar</button>`
        : '';
      return `<div class="research-card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
          <span class="badge ${statusBadge(c.Status)}">${esc(c.Status)}</span>
          <span style="font-size:11px;color:var(--text3)">${c.DataInicio ? formatDate(c.DataInicio) : 'Sem data'}</span>
        </div>
        <div class="research-title">${esc(c.Titulo)}</div>
        <div class="research-desc">${esc(c.Descricao)}</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:8px">
          <i class="fas fa-clock"></i> ${esc(c.CargaHoraria) || '—'}h &nbsp;•&nbsp;
          <i class="fas fa-users"></i> ${esc(c.Vagas) || '—'} vagas &nbsp;•&nbsp;
          <i class="fas fa-laptop"></i> ${esc(c.Modalidade) || '—'}
        </div>
        <div style="font-size:12px;margin-bottom:4px;display:flex;justify-content:space-between">
          <span>Progresso</span><strong>${prog}%</strong>
        </div>
        <div class="progress-bar"><div class="progress-fill" style="width:${prog}%"></div></div>
        ${editBtn}
      </div>`;
    }).join('');
  } catch(e) {
    grid.innerHTML = '<div style="text-align:center;padding:32px;color:var(--coral);grid-column:1/-1">Erro ao carregar cursos.</div>';
    console.warn('loadEnsino:', e);
  }
}

// ══════════════════════════════════════════════════════════════
//  LOADER — OUVIDORIA
// ══════════════════════════════════════════════════════════════

async function loadOuvidoria() {
  // ── helpers de referência ─────────────────────────────────
  const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const listEl = document.getElementById('ouv-solicitacoes-list');

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Ouvidoria' });

    if (!data || data.length === 0) {
      // Zera stat cards
      setEl('ouv-stat-pendentes',  '0');
      setEl('ouv-stat-analise',    '0');
      setEl('ouv-stat-resolvidos', '0');
      setEl('ouv-stat-total',      '0');
      if (listEl) listEl.innerHTML =
        '<div style="text-align:center;padding:28px;color:var(--text3)">' +
        '<i class="fas fa-inbox" style="font-size:24px;display:block;margin-bottom:10px;opacity:.3"></i>' +
        'Nenhuma manifestação registrada ainda.</div>';
      return;
    }

    // ── Contagens por status ───────────────────────────────
    const pendentes  = data.filter(o => o.Status === 'Pendente').length;
    const emAnalise  = data.filter(o => o.Status === 'Em análise').length;
    const resolvidos = data.filter(o => o.Status === 'Resolvido').length;
    const total      = data.length;

    setEl('ouv-stat-pendentes',  pendentes);
    setEl('ouv-stat-analise',    emAnalise);
    setEl('ouv-stat-resolvidos', resolvidos);
    setEl('ouv-stat-total',      total);

    // ── Lista de solicitações abertas (não-resolvidas) ─────
    if (listEl) {
      const abertas = data
        .filter(o => o.Status !== 'Resolvido')
        .sort((a, b) => new Date(b.Data) - new Date(a.Data))
        .slice(0, 5);

      if (abertas.length === 0) {
        listEl.innerHTML =
          '<div style="text-align:center;padding:24px;color:var(--sage)">' +
          '<i class="fas fa-check-circle" style="font-size:22px;display:block;margin-bottom:8px"></i>' +
          'Nenhuma solicitação em aberto.</div>';
      } else {
        listEl.innerHTML = abertas.map(o => {
          const num  = String(o.ID || '').slice(-4) || '????';
          const desc = o.Mensagem ? o.Mensagem.substring(0, 70) + (o.Mensagem.length > 70 ? '…' : '') : '—';
          return `<div class="finance-row">
            <div>
              <div class="finance-desc">${esc(o.Tipo || 'Manifestação')}: ${esc(desc)}</div>
              <div class="finance-cat">#${esc(num)} • Anônimo • ${formatDate(o.Data)} • ${esc(o.Tipo || '—')}</div>
            </div>
            <span class="badge ${statusBadge(o.Status)}">${esc(o.Status || '—')}</span>
          </div>`;
        }).join('');
      }
    }
  } catch(e) {
    console.warn('loadOuvidoria:', e);
    // Em caso de erro, exibe indicadores zerados para não deixar skeleton
    setEl('ouv-stat-pendentes',  '—');
    setEl('ouv-stat-analise',    '—');
    setEl('ouv-stat-resolvidos', '—');
    setEl('ouv-stat-total',      '—');
    if (listEl) listEl.innerHTML =
      '<div style="text-align:center;padding:20px;color:var(--coral)">' +
      '<i class="fas fa-exclamation-circle"></i> Erro ao carregar manifestações.</div>';
  }
}

// ══════════════════════════════════════════════════════════════
//  LOADER — MARKETING
// ══════════════════════════════════════════════════════════════

async function loadMarketing() {
  // ── Aplica indicadores via API ────────────────────────────
  _aplicarTodosIndicadores();

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'TarefasMarketing' });

    // ── Mapeamento exato Status → coluna ──────────────────
    const cols = {
      'Ideia':     'backlog-col',
      'Backlog':   'backlog-col',   // alias explícito — evita fallback silencioso
      'Produção':  'producao-col',
      'Revisão':   'revisao-col',
      'Publicado': 'publicado-col',
    };

    const colTitles = {
      'backlog-col':   { emoji:'📋', label:'Backlog',      badge:'teal'  },
      'producao-col':  { emoji:'🛠',  label:'Em Produção',  badge:'gold'  },
      'revisao-col':   { emoji:'🔍', label:'Revisão',      badge:'coral' },
      'publicado-col': { emoji:'✅', label:'Publicado',    badge:'sage'  },
    };

    // Limpa apenas cards dinâmicos (mantém estáticos se API vazia)
    Object.values(cols).forEach(colId => {
      const col = document.getElementById(colId);
      if (!col) return;
      col.querySelectorAll('.kanban-card[data-task-id]').forEach(el => el.remove());
    });

    if (!data || data.length === 0) {
      // Recalcula contadores com base nos cards estáticos restantes
      Object.entries(cols).forEach(([, colId]) => {
        const col = document.getElementById(colId);
        const info = colTitles[colId];
        if (!col || !info) return;
        const cnt = col.querySelectorAll('.kanban-card').length;
        const titleEl = col.querySelector('.kanban-col-title');
        if (titleEl) titleEl.innerHTML = `${info.emoji} ${info.label} <span class="badge ${info.badge}">${cnt}</span>`;
      });
      return;
    }

    // Organiza contagens por coluna
    const counts = { 'backlog-col':0,'producao-col':0,'revisao-col':0,'publicado-col':0 };

    data.forEach(t => {
      // Mapeamento direto por Status exato; fallback para Backlog com aviso
      const colId = cols[t.Status];
      if (!colId) {
        console.warn(`[Kanban] Status desconhecido "${t.Status}" na tarefa ID=${t.ID} — alocado em Backlog por fallback.`);
      }
      const resolvedColId = colId || 'backlog-col';
      const col   = document.getElementById(resolvedColId);
      if (!col) return;

      counts[resolvedColId] = (counts[resolvedColId] || 0) + 1;

      // Evita duplicata
      if (col.querySelector(`[data-task-id="${CSS.escape(String(t.ID))}"]`)) return;

      const cor  = setorCor(t.Formato);
      const card = document.createElement('div');
      card.className = 'kanban-card';
      card.setAttribute('data-task-id', String(t.ID));
      const editBtn = isAdmin()
        ? `<button class="btn btn-outline btn-sm" style="margin-left:auto;padding:3px 8px;font-size:11px"
             onclick="excluirTarefaMkt('${esc(String(t.ID))}','${esc(t.Titulo)}')" title="Excluir">
             <i class="fas fa-trash" style="color:var(--coral)"></i></button>`
        : '';
      card.innerHTML = `
        <div style="display:flex;align-items:flex-start;justify-content:space-between">
          <div class="kanban-card-title" style="flex:1">${esc(t.Titulo)}</div>
          ${editBtn}
        </div>
        <div class="kanban-card-meta">
          <span class="badge ${cor.badge}">${esc(t.Formato || '—')}</span>
          ${t.Prazo ? ' • ' + formatDate(t.Prazo) : ''}
          ${t.Responsavel ? `<span style="font-size:10px;color:var(--text3);display:block;margin-top:3px"><i class="fas fa-user"></i> ${esc(t.Responsavel)}</span>` : ''}
        </div>`;
      col.appendChild(card);
    });

    // Atualiza contadores das colunas (API + estáticos)
    Object.entries(counts).forEach(([colId, cnt]) => {
      const info = colTitles[colId];
      const col  = document.getElementById(colId);
      if (!col || !info) return;
      const total = col.querySelectorAll('.kanban-card').length;
      const titleEl = col.querySelector('.kanban-col-title');
      if (titleEl) titleEl.innerHTML = `${info.emoji} ${info.label} <span class="badge ${info.badge}">${total}</span>`;
    });

    // Activa drag-and-drop após renderizar os cards
    _initKanbanDnD();

  } catch(e) { console.warn('loadMarketing:', e); }

  // ── Carrega campanhas da sheet Campanhas (ou TarefasMarketing filtrada) ──
  try {
    const campEl = document.getElementById('mkt-campanhas-list');
    if (campEl) {
      const campData = await apiGet({ action: 'getAll', sheet: 'Campanhas' });
      if (!campData || campData.length === 0) {
        campEl.innerHTML = '<div style="padding:12px;color:var(--text3);font-size:13px;text-align:center"><i class="fas fa-bullhorn" style="font-size:20px;display:block;margin-bottom:8px;opacity:.3"></i>Nenhuma campanha cadastrada.</div>';
      } else {
        campEl.innerHTML = campData.slice(0, 5).map(c => {
          const badgeCls = c.Status === 'Ativa' ? 'sage' : c.Status === 'Encerrada' ? 'coral' : 'gold';
          return `<div class="finance-row">
            <div>
              <div class="finance-desc">${esc(c.Nome || c.Titulo || '—')}</div>
              <div class="finance-cat">${esc(c.Rede || c.Canal || '—')}${c.Periodo ? ' • ' + esc(c.Periodo) : ''}</div>
            </div>
            <span class="badge ${badgeCls}">${esc(c.Status || '—')}</span>
          </div>`;
        }).join('');
      }
    }
  } catch(e) {
    const campEl = document.getElementById('mkt-campanhas-list');
    if (campEl) campEl.innerHTML = '<div style="padding:12px;color:var(--text3);font-size:13px">Configure a sheet <strong>Campanhas</strong> no Google Sheets para listar campanhas aqui.</div>';
  }
}

async function excluirTarefaMkt(id, titulo) {
  if (!requireAdmin('excluir tarefas')) return;
  customConfirm({
    title: 'Excluir tarefa',
    message: `Deseja remover a tarefa "${titulo}" do Kanban?`,
    confirmLabel: 'Excluir',
    icon: 'fa-trash',
    onConfirm: async () => {
      try {
        await apiPost({ action: 'delete', sheet: 'TarefasMarketing', id });
        showToast('Tarefa excluída.', 'success');
        loadMarketing();
      } catch(e) { showToast('Erro: ' + e.message, 'error'); }
    }
  });
}

// ══════════════════════════════════════════════════════════════
//  AÇÕES EM REGISTROS
// ══════════════════════════════════════════════════════════════

function editMembro(id) {
  if (!requireAdmin('editar membros')) return;
  // Busca dados do membro na tabela já carregada
  const rows = document.querySelectorAll('#members-table tr');
  let dadosMembro = null;
  rows.forEach(row => {
    const btn = row.querySelector(`[onclick*="${id}"]`);
    if (btn) {
      const cells = row.querySelectorAll('td');
      dadosMembro = {
        ID:          id,
        Nome:        cells[0]?.querySelector('div:last-child')?.textContent?.trim() || cells[0]?.textContent?.trim() || '',
        Matricula:   cells[1]?.textContent?.trim() || '',
        Periodo:     (cells[2]?.textContent?.trim() || '').replace('º',''),
        Setor:       cells[3]?.textContent?.trim() || '',
        Cargo:       cells[4]?.textContent?.trim() || '',
        Status:      cells[6]?.textContent?.trim() || '',
      };
    }
  });

  const modal = document.getElementById('modal-edit-membro');
  if (!modal) { showToast('Modal de edição não encontrado.', 'error'); return; }

  if (dadosMembro) {
    document.getElementById('edit-membro-id').value       = dadosMembro.ID;
    document.getElementById('edit-membro-nome').value     = dadosMembro.Nome;
    document.getElementById('edit-membro-mat').value      = dadosMembro.Matricula;
    const perSel = document.getElementById('edit-membro-periodo');
    if (perSel) [...perSel.options].forEach(o => { o.selected = o.value === dadosMembro.Periodo || o.text.startsWith(dadosMembro.Periodo); });
    const setSel = document.getElementById('edit-membro-setor');
    if (setSel) [...setSel.options].forEach(o => { o.selected = o.value === dadosMembro.Setor; });
    const carSel = document.getElementById('edit-membro-cargo');
    if (carSel) [...carSel.options].forEach(o => { o.selected = o.value === dadosMembro.Cargo; });
    const stSel  = document.getElementById('edit-membro-status');
    if (stSel)  [...stSel.options].forEach(o => { o.selected = o.value === dadosMembro.Status; });
  }
  openModal('modal-edit-membro');
}

async function salvarEdicaoMembro() {
  if (!requireAdmin('editar membros')) return;
  const modal = document.getElementById('modal-edit-membro');
  const id    = document.getElementById('edit-membro-id').value;
  const row   = {
    Nome:      document.getElementById('edit-membro-nome').value.trim(),
    Matricula: document.getElementById('edit-membro-mat').value.trim(),
    Periodo:   document.getElementById('edit-membro-periodo').value,
    Setor:     document.getElementById('edit-membro-setor').value,
    Cargo:     document.getElementById('edit-membro-cargo').value,
    Status:    document.getElementById('edit-membro-status').value,
  };
  if (!row.Nome) { showToast('Informe o nome completo.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';

  try {
    await apiPost({ action: 'update', sheet: 'Membros', id, row });
    closeModal('modal-edit-membro');
    showToast('Membro atualizado com sucesso!', 'success');
    loadMembros();
  } catch(e) {
    showToast('Erro ao atualizar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> Salvar alterações';
  }
}

async function deleteMembro(id, nome) {
  if (!requireAdmin('remover membros')) return;
  customConfirm({
    title: 'Remover membro',
    message: `Deseja realmente remover "${nome}" da liga? Esta ação não pode ser desfeita.`,
    confirmLabel: 'Remover',
    icon: 'fa-user-times',
    onConfirm: async () => {
      try {
        await apiPost({ action: 'delete', sheet: 'Membros', id });
        showToast('Membro removido com sucesso.', 'success');
        loadMembros();
      } catch(e) { showToast('Erro ao remover: ' + e.message, 'error'); }
    }
  });
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — MEMBRO (IDs semânticos — sem índice posicional)
// ══════════════════════════════════════════════════════════════

async function salvarMembro() {
  if (!requireAdmin('adicionar membros')) return;
  const modal = document.getElementById('modal-add-membro');

  const row = {
    Nome:         document.getElementById('mb-nome')?.value.trim()         || '',
    Matricula:    document.getElementById('mb-matricula')?.value.trim()    || '',
    Periodo:      document.getElementById('mb-periodo')?.value             || '',
    Setor:        document.getElementById('mb-setor')?.value               || '',
    Cargo:        document.getElementById('mb-cargo')?.value               || '',
    DataIngresso: document.getElementById('mb-data-ingresso')?.value       || new Date().toISOString().split('T')[0],
    Email:        document.getElementById('mb-email')?.value.trim()        || '',
    Status:       'Ativo'
  };

  if (!row.Nome) { showToast('Informe o nome completo.', 'warning'); return; }
  if (!row.Matricula) { showToast('Informe a matrícula.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Membros', row });
    closeModal('modal-add-membro');
    showToast(`Membro ${row.Nome} adicionado com sucesso!`, 'success');
    loadMembros();
  } catch(e) {
    showToast('Erro ao salvar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-user-plus"></i> Adicionar';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — ATA
// ══════════════════════════════════════════════════════════════

async function salvarAta() {
  if (!requireAdmin('registrar atas')) return;
  const modal = document.getElementById('modal-nova-ata');

  const tipo     = document.getElementById('ata-tipo')?.value     || 'Ordinária';
  const data     = document.getElementById('ata-data')?.value     || '';
  const horario  = document.getElementById('ata-horario')?.value  || '';
  const presentes= document.getElementById('ata-presentes')?.value|| '0';
  const pauta    = document.getElementById('ata-pauta')?.value    || '';
  const deliber  = document.getElementById('ata-deliberacoes')?.value || '';

  const dataPtBR = data
    ? new Date(data + 'T00:00:00').toLocaleDateString('pt-BR', { month: 'long', year: 'numeric' })
    : '';

  const row = {
    Titulo:       `Reunião ${tipo} — ${dataPtBR}`,
    Tipo:         tipo,
    Data:         data,
    HorarioInicio:horario,   // campo semântico correto: hora de início
    Duracao:      '',         // duração (não preenchida neste modal; editável em modal-edit-ata)
    Presentes:    presentes,
    Pauta:        pauta,
    Deliberacoes: deliber,
    Status:       'Pendente assinatura'
  };

  if (!row.Data) { showToast('Informe a data da reunião.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Atas', row });
    closeModal('modal-nova-ata');
    showToast('Ata registrada com sucesso!', 'success');
    loadAtas();
  } catch(e) {
    showToast('Erro ao salvar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> Salvar ata';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — LANÇAMENTO FINANCEIRO
// ══════════════════════════════════════════════════════════════

async function salvarLancamento() {
  if (!requireAdmin('registrar lançamentos')) return;
  const modal = document.getElementById('modal-lancamento');

  const row = {
    Tipo:      document.getElementById('lanc-tipo')?.value                    || 'Receita',
    Valor:     document.getElementById('lanc-valor')?.value                   || '0',
    Descricao: document.getElementById('lanc-descricao')?.value.trim()        || '',
    Categoria: document.getElementById('lanc-categoria')?.value               || '',
    Data:      document.getElementById('lanc-data')?.value                    || new Date().toISOString().split('T')[0]
  };

  if (!row.Descricao) { showToast('Informe a descrição do lançamento.', 'warning'); return; }
  if (!row.Valor || parseFloat(row.Valor) <= 0) { showToast('Informe um valor válido.', 'warning'); return; }
  if (!row.Data) { showToast('Informe a data.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Registrando…';

  try {
    // Upload do comprovante para o Drive (se fornecido)
    const fileInput = document.getElementById('lanc-comprovante');
    if (fileInput?.files?.length) {
      const file = fileInput.files[0];
      if (file.size <= 10 * 1024 * 1024) {
        const base64 = await new Promise((resolve, reject) => {
          const r = new FileReader();
          r.onload  = () => resolve(r.result.split(',')[1]);
          r.onerror = reject;
          r.readAsDataURL(file);
        });
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando comprovante…';
        const upResp = await fetch(API_URL, {
          method:  'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: JSON.stringify({
            action:     'uploadFile',
            fileName:   `Comprovante_${row.Descricao.substring(0,30)}_${row.Data}`,
            mimeType:   file.type || 'application/octet-stream',
            data:       base64,
            categoria:  'Financeiro',
            descricao:  `Comprovante: ${row.Descricao}`,
            tamanho:    (file.size / 1024).toFixed(1) + ' KB',
            dataUpload: row.Data,
          })
        });
        const upResult = await upResp.json();
        if (upResult.success && upResult.url) {
          row.ComprovanteUrl = upResult.url;
        }
      } else {
        showToast('Comprovante muito grande (máx. 10 MB). Lançamento registrado sem comprovante.', 'warning');
      }
    }

    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';
    await apiPost({ action: 'insert', sheet: 'Financeiro', row });
    closeModal('modal-lancamento');
    showToast(`Lançamento de R$ ${parseFloat(row.Valor).toFixed(2)} registrado!`, 'success');
    loadTesouraria();
  } catch(e) {
    showToast('Erro ao registrar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-save"></i> Registrar';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — EVENTO
// ══════════════════════════════════════════════════════════════

async function salvarEvento() {
  if (!requireAdmin('criar eventos')) return;
  const modal = document.getElementById('modal-novo-evento');

  const row = {
    Titulo:      document.getElementById('ev-titulo')?.value.trim()       || '',
    Tipo:        document.getElementById('ev-tipo')?.value                || '',
    Data:        document.getElementById('ev-data')?.value                || '',
    HoraInicio:  document.getElementById('ev-hora-inicio')?.value         || '',
    HoraFim:     document.getElementById('ev-hora-fim')?.value            || '',
    Local:       document.getElementById('ev-local')?.value.trim()        || '',
    Responsavel: document.getElementById('ev-responsavel')?.value.trim()  || '',
    Descricao:   document.getElementById('ev-descricao')?.value           || '',
    Status:      'Confirmado'
  };

  if (!row.Titulo) { showToast('Informe o título do evento.', 'warning'); return; }
  if (!row.Data)   { showToast('Informe a data do evento.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Criando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Eventos', row });
    closeModal('modal-novo-evento');
    showToast(`Evento "${row.Titulo}" criado com sucesso!`, 'success');
    loadAgenda();
  } catch(e) {
    showToast('Erro ao criar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-calendar-plus"></i> Criar evento';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — PROJETO DE PESQUISA
// ══════════════════════════════════════════════════════════════

async function salvarProjeto() {
  if (!requireAdmin('cadastrar projetos')) return;
  const modal = document.getElementById('modal-novo-projeto');

  const row = {
    Titulo:        document.getElementById('proj-titulo')?.value.trim()       || '',
    TipoEstudo:    document.getElementById('proj-tipo-estudo')?.value         || '',
    Status:        document.getElementById('proj-status')?.value              || '',
    CAAE:          document.getElementById('proj-caae')?.value.trim()         || '',
    Pesquisadores: document.getElementById('proj-pesquisadores')?.value       || '0',
    Descricao:     document.getElementById('proj-descricao')?.value           || '',
    Progresso:     '0'
  };

  if (!row.Titulo) { showToast('Informe o título do projeto.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cadastrando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Pesquisas', row });
    closeModal('modal-novo-projeto');
    showToast('Projeto cadastrado com sucesso!', 'success');
    loadPesquisa();
  } catch(e) {
    showToast('Erro ao cadastrar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-flask"></i> Cadastrar projeto';
  }
}

// ══════════════════════════════════════════════════════════════
//  EDITAR — CURSO
// ══════════════════════════════════════════════════════════════

async function editCurso(id) {
  if (!requireAdmin('editar cursos')) return;
  showToast('Buscando dados do curso…', 'info');
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Cursos' });
    const c    = data?.find(x => String(x.ID) === String(id));
    if (!c) { showToast('Curso não encontrado.', 'error'); return; }
    // Preenche modal via IDs semânticos
    const modal = document.getElementById('modal-novo-curso');
    if (!modal) return;
    document.getElementById('curso-titulo').value        = c.Titulo       || '';
    document.getElementById('curso-modalidade').value    = c.Modalidade    || '';
    document.getElementById('curso-carga-horaria').value = c.CargaHoraria  || '';
    document.getElementById('curso-vagas').value         = c.Vagas         || '';
    document.getElementById('curso-data-inicio').value   = c.DataInicio    || '';
    document.getElementById('curso-descricao').value     = c.Descricao     || '';
    // Muda botão para modo edição
    const btn = modal.querySelector('.btn-primary');
    if (btn) {
      btn.innerHTML = '<i class="fas fa-save"></i> Salvar alterações';
      btn.onclick = async () => {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Salvando…';
        const row = {
          Titulo:       document.getElementById('curso-titulo')?.value.trim(),
          Modalidade:   document.getElementById('curso-modalidade')?.value,
          CargaHoraria: document.getElementById('curso-carga-horaria')?.value,
          Vagas:        document.getElementById('curso-vagas')?.value,
          DataInicio:   document.getElementById('curso-data-inicio')?.value,
          Descricao:    document.getElementById('curso-descricao')?.value.trim(),
        };
        try {
          await apiPost({ action: 'update', sheet: 'Cursos', id, row });
          closeModal('modal-novo-curso');
          showToast('Curso atualizado com sucesso!', 'success');
          loadEnsino();
        } catch(e) {
          showToast('Erro: ' + e.message, 'error');
          btn.disabled = false;
          btn.innerHTML = '<i class="fas fa-save"></i> Salvar alterações';
        }
      };
    }
    openModal('modal-novo-curso');
  } catch(e) { showToast('Erro: ' + e.message, 'error'); }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — CURSO
// ══════════════════════════════════════════════════════════════

async function salvarCurso() {
  if (!requireAdmin('criar cursos')) return;
  const modal = document.getElementById('modal-novo-curso');

  const row = {
    Titulo:       document.getElementById('curso-titulo')?.value.trim()        || '',
    Modalidade:   document.getElementById('curso-modalidade')?.value           || '',
    CargaHoraria: document.getElementById('curso-carga-horaria')?.value        || '0',
    Vagas:        document.getElementById('curso-vagas')?.value                || '0',
    DataInicio:   document.getElementById('curso-data-inicio')?.value          || '',
    Descricao:    document.getElementById('curso-descricao')?.value            || '',
    Progresso:    '0',
    Status:       'Planejado'
  };

  if (!row.Titulo) { showToast('Informe o título do curso.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Criando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Cursos', row });
    closeModal('modal-novo-curso');
    showToast(`Curso "${row.Titulo}" criado com sucesso!`, 'success');
    loadEnsino();
  } catch(e) {
    showToast('Erro ao criar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-graduation-cap"></i> Criar curso';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — AÇÃO DE EXTENSÃO
// ══════════════════════════════════════════════════════════════

async function salvarAcao() {
  if (!requireAdmin('registrar ações')) return;
  const modal = document.getElementById('modal-nova-acao');

  const row = {
    Nome:          document.getElementById('acao-nome')?.value.trim()          || '',
    Tipo:          document.getElementById('acao-tipo')?.value                  || '',
    Data:          document.getElementById('acao-data')?.value                  || '',
    Local:         document.getElementById('acao-local')?.value.trim()          || '',
    Participantes: document.getElementById('acao-participantes')?.value         || '0',
    Status:        'Realizado'
  };

  if (!row.Nome) { showToast('Informe o nome da ação.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Registrando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Extensao', row });
    closeModal('modal-nova-acao');
    showToast('Ação de extensão registrada!', 'success');
    loadExtensao();
  } catch(e) {
    showToast('Erro ao registrar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-hands-helping"></i> Registrar ação';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — PARCEIRO DE EXTENSÃO
// ══════════════════════════════════════════════════════════════

async function salvarParceiro() {
  if (!requireAdmin('cadastrar parceiros')) return;
  const modal = document.getElementById('modal-novo-parceiro');

  const row = {
    Nome:      document.getElementById('parc-nome')?.value.trim()      || '',
    Area:      document.getElementById('parc-area')?.value.trim()      || '',
    Status:    document.getElementById('parc-status')?.value           || 'Ativo',
    Descricao: document.getElementById('parc-descricao')?.value.trim() || '',
  };

  if (!row.Nome) { showToast('Informe o nome do parceiro.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cadastrando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Parceiros', row });
    closeModal('modal-novo-parceiro');
    showToast(`Parceiro "${row.Nome}" cadastrado com sucesso!`, 'success');
    loadExtensao();
  } catch(e) {
    showToast('Erro ao cadastrar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-handshake"></i> Cadastrar parceiro';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — CORRESPONDÊNCIA
// ══════════════════════════════════════════════════════════════

async function salvarCorrespondencia() {
  if (!requireAdmin('registrar correspondências')) return;
  const modal = document.getElementById('modal-nova-corr');

  const row = {
    Tipo:         document.getElementById('corr-tipo')?.value              || '',
    Direcao:      'Enviada',
    Destinatario: document.getElementById('corr-destinatario')?.value.trim()|| '',
    Assunto:      document.getElementById('corr-assunto')?.value.trim()    || '',
    Corpo:        document.getElementById('corr-corpo')?.value             || '',
    Data:         new Date().toISOString().split('T')[0],
    Status:       'Enviada'
  };

  if (!row.Destinatario) { showToast('Informe o destinatário.', 'warning'); return; }
  if (!row.Assunto)      { showToast('Informe o assunto.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Registrando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Correspondencias', row });
    closeModal('modal-nova-corr');
    showToast('Correspondência registrada com sucesso!', 'success');
  } catch(e) {
    showToast('Erro ao registrar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-paper-plane"></i> Registrar envio';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — TAREFA MARKETING
// ══════════════════════════════════════════════════════════════

async function salvarTarefaMkt() {
  if (!requireAdmin('adicionar tarefas')) return;
  const modal   = document.getElementById('modal-new-task');
  const selects = modal.querySelectorAll('select');
  const inputs  = modal.querySelectorAll('input');

  const row = {
    Titulo:      inputs[0]?.value.trim() || '',
    Formato:     selects[0]?.value || '',
    Prazo:       inputs[1]?.value || '',
    Responsavel: inputs[2]?.value.trim() || '',
    Status:      'Ideia'
  };

  if (!row.Titulo) { showToast('Informe o título da tarefa.', 'warning'); return; }

  const btn = modal.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adicionando…';

  try {
    await apiPost({ action: 'insert', sheet: 'TarefasMarketing', row });
    closeModal('modal-new-task');
    showToast('Tarefa adicionada ao Kanban!', 'success');
    loadMarketing();
  } catch(e) {
    showToast('Erro ao adicionar: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-plus"></i> Adicionar tarefa';
  }
}

// ══════════════════════════════════════════════════════════════
//  SALVAR — OUVIDORIA (não exige admin)
// ══════════════════════════════════════════════════════════════

async function salvarOuvidoria() {
  const form    = document.querySelector('#page-ouvidoria .card:last-child');
  if (!form) return;
  const selects = form.querySelectorAll('select');
  const inputs  = form.querySelectorAll('input');

  const row = {
    Tipo:     selects[0]?.value || '',
    Assunto:  inputs[0]?.value.trim() || '',
    Mensagem: form.querySelector('textarea')?.value.trim() || '',
    Data:     new Date().toISOString().split('T')[0],
    Status:   'Pendente'
  };

  if (!row.Mensagem) { showToast('Escreva sua mensagem antes de enviar.', 'warning'); return; }

  const btn = form.querySelector('.btn-primary');
  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando…';

  try {
    await apiPost({ action: 'insert', sheet: 'Ouvidoria', row });
    showToast('Manifestação enviada anonimamente!', 'success');
    form.querySelector('textarea').value = '';
    if (inputs[0]) inputs[0].value = '';
  } catch(e) {
    showToast('Erro ao enviar: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-paper-plane"></i> Enviar anonimamente';
  }
}

// ══════════════════════════════════════════════════════════════
//  BOTÕES DE RELATÓRIOS (exportar)
// ══════════════════════════════════════════════════════════════

async function exportarRelatorio(tipo) {
  if (!requireAdmin('exportar relatórios')) return;

  // Mapa direto: string exata do botão → configuração de exportação.
  // 'formato' determina extensão e MIME do download.
  // Tanto XLSX quanto PDF são exportados como CSV com BOM (compatível com
  // Excel PT-BR para abertura direta); o nome do arquivo usa a extensão
  // prometida para orientar o usuário, e um toast explica o formato real.
  const exportMap = {
    'Relatório semestral CSV': {
      sheet:   'Eventos',
      label:   'Eventos',
      ext:     'csv',
      nota:    null,
    },
    'Planilha financeira XLSX': {
      sheet:   'Financeiro',
      label:   'Financeiro',
      ext:     'csv',
      nota:    'Exportado como CSV com BOM — abra no Excel e salve como .xlsx.',
    },
    'Lista de membros CSV': {
      sheet:   'Membros',
      label:   'Membros',
      ext:     'csv',
      nota:    null,
    },
    'Indicadores gerais': {
      sheet:   'Membros',
      label:   'Membros',
      ext:     'csv',
      nota:    null,
    },
  };

  const cfg = exportMap[tipo];
  if (!cfg) {
    showToast(`Tipo de exportação não reconhecido: "${tipo}"`, 'warning');
    return;
  }

  showToast(`Gerando exportação: ${tipo}…`, 'info');

  try {
    const data = await apiGet({ action: 'getAll', sheet: cfg.sheet });
    if (!data || data.length === 0) {
      showToast('Nenhum dado disponível para exportar.', 'warning');
      return;
    }

    const hoje    = new Date().toISOString().split('T')[0];
    const headers = Object.keys(data[0]);
    const csvRows = [
      headers.join(';'),
      ...data.map(row =>
        headers.map(h => `"${String(row[h] ?? '').replace(/"/g, '""')}"`).join(';')
      ),
    ];
    // BOM UTF-8 garante acentos no Excel PT-BR
    const csvContent = '\uFEFF' + csvRows.join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `LAPA_${cfg.label}_${hoje}.${cfg.ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    if (cfg.nota) {
      showToast(cfg.nota, 'info');
    } else {
      showToast(`"${tipo}" exportado com sucesso!`, 'success');
    }
  } catch(e) {
    showToast('Erro ao exportar: ' + e.message, 'error');
  }
}

// ══════════════════════════════════════════════════════════════
//  BOTÃO UPLOAD DE DOCUMENTO
// ══════════════════════════════════════════════════════════════

function uploadDocumento() {
  if (!requireAdmin('enviar documentos')) return;
  openModal('modal-upload-doc');
  // Limpa campos e barra de progresso
  const fi = document.getElementById('upload-file-input');
  const ni = document.getElementById('upload-file-name');
  const di = document.getElementById('upload-desc');
  const pb = document.getElementById('upload-progress-bar');
  const sm = document.getElementById('upload-status-msg');
  if (fi) fi.value = '';
  if (ni) ni.value = '';
  if (di) di.value = '';
  if (pb) pb.style.display = 'none';
  if (sm) sm.textContent = '';
  const btn = document.getElementById('btn-upload-exec');
  if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-upload"></i> Enviar para o Drive'; }
  bindUploadFileInput();
}

// ══════════════════════════════════════════════════════════════
//  UPLOAD REAL — GOOGLE DRIVE VIA APPS SCRIPT
// ══════════════════════════════════════════════════════════════

async function executarUpload() {
  if (!requireAdmin('enviar documentos')) return;
  const fileInput = document.getElementById('upload-file-input');
  const nameInput = document.getElementById('upload-file-name');
  const catSelect = document.getElementById('upload-category');
  const descInput = document.getElementById('upload-desc');
  const btn       = document.getElementById('btn-upload-exec');
  const progress  = document.getElementById('upload-progress-bar');
  const status    = document.getElementById('upload-status-msg');

  if (!fileInput.files.length) {
    showToast('Selecione um arquivo para enviar.', 'warning');
    return;
  }

  const file = fileInput.files[0];
  const MAX_MB = 20;
  if (file.size > MAX_MB * 1024 * 1024) {
    showToast(`Arquivo muito grande. Limite: ${MAX_MB} MB.`, 'error');
    return;
  }

  const nomeExibicao = nameInput.value.trim() || file.name;
  const categoria    = catSelect.value;
  const descricao    = descInput.value.trim();

  btn.disabled = true;
  btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Enviando…';
  progress.style.display = 'block';
  progress.querySelector('.progress-fill').style.width = '0%';
  status.textContent = 'Lendo arquivo…';

  try {
    // Converte para Base64
    const base64 = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = () => resolve(reader.result.split(',')[1]);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });

    progress.querySelector('.progress-fill').style.width = '40%';
    status.textContent = 'Enviando para o Google Drive…';

    const payload = {
      action:     'uploadFile',
      fileName:   nomeExibicao,
      mimeType:   file.type || 'application/octet-stream',
      data:       base64,
      categoria,
      descricao,
      tamanho:    (file.size / 1024).toFixed(1) + ' KB',
      dataUpload: new Date().toISOString().split('T')[0],
    };

    const resp = await fetch(API_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'text/plain' },
      body:    JSON.stringify(payload),
    });
    const result = await resp.json();

    progress.querySelector('.progress-fill').style.width = '100%';

    if (!result.success) throw new Error(result.error || 'Erro no servidor');

    status.textContent = '✓ Arquivo enviado com sucesso!';
    showToast(`"${nomeExibicao}" salvo no Google Drive!`, 'success');

    // Adiciona card dinâmico à grade de documentos
    adicionarCardDocumento({
      nome:      nomeExibicao,
      categoria,
      descricao,
      tamanho:   (file.size / 1024).toFixed(1) + ' KB',
      url:       result.url || null,
      mimeType:  file.type,
      data:      new Date().toISOString().split('T')[0],
    });

    setTimeout(() => closeModal('modal-upload-doc'), 1200);

  } catch(e) {
    progress.querySelector('.progress-fill').style.cssText = 'width:100%;background:var(--coral)';
    status.textContent = 'Falha: ' + e.message;
    showToast('Erro no upload: ' + e.message, 'error');
    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-upload"></i> Tentar novamente';
  }
}

function adicionarCardDocumento({ nome, categoria, descricao, tamanho, url, mimeType, data }) {
  const area = document.getElementById('docs-dynamic-area');
  if (!area) return;

  // Garante que existe uma grid na área dinâmica
  let grid = area.querySelector('.grid');
  if (!grid) {
    grid = document.createElement('div');
    grid.className = 'grid grid-4';
    grid.style.marginBottom = '12px';
    area.appendChild(grid);
  }

  const iconeMap = {
    'application/pdf':   { icon: 'fa-file-pdf',   cor: 'var(--coral)'   },
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': { icon: 'fa-file-excel', cor: 'var(--sage)' },
    'application/vnd.ms-excel': { icon: 'fa-file-excel', cor: 'var(--sage)' },
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': { icon: 'fa-file-word', cor: 'var(--sky)' },
    'application/msword': { icon: 'fa-file-word', cor: 'var(--sky)' },
    'image/jpeg': { icon: 'fa-file-image', cor: 'var(--lavender)' },
    'image/png':  { icon: 'fa-file-image', cor: 'var(--lavender)' },
    'image/gif':  { icon: 'fa-file-image', cor: 'var(--lavender)' },
    'image/svg+xml': { icon: 'fa-file-image', cor: 'var(--lavender)' },
    'default':    { icon: 'fa-file-alt',   cor: 'var(--gold)'     },
  };
  const tipo = iconeMap[mimeType] || iconeMap['default'];

  const badgeMap = { Ata:'lav', Financeiro:'gold', Regulamento:'teal', Marketing:'lav',
                     Pesquisa:'teal', 'Extensão':'sage', Ensino:'sage', Imagem:'lav', Geral:'sage' };
  const badgeCls = badgeMap[categoria] || 'teal';

  const card = document.createElement('div');
  card.className = 'doc-card card';
  card.setAttribute('data-nome', nome.toLowerCase());
  card.setAttribute('data-cat', categoria);
  card.style.cssText = 'text-align:center;cursor:pointer;transition:all .2s;position:relative';
  card.onmouseover = () => card.style.transform = 'translateY(-4px)';
  card.onmouseout  = () => card.style.transform = '';
  card.innerHTML = `
    <span class="badge ${badgeCls}" style="font-size:9px;position:absolute;top:8px;right:8px">${esc(categoria)}</span>
    <i class="fas ${tipo.icon}" style="font-size:36px;color:${tipo.cor};margin-bottom:12px;margin-top:8px"></i>
    <div style="font-size:13px;font-weight:600">${esc(nome)}</div>
    <div style="font-size:11px;color:var(--text3);margin-top:4px">${tamanho} • ${data}</div>
    ${descricao ? `<div style="font-size:11px;color:var(--text3);margin-top:6px;font-style:italic">${esc(descricao)}</div>` : ''}
  `;
  card.onclick = () => {
    if (url) window.open(url, '_blank');
    else showToast(`"${nome}" ainda não possui link vinculado no Drive.`, 'info');
  };
  grid.prepend(card);
}

// ── Carrega documentos salvos via API (sheet: Documentos) ──
async function loadDocumentos() {
  const area = document.getElementById('docs-dynamic-area');
  if (!area) return;

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Documentos' });
    if (!data || data.length === 0) { area.innerHTML = ''; return; }

    // Limpa área dinâmica antes de recarregar (evita duplicatas)
    area.innerHTML = '';
    const grid = document.createElement('div');
    grid.className = 'grid grid-4';
    grid.style.marginBottom = '12px';
    area.appendChild(grid);

    data
      .sort((a, b) => new Date(b.dataUpload || b.Data || 0) - new Date(a.dataUpload || a.Data || 0))
      .forEach(doc => {
        adicionarCardDocumento({
          nome:      doc.fileName || doc.Nome || 'Arquivo',
          categoria: doc.categoria || doc.Categoria || 'Geral',
          descricao: doc.descricao || doc.Descricao || '',
          tamanho:   doc.tamanho   || doc.Tamanho   || '—',
          url:       doc.url       || doc.Url       || null,
          mimeType:  doc.mimeType  || 'default',
          data:      formatDate(doc.dataUpload || doc.Data),
        });
      });
  } catch(e) {
    console.warn('loadDocumentos:', e);
  }
}

// ── Filtragem de documentos por texto e categoria ──
function filtrarDocumentos(termo) {
  const cat = (document.getElementById('doc-filter-cat')?.value || '').toLowerCase();
  const val = (termo || '').toLowerCase().trim();

  let total = 0;

  // Filtrar cards estáticos
  document.querySelectorAll('#docs-static-grid .doc-card').forEach(card => {
    const nome  = (card.getAttribute('data-nome') || card.textContent).toLowerCase();
    const cCard = (card.getAttribute('data-cat') || '').toLowerCase();
    const nomeOk = !val || nome.includes(val);
    const catOk  = !cat || cCard === cat;
    const vis = nomeOk && catOk;
    card.style.display = vis ? '' : 'none';
    if (vis) total++;
  });

  // Filtrar cards dinâmicos
  document.querySelectorAll('#docs-dynamic-area .doc-card').forEach(card => {
    const nome  = (card.getAttribute('data-nome') || card.textContent).toLowerCase();
    const cCard = (card.getAttribute('data-cat') || '').toLowerCase();
    const nomeOk = !val || nome.includes(val);
    const catOk  = !cat || cCard === cat;
    const vis = nomeOk && catOk;
    card.style.display = vis ? '' : 'none';
    if (vis) total++;
  });

  const emptyMsg = document.getElementById('docs-empty-msg');
  if (emptyMsg) emptyMsg.style.display = total === 0 ? 'block' : 'none';
}

// ── Listener do input de arquivo de upload (bind inline no modal) ──
function bindUploadFileInput() {
  const fi = document.getElementById('upload-file-input');
  const ni = document.getElementById('upload-file-name');
  const pb = document.getElementById('upload-progress-bar');
  const sm = document.getElementById('upload-status-msg');
  if (!fi || fi._bound) return;
  fi._bound = true;
  fi.addEventListener('change', () => {
    if (fi.files.length && ni && !ni.value) {
      ni.value = fi.files[0].name.replace(/\.[^.]+$/, '');
    }
    if (pb) pb.style.display = 'none';
    if (sm) sm.textContent = '';
    const btn = document.getElementById('btn-upload-exec');
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-upload"></i> Enviar para o Drive'; }
  });
}


// ══════════════════════════════════════════════════════════════
//  INDICADORES EDITÁVEIS — persiste em Google Sheets (sheet: Configuracoes)
// ══════════════════════════════════════════════════════════════

/**
 * Salva ou atualiza uma chave na sheet Configuracoes.
 * Estrutura esperada da sheet: id | chave | valor | complemento
 */
async function _upsertConfig(chave, valor, complemento) {
  try {
    // Tenta atualizar; se falhar, insere
    try {
      await apiPost({
        action: 'update',
        sheet:  'Configuracoes',
        id:     chave,
        row:    { chave, valor, complemento: complemento || '' },
      });
    } catch(_) {
      await apiPost({
        action: 'insert',
        sheet:  'Configuracoes',
        row:    { id: chave, chave, valor, complemento: complemento || '' },
      });
    }
  } catch(e) {
    console.warn('_upsertConfig:', e.message);
  }
}

/**
 * Carrega todas as configurações da sheet Configuracoes e retorna
 * um objeto { chave: { valor, complemento } }.
 */
async function _carregarConfiguracoes() {
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Configuracoes' });
    if (!data || data.length === 0) return {};
    const map = {};
    data.forEach(row => {
      if (row.chave) map[row.chave] = { valor: row.valor || '', complemento: row.complemento || '' };
    });
    return map;
  } catch(e) {
    console.warn('_carregarConfiguracoes:', e.message);
    return {};
  }
}

/**
 * Aplica TODOS os indicadores (home + marketing + tesouraria)
 * buscando dados da sheet Configuracoes. Fallback para defaults se API
 * não estiver disponível.
 */
async function _aplicarTodosIndicadores() {
  const saved = await _carregarConfiguracoes();

  // ── Indicadores de home/tesouraria ──────────────────────
  Object.entries(_indConfig).forEach(([key, cfg]) => {
    const val = saved[key]?.valor       || cfg.defaultVal;
    const ch  = saved[key]?.complemento || cfg.defaultChange;

    // ID principal
    const el   = document.getElementById(cfg.valorId);
    const chEl = document.getElementById(cfg.changeId);
    if (el)   el.textContent = val;
    if (chEl) chEl.innerHTML = `<i class="fas ${cfg.changeIcon}"></i> ${ch}`;
    if (chEl && cfg.changeCls) chEl.className = 'stat-change ' + cfg.changeCls;

    // IDs extras (mesmo indicador exibido em outras páginas, ex: Ensino)
    (cfg.extraValorIds || []).forEach(id => {
      const extra = document.getElementById(id);
      if (extra) extra.textContent = val;
    });
    (cfg.extraChangeIds || []).forEach(id => {
      const extra = document.getElementById(id);
      if (extra) {
        extra.innerHTML = `<i class="fas ${cfg.changeIcon}"></i> ${ch}`;
        if (cfg.changeCls) extra.className = 'stat-change ' + cfg.changeCls;
      }
    });
  });

  // ── Indicadores de marketing ─────────────────────────────
  const set    = (id, v) => { const el = document.getElementById(id); if (el && v) el.textContent = v; };
  const setHTML= (id, v) => { const el = document.getElementById(id); if (el && v) el.innerHTML = v; };
  set('mkt-seg-val',   saved['mkt.seguidores']?.valor);
  set('mkt-eng-val',   saved['mkt.engajamento']?.valor);
  set('mkt-posts-val', saved['mkt.posts']?.valor);
  set('mkt-camp-val',  saved['mkt.campanhas']?.valor);
  if (saved['mkt.segChange']?.valor) setHTML('mkt-seg-change', '<i class="fas fa-arrow-up"></i> ' + saved['mkt.segChange'].valor);
  if (saved['mkt.engChange']?.valor) setHTML('mkt-eng-change', '<i class="fas fa-arrow-up"></i> ' + saved['mkt.engChange'].valor);

  // ── Prazo de prestação de contas (Tesouraria) ─────────────
  const prazoEl = document.getElementById('proximo-prazo-contas');
  if (prazoEl) {
    const prazo = saved['prazo_prestacao_contas']?.valor;
    prazoEl.textContent = prazo ? formatDate(prazo) : '—';
  }

  // ── Anos de existência (home hero) ───────────────────────
  const anosEl = document.getElementById('cnt-anos');
  if (anosEl && anosEl.textContent === '—') {
    const anoFund = parseInt(saved['ano_fundacao']?.valor);
    if (anoFund && anoFund > 1900) {
      anosEl.textContent = new Date().getFullYear() - anoFund;
    }
  }
}

// Compat: funções síncronas usadas em chamadas legadas → delegam para a versão async
function _aplicarIndicadoresLocais() { _aplicarTodosIndicadores(); }
function _aplicarIndicadoresMkt()    { _aplicarTodosIndicadores(); }

// Config de cada indicador: key → { label, valorId, changeId, defaultVal, defaultChange }
const _indConfig = {
  horas_treinamento: {
    label: 'Horas de treinamento',
    valorId: 'home-horas-val',
    changeId: 'home-horas-change',
    defaultVal: '—',
    defaultChange: 'Configure nas Configurações',
    changeIcon: 'fa-arrow-up',
    changeCls: 'up'
  },
  certificados_emitidos: {
    label: 'Certificados emitidos',
    valorId:  'home-certs-val',
    changeId: 'home-certs-change',
    // IDs adicionais do mesmo indicador em outras páginas (aba Ensino)
    extraValorIds:  ['home-certs-val2'],
    extraChangeIds: ['home-certs-change2'],
    defaultVal: '0',
    defaultChange: 'Acumulado no ano',
    changeIcon: 'fa-certificate',
    changeCls: ''
  },
  inadimplencia: {
    label: 'Inadimplência (membros em atraso)',
    valorId: 'tesour-inadim-val',
    changeId: 'tesour-inadim-change',
    defaultVal: '0',
    defaultChange: 'Membros em atraso',
    changeIcon: 'fa-exclamation-triangle',
    changeCls: 'down'
  },
};

async function editarIndicador(key) {
  if (!requireAdmin('editar indicadores')) return;
  const cfg   = _indConfig[key];
  if (!cfg) return;
  const saved = await _carregarConfiguracoes();
  document.getElementById('edit-ind-key').value         = key;
  document.getElementById('edit-ind-titulo').textContent= 'Editar: ' + cfg.label;
  document.getElementById('edit-ind-label').textContent = 'Valor do indicador';
  document.getElementById('edit-ind-valor').value       = saved[key]?.valor        || cfg.defaultVal;
  document.getElementById('edit-ind-complemento').value = saved[key]?.complemento  || cfg.defaultChange;
  document.getElementById('edit-ind-sub-label').textContent = 'Texto complementar (ex: +24h vs semestre passado)';
  openModal('modal-edit-indicador');
}

async function salvarIndicador() {
  const key = document.getElementById('edit-ind-key').value;
  const val = document.getElementById('edit-ind-valor').value.trim();
  const ch  = document.getElementById('edit-ind-complemento').value.trim();
  if (!val) { showToast('Informe o valor.', 'warning'); return; }
  await _upsertConfig(key, val, ch);
  await _aplicarTodosIndicadores();
  closeModal('modal-edit-indicador');
  showToast('Indicador atualizado!', 'success');
}

// ── Marketing indicators ──────────────────────────────────

async function editarIndicadoresMkt() {
  if (!requireAdmin('editar indicadores')) return;
  const saved = await _carregarConfiguracoes();
  document.getElementById('mkt-input-seg').value     = saved['mkt.seguidores']?.valor  || '1.2k';
  document.getElementById('mkt-input-seg-ch').value  = saved['mkt.segChange']?.valor   || '+87 este mês';
  document.getElementById('mkt-input-eng').value     = saved['mkt.engajamento']?.valor || '8.4%';
  document.getElementById('mkt-input-eng-ch').value  = saved['mkt.engChange']?.valor   || '+1.2pp';
  document.getElementById('mkt-input-posts').value   = saved['mkt.posts']?.valor       || '38';
  document.getElementById('mkt-input-camp').value    = saved['mkt.campanhas']?.valor   || '3';
  openModal('modal-edit-mkt');
}

async function salvarIndicadoresMkt() {
  const campos = {
    'mkt.seguidores':  document.getElementById('mkt-input-seg').value.trim(),
    'mkt.segChange':   document.getElementById('mkt-input-seg-ch').value.trim(),
    'mkt.engajamento': document.getElementById('mkt-input-eng').value.trim(),
    'mkt.engChange':   document.getElementById('mkt-input-eng-ch').value.trim(),
    'mkt.posts':       document.getElementById('mkt-input-posts').value.trim(),
    'mkt.campanhas':   document.getElementById('mkt-input-camp').value.trim(),
  };
  for (const [chave, valor] of Object.entries(campos)) {
    await _upsertConfig(chave, valor, '');
  }
  await _aplicarTodosIndicadores();
  closeModal('modal-edit-mkt');
  showToast('Indicadores de marketing salvos!', 'success');
}

// ══════════════════════════════════════════════════════════════
//  BIND — CONECTA BOTÕES AOS HANDLERS
// ══════════════════════════════════════════════════════════════

function bindModalButtons() {
  const bindings = [
    { modal:'modal-add-membro',   fn: salvarMembro         },
    { modal:'modal-nova-ata',     fn: salvarAta            },
    { modal:'modal-lancamento',   fn: salvarLancamento     },
    { modal:'modal-novo-evento',  fn: salvarEvento         },
    { modal:'modal-novo-projeto', fn: salvarProjeto        },
    { modal:'modal-novo-curso',   fn: salvarCurso          },
    { modal:'modal-nova-acao',    fn: salvarAcao           },
    { modal:'modal-nova-corr',    fn: salvarCorrespondencia},
    { modal:'modal-new-task',     fn: salvarTarefaMkt      },
  ];

  bindings.forEach(({ modal, fn }) => {
    const el = document.getElementById(modal);
    if (!el) return;
    const btn = el.querySelector('.btn-primary');
    if (!btn) return;
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);
    newBtn.addEventListener('click', fn);
  });

  // Modais de indicadores
  const indBtn = document.querySelector('#modal-edit-indicador .btn-primary');
  if (indBtn) { const nb = indBtn.cloneNode(true); indBtn.parentNode.replaceChild(nb, indBtn); nb.addEventListener('click', salvarIndicador); }
  const mktBtn = document.querySelector('#modal-edit-mkt .btn-primary');
  if (mktBtn) { const nb = mktBtn.cloneNode(true); mktBtn.parentNode.replaceChild(nb, mktBtn); nb.addEventListener('click', salvarIndicadoresMkt); }

  // Ouvidoria — botão inline (fora de modal)
  const ouvBtn = document.querySelector('#page-ouvidoria .card:last-child .btn-primary');
  if (ouvBtn) {
    const nb = ouvBtn.cloneNode(true);
    ouvBtn.parentNode.replaceChild(nb, ouvBtn);
    nb.addEventListener('click', salvarOuvidoria);
  }

  // Relatórios — botões de exportar: lê chave estável via data-export (não textContent)
  document.querySelectorAll('#page-relatorios [data-export]').forEach(btn => {
    const key = btn.getAttribute('data-export');
    btn.addEventListener('click', () => exportarRelatorio(key));
  });

  // Documentos — botão upload
  const uploadBtn = document.querySelector('#page-documentos .btn-primary');
  if (uploadBtn) {
    const nb = uploadBtn.cloneNode(true);
    uploadBtn.parentNode.replaceChild(nb, uploadBtn);
    nb.addEventListener('click', uploadDocumento);
  }

  // Documentos — cards estáticos clicáveis (sem URL Drive ainda)
  document.querySelectorAll('#docs-static-grid .doc-card').forEach(card => {
    card.style.cursor = 'pointer';
    card.addEventListener('click', () => {
      const nome = card.getAttribute('data-nome') || card.querySelector('div:nth-child(3)')?.textContent || 'arquivo';
      showToast(`"${nome.trim()}" — link do Drive não configurado ainda. Use o botão Enviar arquivo para fazer upload.`, 'info');
    });
  });

  // Agenda edit buttons (static ones) — estes abrem modal-edit-evento vazio para novo evento
  document.querySelectorAll('#ag-lista .btn-outline.btn-sm').forEach(btn => {
    if (!btn.getAttribute('onclick')) {
      btn.addEventListener('click', () => {
        if (!requireAdmin('editar eventos')) return;
        openModal('modal-novo-evento');
      });
    }
  });

  // Atas cards estáticas — modal ver ata
  document.querySelectorAll('.ata-card:not([onclick])').forEach(card => {
    card.addEventListener('click', () => openModal('modal-ver-ata'));
  });

  // Estatuto & Regimento — cards: abre modal-doc para o Estatuto, exibe info para os outros
  document.querySelectorAll('#sec-estatuto .card').forEach((card, idx) => {
    if (!card.getAttribute('onclick')) {
      card.addEventListener('click', () => {
        if (idx === 0) {
          openModal('modal-doc');
        } else {
          const nome = card.querySelector('div[style*="font-weight"]')?.textContent || 'documento';
          showToast(`Para acessar "${nome.trim()}", faça o upload via "Enviar arquivo" na aba Documentos.`, 'info');
        }
      });
    }
  });
}

// ══════════════════════════════════════════════════════════════
//  LOADER — CORRESPONDÊNCIAS
// ══════════════════════════════════════════════════════════════

async function loadCorrespondencias() {
  const recEl = document.getElementById('corr-recebidas-list');
  const envEl = document.getElementById('corr-enviadas-list');

  try {
    const data = await apiGet({ action: 'getAll', sheet: 'Correspondencias' });

    if (!data || data.length === 0) {
      const empty = '<div style="text-align:center;padding:20px;color:var(--text3);font-size:13px"><i class="fas fa-inbox" style="font-size:24px;display:block;margin-bottom:8px;opacity:.3"></i>Nenhum registro ainda.</div>';
      if (recEl) recEl.innerHTML = empty;
      if (envEl) envEl.innerHTML = empty;
      return;
    }

    const recebidas = data.filter(c => c.Direcao === 'Recebida');
    const enviadas  = data.filter(c => c.Direcao === 'Enviada');

    // Atualiza badge de recebidas
    const badgeRec = document.getElementById('badge-corr-recebidas');
    if (badgeRec) {
      badgeRec.textContent = recebidas.length + ' total';
      badgeRec.style.display = recebidas.length > 0 ? '' : 'none';
    }

    if (recEl) {
      if (recebidas.length === 0) {
        recEl.innerHTML = '<div style="padding:12px;color:var(--text3);font-size:13px">Nenhuma correspondência recebida.</div>';
      } else {
        recEl.innerHTML = recebidas.slice(0, 5).map(c => `
          <div class="ata-card">
            <div class="ata-title">${esc(c.Assunto)}</div>
            <div class="ata-meta">
              <span>${esc(c.Remetente || c.Destinatario || '—')}</span>
              <span>${formatDate(c.Data)}</span>
              <span class="badge ${statusBadge(c.Status)}">${esc(c.Status || '—')}</span>
            </div>
          </div>`).join('');
      }
    }

    if (envEl) {
      if (enviadas.length === 0) {
        envEl.innerHTML = '<div style="padding:12px;color:var(--text3);font-size:13px">Nenhuma correspondência enviada.</div>';
      } else {
        envEl.innerHTML = enviadas.slice(0, 5).map(c => `
          <div class="ata-card">
            <div class="ata-title">${esc(c.Assunto)}</div>
            <div class="ata-meta">
              <span>Para: ${esc(c.Destinatario || '—')}</span>
              <span>${formatDate(c.Data)}</span>
              <span class="badge ${statusBadge(c.Status)}">${esc(c.Status || '—')}</span>
            </div>
          </div>`).join('');
      }
    }
  } catch(e) {
    console.warn('loadCorrespondencias:', e);
    const errMsg = '<div style="padding:12px;color:var(--coral);font-size:13px"><i class="fas fa-exclamation-circle"></i> Erro ao carregar.</div>';
    if (recEl) recEl.innerHTML = errMsg;
    if (envEl) envEl.innerHTML = errMsg;
  }
}

// ══════════════════════════════════════════════════════════════
//  CALENDÁRIO MINI — GERADO A PARTIR DOS EVENTOS DA API
// ══════════════════════════════════════════════════════════════

// State vars para o calendário (declarados aqui para compatibilidade)
let _calEventos = [];
let _calYear    = new Date().getFullYear();
let _calMonth   = new Date().getMonth();

function mostrarEventosDia(dateStr) {
  const evs = _calEventos.filter(e => (e.Data || '').substring(0,10) === dateStr);
  if (!evs.length) return;

  // Remove modal anterior se existir
  const old = document.getElementById('modal-eventos-dia');
  if (old) old.remove();

  const overlay = document.createElement('div');
  overlay.id = 'modal-eventos-dia';
  overlay.className = 'modal-overlay open';
  overlay.style.zIndex = '9999';
  overlay.innerHTML = `
    <div class="modal" style="max-width:420px">
      <div class="modal-header">
        <div class="modal-title"><i class="fas fa-calendar-day" style="color:var(--teal);margin-right:8px"></i>Eventos em ${formatDate(dateStr)}</div>
        <button class="modal-close" onclick="document.getElementById('modal-eventos-dia').remove()"><i class="fas fa-times"></i></button>
      </div>
      ${evs.map(e => {
        const cor = setorCor(e.Tipo);
        return `<div style="display:flex;gap:12px;align-items:flex-start;padding:12px 0;border-bottom:1px solid var(--border)">
          <div style="width:36px;height:36px;border-radius:8px;background:${cor.bg};border:1px solid ${cor.bd};display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <i class="fas fa-calendar-check" style="color:${cor.fg};font-size:13px"></i>
          </div>
          <div>
            <div style="font-size:14px;font-weight:600">${esc(e.Titulo)}</div>
            <div style="font-size:12px;color:var(--text3);margin-top:2px">
              ${e.HoraInicio ? `<i class="fas fa-clock"></i> ${esc(e.HoraInicio)}${e.HoraFim ? '–'+esc(e.HoraFim) : ''}&nbsp; ` : ''}
              ${e.Local ? `<i class="fas fa-map-marker-alt"></i> ${esc(e.Local)}` : ''}
            </div>
          </div>
          <span class="badge ${cor.badge}" style="margin-left:auto;flex-shrink:0">${esc(e.Tipo || '—')}</span>
        </div>`;
      }).join('')}
      <div class="modal-footer" style="margin-top:12px">
        <button class="btn btn-outline" onclick="document.getElementById('modal-eventos-dia').remove()">Fechar</button>
        <button class="btn btn-primary btn-sm" onclick="document.getElementById('modal-eventos-dia').remove();showPage('agenda')"><i class="fas fa-calendar-alt"></i> Ver agenda</button>
      </div>
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
  document.body.appendChild(overlay);
}

// ══════════════════════════════════════════════════════════════
//  CONFIGURAÇÕES — MODAL DE PREFERÊNCIAS
// ══════════════════════════════════════════════════════════════

async function openConfiguracoes() {
  openModal('modal-configuracoes');
  try {
    const cfgs = await _carregarConfiguracoes();
    const anoEl   = document.getElementById('cfg-ano-fundacao');
    const prazoEl = document.getElementById('cfg-prazo-contas');
    const apiEl   = document.getElementById('cfg-api-url');
    if (anoEl   && cfgs['ano_fundacao']?.valor)           anoEl.value   = cfgs['ano_fundacao'].valor;
    if (prazoEl && cfgs['prazo_prestacao_contas']?.valor) prazoEl.value = cfgs['prazo_prestacao_contas'].valor;
    // Mostra a URL ativa em memória; se a sheet tiver outra, aplica em memória também
    const urlSalva = cfgs['api_url']?.valor;
    if (urlSalva && urlSalva !== API_URL) {
      API_URL = urlSalva;
      Object.keys(_apiCache).forEach(k => delete _apiCache[k]);
    }
    if (apiEl) apiEl.value = API_URL || '';
  } catch(_) {}
}

async function salvarConfiguracoes() {
  const nomeOrg   = document.getElementById('cfg-nome-org')?.value.trim();
  const apiUrlCfg = document.getElementById('cfg-api-url')?.value.trim();
  const anoFund   = document.getElementById('cfg-ano-fundacao')?.value.trim();
  const prazo     = document.getElementById('cfg-prazo-contas')?.value.trim();

  // ── Atualiza nome da organização na sidebar ───────────────
  if (nomeOrg) {
    const logoEl = document.querySelector('.logo-title');
    if (logoEl) logoEl.textContent = nomeOrg;
  }

  // ── Atualiza API_URL em runtime imediatamente ─────────────
  // A variável é global (var), então a reatribuição aqui se propaga para
  // todas as chamadas subsequentes de apiGet/apiPost sem precisar recarregar.
  if (apiUrlCfg && apiUrlCfg !== API_URL) {
    API_URL = apiUrlCfg;
    // Invalida todo o cache para forçar re-fetch com a nova URL
    Object.keys(_apiCache).forEach(k => delete _apiCache[k]);
    // Persiste a nova URL na sheet Configuracoes para leituras futuras
    await _upsertConfig('api_url', apiUrlCfg, '').catch(() => {
      // Se a persistência falhar (ex.: ainda com a URL antiga), não é crítico —
      // a variável em memória já está correta para a sessão atual.
    });
    showToast('URL da API atualizada — cache limpo. Dados serão recarregados.', 'info');
  }

  // ── Persiste outras configurações na sheet ────────────────
  const tarefas = [];
  if (anoFund) tarefas.push(_upsertConfig('ano_fundacao', anoFund, ''));
  if (prazo)   tarefas.push(_upsertConfig('prazo_prestacao_contas', prazo, ''));
  await Promise.allSettled(tarefas);

  closeModal('modal-configuracoes');
  showToast('Configurações salvas com sucesso!', 'success');

  // Reaplica indicadores para refletir novo ano de fundação imediatamente
  _aplicarTodosIndicadores();
}

// ══════════════════════════════════════════════════════════════
//  NOTIFICAÇÕES — PAINEL SIMPLES
// ══════════════════════════════════════════════════════════════

function openNotificacoes() {
  openModal('modal-notificacoes');
  carregarNotificacoes();
}

async function carregarNotificacoes() {
  const list = document.getElementById('notif-list');
  if (!list) return;
  list.innerHTML = '<div style="text-align:center;padding:18px;color:var(--text3)"><i class="fas fa-spinner fa-spin"></i></div>';

  const notifs = [];

  try {
    // Membros ativos
    const membros = await apiGet({ action: 'getAll', sheet: 'Membros' });
    if (membros) {
      const ativos = membros.filter(m => m.Status === 'Ativo').length;
      notifs.push({ icon: 'fa-users', cor: 'var(--teal)',    msg: `${ativos} membros ativos cadastrados.`,      data: 'Agora' });
    }

    // Atas pendentes de assinatura
    const atas = await apiGet({ action: 'getAll', sheet: 'Atas' });
    if (atas) {
      const pend = atas.filter(a => a.Status === 'Pendente assinatura').length;
      if (pend > 0) notifs.push({ icon: 'fa-file-alt', cor: 'var(--gold)', msg: `${pend} ata(s) pendente(s) de assinatura.`, data: 'Verificar' });
    }

    // Financeiro: últimos lançamentos
    const fin = await apiGet({ action: 'getAll', sheet: 'Financeiro' });
    if (fin && fin.length) {
      const ult = fin[fin.length - 1];
      notifs.push({ icon: 'fa-receipt', cor: 'var(--sage)', msg: `Último lançamento: ${ult.Descricao} (R$ ${ult.Valor})`, data: formatDate(ult.Data) });
    }

    // Próximos eventos
    const hoje = new Date();
    const evs  = await apiGet({ action: 'getAll', sheet: 'Eventos' });
    if (evs) {
      const prox = evs.filter(e => e.Data && new Date(e.Data+'T00:00:00') >= hoje)
                      .sort((a,b) => new Date(a.Data) - new Date(b.Data))[0];
      if (prox) notifs.push({ icon: 'fa-calendar', cor: 'var(--lavender)', msg: `Próximo evento: ${prox.Titulo} em ${formatDate(prox.Data)}`, data: prox.HoraInicio || '' });
    }
  } catch(e) { /* ignora erros parciais */ }

  if (notifs.length === 0) {
    notifs.push({ icon: 'fa-check-circle', cor: 'var(--sage)', msg: 'Tudo em ordem. Nenhuma notificação pendente.', data: 'Agora' });
  }

  list.innerHTML = notifs.map(n => `
    <div style="display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)">
      <div style="width:34px;height:34px;border-radius:50%;background:rgba(0,0,0,.15);display:flex;align-items:center;justify-content:center;flex-shrink:0">
        <i class="fas ${n.icon}" style="color:${n.cor};font-size:14px"></i>
      </div>
      <div style="flex:1">
        <div style="font-size:13px;line-height:1.5">${n.msg}</div>
        <div style="font-size:11px;color:var(--text3);margin-top:2px">${n.data}</div>
      </div>
    </div>`).join('');

  // Limpa o dot de notificação após visualizar
  document.querySelector('.notif-dot')?.remove();
}

// API_URL é fixa em código — não utiliza localStorage para isso

function setupKanbanIds() {
  const cols = document.querySelectorAll('.kanban-col');
  const ids  = ['backlog-col','producao-col','revisao-col','publicado-col'];
  cols.forEach((col, i) => { if (ids[i]) col.id = ids[i]; });
}

// ══════════════════════════════════════════════════════════════
//  KANBAN — DRAG AND DROP
// ══════════════════════════════════════════════════════════════

const _kanbanStatusMap = {
  'backlog-col':   'Ideia',
  'producao-col':  'Produção',
  'revisao-col':   'Revisão',
  'publicado-col': 'Publicado',
};

let _dragCard = null;

function _initKanbanDnD() {
  const board = document.getElementById('kanban-board');
  if (!board || board.dataset.dndReady) return;
  board.dataset.dndReady = '1';

  // ── cards: eventos dragstart/dragend ──────────────────────
  board.addEventListener('dragstart', e => {
    const card = e.target.closest('.kanban-card');
    if (!card || !isAdmin()) { e.preventDefault(); return; }
    _dragCard = card;
    card.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', card.getAttribute('data-task-id') || '');
  });

  board.addEventListener('dragend', () => {
    if (_dragCard) { _dragCard.classList.remove('dragging'); _dragCard = null; }
    document.querySelectorAll('.kanban-col').forEach(c => c.classList.remove('drag-over'));
  });

  // ── colunas: dragover / drop ──────────────────────────────
  board.addEventListener('dragover', e => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const col = e.target.closest('.kanban-col');
    document.querySelectorAll('.kanban-col').forEach(c => c.classList.remove('drag-over'));
    if (col && _dragCard && !col.contains(_dragCard)) col.classList.add('drag-over');
  });

  board.addEventListener('dragleave', e => {
    const col = e.target.closest('.kanban-col');
    if (col && !col.contains(e.relatedTarget)) col.classList.remove('drag-over');
  });

  board.addEventListener('drop', async e => {
    e.preventDefault();
    const col = e.target.closest('.kanban-col');
    col?.classList.remove('drag-over');
    if (!col || !_dragCard) return;
    if (col.contains(_dragCard)) return;

    const taskId    = _dragCard.getAttribute('data-task-id');
    const newStatus = _kanbanStatusMap[col.id];
    if (!newStatus || !taskId) return;

    // Move o card visualmente de imediato
    const titleEl = col.querySelector('.kanban-col-title');
    col.insertBefore(_dragCard, titleEl ? titleEl.nextSibling : col.firstChild);

    // Atualiza contadores
    _updateKanbanCounts();

    // Persiste na API
    try {
      await apiPost({ action: 'update', sheet: 'TarefasMarketing', id: taskId, row: { Status: newStatus } });
      showToast(`Tarefa movida para "${newStatus}"`, 'success');
    } catch(e) {
      showToast('Erro ao mover tarefa: ' + e.message, 'error');
    }
  });

  // Habilita todos os cards para drag
  _refreshKanbanDraggable();
}

function _refreshKanbanDraggable() {
  document.querySelectorAll('.kanban-card').forEach(card => {
    card.draggable = isAdmin();
  });
}

function _updateKanbanCounts() {
  const colTitles = {
    'backlog-col':   { emoji:'📋', label:'Backlog',      badge:'teal'  },
    'producao-col':  { emoji:'🛠',  label:'Em Produção',  badge:'gold'  },
    'revisao-col':   { emoji:'🔍', label:'Revisão',      badge:'coral' },
    'publicado-col': { emoji:'✅', label:'Publicado',    badge:'sage'  },
  };
  Object.entries(colTitles).forEach(([colId, info]) => {
    const col = document.getElementById(colId);
    if (!col) return;
    const cnt = col.querySelectorAll('.kanban-card').length;
    const el  = col.querySelector('.kanban-col-title');
    if (el) el.innerHTML = `${info.emoji} ${info.label} <span class="badge ${info.badge}">${cnt}</span>`;
  });
}

// ══════════════════════════════════════════════════════════════
//  VALIDAÇÃO INLINE — blur em campos obrigatórios
// ══════════════════════════════════════════════════════════════

function setupInlineValidation() {
  // Escuta blur em qualquer input/select/textarea dentro de modais
  document.addEventListener('blur', e => {
    const el = e.target;
    if (!el.matches('.form-input,.form-select,.form-textarea')) return;
    if (!el.closest('.modal')) return;
    _validateField(el);
  }, true);

  // Limpa erro quando usuário começa a digitar
  document.addEventListener('input', e => {
    const el = e.target;
    if (!el.matches('.form-input,.form-select,.form-textarea')) return;
    if (el.classList.contains('field-error')) {
      el.classList.remove('field-error');
      el.nextElementSibling?.classList.contains('field-error-msg') && el.nextElementSibling.remove();
    }
  });
}

function _validateField(el) {
  const isRequired = el.hasAttribute('required') || el.closest('.form-group')?.querySelector('.form-label')?.textContent?.includes('*');
  if (!isRequired) return true;
  const val = el.value.trim();
  if (!val) {
    el.classList.add('field-error');
    // Adiciona msg de erro se não existir ainda
    if (!el.nextElementSibling?.classList.contains('field-error-msg')) {
      const msg = document.createElement('div');
      msg.className = 'field-error-msg';
      msg.innerHTML = '<i class="fas fa-exclamation-circle"></i> Este campo é obrigatório';
      el.insertAdjacentElement('afterend', msg);
    }
    return false;
  }
  el.classList.remove('field-error');
  el.nextElementSibling?.classList.contains('field-error-msg') && el.nextElementSibling.remove();
  return true;
}

function _validateModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return true;
  // Valida todos os campos required e os com asterisco no label
  let allOk = true;
  modal.querySelectorAll('.form-input[required],.form-select[required],.form-textarea[required]').forEach(el => {
    if (!_validateField(el)) allOk = false;
  });
  return allOk;
}

// ══════════════════════════════════════════════════════════════
//  CALENDÁRIO — VISÕES: MÊS / SEMANA / DIA
// ══════════════════════════════════════════════════════════════

let _calView = 'month';  // 'month' | 'week' | 'day'
let _calDayTarget = new Date();  // data de referência para week/day

function switchCalView(view, tabEl) {
  _calView = view;
  document.querySelectorAll('.cal-view-tab').forEach(t => t.classList.remove('active'));
  if (tabEl) tabEl.classList.add('active');
  renderCalendar();
}

async function renderCalendar(year, month, eventos) {
  if (eventos !== undefined) _calEventos = eventos;
  if (year  !== undefined) _calYear  = year;
  if (month !== undefined) { _calMonth = month; _calDayTarget = new Date(_calYear, _calMonth, _calDayTarget.getDate() || 1); }

  const container = document.getElementById('mini-calendar-container');
  if (!container) return;

  if (_calView === 'week') {
    _renderCalWeek(container);
  } else if (_calView === 'day') {
    _renderCalDay(container);
  } else {
    _renderCalMonth(container);
  }
}

function _renderCalMonth(container) {
  const hoje     = new Date();
  const primeiro = new Date(_calYear, _calMonth, 1);
  const ultimo   = new Date(_calYear, _calMonth + 1, 0);
  const diaSemana= primeiro.getDay();
  const meses    = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho',
                    'Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];

  const eventosPorDia = {};
  (_calEventos || []).forEach(ev => {
    if (ev.Data) {
      const key = ev.Data.substring(0, 10);
      if (!eventosPorDia[key]) eventosPorDia[key] = [];
      eventosPorDia[key].push(ev);
    }
  });

  let html = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <button class="btn btn-outline btn-sm" onclick="renderCalendar(${_calMonth===0?_calYear-1:_calYear},${_calMonth===0?11:_calMonth-1})">
        <i class="fas fa-chevron-left"></i>
      </button>
      <div style="font-family:'Syne',sans-serif;font-size:17px;font-weight:700">
        ${meses[_calMonth]} ${_calYear}
      </div>
      <button class="btn btn-outline btn-sm" onclick="renderCalendar(${_calMonth===11?_calYear+1:_calYear},${_calMonth===11?0:_calMonth+1})">
        <i class="fas fa-chevron-right"></i>
      </button>
    </div>
    <div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px;text-align:center;margin-bottom:8px">
      ${['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'].map(d =>
        `<div style="font-size:11px;font-weight:600;color:var(--text3);padding:4px">${d}</div>`
      ).join('')}
    </div>
    <div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px">`;

  for (let i = 0; i < diaSemana; i++) html += `<div style="min-height:44px"></div>`;

  for (let dia = 1; dia <= ultimo.getDate(); dia++) {
    const dateStr = `${_calYear}-${String(_calMonth+1).padStart(2,'0')}-${String(dia).padStart(2,'0')}`;
    const evsDia  = eventosPorDia[dateStr] || [];
    const isHoje  = dia === hoje.getDate() && _calMonth === hoje.getMonth() && _calYear === hoje.getFullYear();
    const temEv   = evsDia.length > 0;
    const cellStyle = isHoje
      ? 'background:var(--teal);color:var(--bg);border-radius:8px;font-weight:700'
      : temEv
        ? 'background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25);border-radius:8px;color:var(--teal);font-weight:600'
        : 'border-radius:8px';
    const tooltip = temEv ? evsDia.map(e => e.Titulo).join(', ').substring(0, 60) : '';

    html += `<div style="min-height:44px;padding:6px 4px;text-align:center;cursor:pointer;${cellStyle};transition:.15s"
         title="${esc(tooltip)}"
         onclick="${temEv ? `mostrarEventosDia('${dateStr}')` : isAdmin() ? `_criarEventoNoDia('${dateStr}')` : ''}">
      <div style="font-size:13px">${dia}</div>
      ${temEv ? `<div style="font-size:9px;margin-top:2px;overflow:hidden;white-space:nowrap;max-width:36px">● ${evsDia.length}</div>` : ''}
    </div>`;
  }
  html += `</div>`;

  // Próximos eventos
  if (_calEventos && _calEventos.length > 0) {
    const proxEvs = _calEventos
      .filter(e => e.Data && new Date(e.Data + 'T00:00:00') >= new Date(hoje.toDateString()))
      .sort((a,b) => new Date(a.Data) - new Date(b.Data)).slice(0, 3);
    if (proxEvs.length) {
      html += `<div style="margin-top:18px;border-top:1px solid var(--border);padding-top:14px">
        <div style="font-size:12px;font-weight:600;color:var(--text3);margin-bottom:8px;text-transform:uppercase;letter-spacing:1px">Próximos eventos</div>`;
      proxEvs.forEach(ev => {
        const cor = setorCor(ev.Tipo);
        html += `<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
          <div style="width:36px;height:36px;border-radius:8px;background:${cor.bg};border:1px solid ${cor.bd};display:flex;align-items:center;justify-content:center;flex-shrink:0;color:${cor.fg};font-size:12px;font-weight:700">
            ${new Date(ev.Data+'T00:00:00').getDate()}
          </div>
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(ev.Titulo)}</div>
            <div style="font-size:11px;color:var(--text3)">${formatDate(ev.Data)} ${ev.HoraInicio ? '• ' + ev.HoraInicio : ''}</div>
          </div>
          <span class="badge ${cor.badge}">${esc(ev.Tipo)}</span>
        </div>`;
      });
      html += `</div>`;
    }
  }

  container.innerHTML = html;
}

function _renderCalWeek(container) {
  const hoje = new Date();
  // Encontra domingo da semana de referência
  const ref  = new Date(_calDayTarget);
  const dow  = ref.getDay();
  const dom  = new Date(ref); dom.setDate(ref.getDate() - dow);

  const dias = Array.from({length:7}, (_, i) => { const d = new Date(dom); d.setDate(dom.getDate()+i); return d; });
  const meses= ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const semNomes = ['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'];

  const horas = Array.from({length:14}, (_, i) => 7 + i); // 07:00–20:00

  const eventosPorDia = {};
  (_calEventos || []).forEach(ev => {
    if (ev.Data) {
      const key = ev.Data.substring(0, 10);
      if (!eventosPorDia[key]) eventosPorDia[key] = [];
      eventosPorDia[key].push(ev);
    }
  });

  const prevDom  = new Date(dom); prevDom.setDate(dom.getDate()-7);
  const nextDom  = new Date(dom); nextDom.setDate(dom.getDate()+7);
  const fmtDate  = d => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;

  let html = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
      <button class="btn btn-outline btn-sm" onclick="_calDayTarget=new Date(${prevDom.getTime()});renderCalendar()"><i class="fas fa-chevron-left"></i></button>
      <div style="font-family:'Syne',sans-serif;font-size:16px;font-weight:700">
        ${dias[0].getDate()} ${meses[dias[0].getMonth()]} – ${dias[6].getDate()} ${meses[dias[6].getMonth()]} ${dias[6].getFullYear()}
      </div>
      <button class="btn btn-outline btn-sm" onclick="_calDayTarget=new Date(${nextDom.getTime()});renderCalendar()"><i class="fas fa-chevron-right"></i></button>
    </div>
    <div style="display:grid;grid-template-columns:44px repeat(7,1fr);border:1px solid var(--border);border-radius:10px;overflow:hidden">
      <div style="background:var(--bg3)"></div>`;

  dias.forEach(d => {
    const isHoje = d.toDateString() === hoje.toDateString();
    html += `<div style="text-align:center;padding:8px 4px;background:var(--bg3);border-left:1px solid var(--border);font-size:11px">
      <div style="font-weight:600;color:var(--text3)">${semNomes[d.getDay()]}</div>
      <div style="font-family:'Syne',sans-serif;font-size:18px;font-weight:700;${isHoje?'color:var(--teal)':''}">${d.getDate()}</div>
    </div>`;
  });

  horas.forEach(h => {
    const label = `${String(h).padStart(2,'0')}:00`;
    html += `<div style="font-size:10px;color:var(--text3);padding:8px 4px;text-align:right;border-top:1px solid var(--border);background:var(--bg3)">${label}</div>`;
    dias.forEach(d => {
      const key  = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
      const evs  = (eventosPorDia[key] || []).filter(ev => {
        const hStr = (ev.HoraInicio || '').split(':')[0];
        return parseInt(hStr) === h;
      });
      const isHoje = d.toDateString() === hoje.toDateString();
      const ds = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
      const clickFn = evs.length ? `mostrarEventosDia('${ds}')` : isAdmin() ? `_criarEventoNoDia('${ds}','${label}')` : '';
      html += `<div onclick="${clickFn}" style="border-left:1px solid var(--border);border-top:1px solid var(--border);min-height:40px;padding:3px;cursor:${clickFn?'pointer':'default'};${isHoje?'background:rgba(239,68,68,.03)':''}">
        ${evs.map(ev => { const cor = setorCor(ev.Tipo); return `<div class="cal-ev-chip" style="background:${cor.bg};color:${cor.fg}" title="${esc(ev.Titulo)}" onclick="event.stopPropagation();mostrarEventosDia('${ds}')">${esc(ev.Titulo)}</div>`; }).join('')}
      </div>`;
    });
  });

  html += `</div>`;
  container.innerHTML = html;
}

function _renderCalDay(container) {
  const d    = new Date(_calDayTarget);
  const hoje = new Date();
  const semNomes = ['Domingo','Segunda','Terça','Quarta','Quinta','Sexta','Sábado'];
  const meses    = ['janeiro','fevereiro','março','abril','maio','junho','julho','agosto','setembro','outubro','novembro','dezembro'];
  const key      = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
  const horas    = Array.from({length:14}, (_, i) => 7 + i);

  const evsDia   = (_calEventos || []).filter(ev => (ev.Data || '').substring(0,10) === key);
  const evsPorHora = {};
  evsDia.forEach(ev => {
    const h = parseInt((ev.HoraInicio || '').split(':')[0]) || 8;
    if (!evsPorHora[h]) evsPorHora[h] = [];
    evsPorHora[h].push(ev);
  });

  const prevD = new Date(d); prevD.setDate(d.getDate()-1);
  const nextD = new Date(d); nextD.setDate(d.getDate()+1);

  let html = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px">
      <button class="btn btn-outline btn-sm" onclick="_calDayTarget=new Date(${prevD.getTime()});renderCalendar()"><i class="fas fa-chevron-left"></i></button>
      <div style="text-align:center">
        <div style="font-family:'Syne',sans-serif;font-size:20px;font-weight:700;${d.toDateString()===hoje.toDateString()?'color:var(--teal)':''}">${semNomes[d.getDay()]}</div>
        <div style="font-size:13px;color:var(--text2)">${d.getDate()} de ${meses[d.getMonth()]} de ${d.getFullYear()}</div>
      </div>
      <button class="btn btn-outline btn-sm" onclick="_calDayTarget=new Date(${nextD.getTime()});renderCalendar()"><i class="fas fa-chevron-right"></i></button>
    </div>
    <div style="border:1px solid var(--border);border-radius:10px;overflow:hidden">`;

  horas.forEach(h => {
    const label = `${String(h).padStart(2,'0')}:00`;
    const evs   = evsPorHora[h] || [];
    const ds    = key;
    const clickFn = evs.length ? `mostrarEventosDia('${ds}')` : isAdmin() ? `_criarEventoNoDia('${ds}','${label}')` : '';
    html += `<div style="display:grid;grid-template-columns:56px 1fr;border-top:1px solid var(--border);min-height:52px">
      <div style="font-size:11px;color:var(--text3);padding:10px 8px;text-align:right;background:var(--bg3)">${label}</div>
      <div onclick="${clickFn}" style="padding:6px 10px;cursor:${clickFn?'pointer':'default'};${evs.length?'background:rgba(239,68,68,.04)':''}${!evs.length&&isAdmin()?' transition:background .15s;':''}">
        ${evs.map(ev => { const cor = setorCor(ev.Tipo);
          return `<div style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:8px;background:${cor.bg};border:1px solid ${cor.bd};margin-bottom:4px;cursor:pointer" onclick="event.stopPropagation();mostrarEventosDia('${ds}')">
            <div style="font-size:13px;font-weight:600;color:${cor.fg}">${esc(ev.Titulo)}</div>
            ${ev.HoraInicio ? `<div style="font-size:11px;color:var(--text3);margin-left:auto">${ev.HoraInicio}${ev.HoraFim?'–'+ev.HoraFim:''}</div>` : ''}
          </div>`; }).join('')}
        ${!evs.length && isAdmin() ? `<div style="font-size:11px;color:var(--text3);opacity:0;transition:opacity .2s" class="add-ev-hint"><i class="fas fa-plus"></i> clique para criar</div>` : ''}
      </div>
    </div>`;
  });

  html += `</div>`;
  container.innerHTML = html;

  // Hover hint para admin
  if (isAdmin()) {
    container.querySelectorAll('[onclick*="_criarEventoNoDia"]').forEach(cell => {
      const hint = cell.querySelector('.add-ev-hint');
      if (hint) {
        cell.addEventListener('mouseenter', () => hint.style.opacity = '1');
        cell.addEventListener('mouseleave', () => hint.style.opacity = '0');
      }
    });
  }
}

function _criarEventoNoDia(dateStr, hora) {
  if (!requireAdmin('criar eventos')) return;
  const modal = document.getElementById('modal-novo-evento');
  if (!modal) { openModal('modal-novo-evento'); return; }
  // Pré-preenche data e hora
  const dataEl = modal.querySelector('input[type="date"]');
  const horaEl = modal.querySelector('input[type="time"]');
  if (dataEl) dataEl.value = dateStr;
  if (horaEl && hora) horaEl.value = hora.replace(':00','') + ':00';
  openModal('modal-novo-evento');
}

// ══════════════════════════════════════════════════════════════
//  DOCUMENTOS ESTÁTICOS — Edição de nome, categoria e link Drive
// ══════════════════════════════════════════════════════════════

/** Referência ao card estático sendo editado */
let _editDocCard = null;

/**
 * Abre o modal de edição de um card estático.
 * @param {HTMLElement} card - O elemento .doc-card a editar
 */
function editarDocStatic(card) {
  if (!requireAdmin('editar documentos')) return;
  _editDocCard = card;

  const nome    = card.getAttribute('data-nome') || '';
  const cat     = card.getAttribute('data-cat')  || 'Geral';
  const url     = card.getAttribute('data-drive-url') || '';
  const tamanho = card.getAttribute('data-tamanho') || '';

  document.getElementById('edit-doc-static-nome').value    = nome;
  document.getElementById('edit-doc-static-tamanho').value = tamanho;
  document.getElementById('edit-doc-static-url').value     = url;

  const catSel = document.getElementById('edit-doc-static-cat');
  for (let opt of catSel.options) {
    if (opt.value === cat || opt.text === cat) { catSel.value = opt.value; break; }
  }

  // Preview do link atual
  _atualizarPreviewDocStatic(url);

  // Atualiza preview ao digitar
  document.getElementById('edit-doc-static-url').oninput = function() {
    _atualizarPreviewDocStatic(this.value.trim());
  };

  openModal('modal-edit-doc-static');
}

function _atualizarPreviewDocStatic(url) {
  const prev = document.getElementById('edit-doc-static-preview');
  const txt  = document.getElementById('edit-doc-static-preview-text');
  if (!prev || !txt) return;
  if (url && url.startsWith('http')) {
    prev.style.display = 'block';
    txt.textContent = 'Link válido — o card abrirá o Drive ao ser clicado.';
  } else {
    prev.style.display = 'none';
  }
}

/**
 * Salva as alterações do card estático (persiste em localStorage).
 */
async function salvarDocStatic() {
  const card = _editDocCard;
  if (!card) return;

  const nome    = document.getElementById('edit-doc-static-nome').value.trim();
  const cat     = document.getElementById('edit-doc-static-cat').value;
  const url     = document.getElementById('edit-doc-static-url').value.trim();
  const tamanho = document.getElementById('edit-doc-static-tamanho').value.trim();

  if (!nome) { showToast('Informe o nome do documento.', 'warning'); return; }

  // Atualiza atributos de dados
  card.setAttribute('data-nome',      nome.toLowerCase());
  card.setAttribute('data-cat',       cat);
  card.setAttribute('data-drive-url', url);
  card.setAttribute('data-tamanho',   tamanho);

  // Atualiza textos visíveis no card
  const nomeEl = card.querySelector('.doc-static-nome');
  if (nomeEl) nomeEl.textContent = nome;

  const tamEl = card.querySelector('.doc-static-tamanho');
  if (tamEl) tamEl.textContent = tamanho;

  // Indicador de link
  const linkInd = card.querySelector('.doc-link-indicator');
  if (linkInd) linkInd.style.display = url ? 'block' : 'none';

  // Atualiza badge de categoria
  const badgeMap = { Ata:'lav', Financeiro:'gold', Regulamento:'teal', Marketing:'lav',
                     Pesquisa:'teal', 'Extensão':'sage', Ensino:'sage', Imagem:'lav', Geral:'sage' };
  const badge = card.querySelector('.badge');
  if (badge) {
    badge.className = 'badge ' + (badgeMap[cat] || 'teal');
    badge.textContent = cat;
    badge.style.cssText = 'font-size:9px;position:absolute;top:8px;right:8px';
  }

  // Persiste na sheet ConfigDocumentos via API
  await _persistirDocsStatic();

  closeModal('modal-edit-doc-static');
  showToast(`"${nome}" atualizado com sucesso!`, 'success');
}

/**
 * Abre o link do Drive ao clicar no card estático.
 */
function abrirDocStatic(card) {
  const url = card.getAttribute('data-drive-url') || '';
  if (url && url.startsWith('http')) {
    window.open(url, '_blank', 'noopener');
  } else {
    const nome = card.querySelector('.doc-static-nome')?.textContent || 'Este documento';
    if (isAdmin()) {
      showToast(`"${nome}" não possui link do Drive. Clique em ✏️ para vincular.`, 'info');
    } else {
      showToast(`"${nome}" ainda não está disponível para download.`, 'info');
    }
  }
}

// ── Persistência dos cards estáticos via API (sheet: ConfigDocumentos) ──────

/**
 * Persiste o estado atual de todos os cards estáticos na sheet ConfigDocumentos.
 * Cada card é um registro identificado pelo campo "nome" (chave natural).
 */
async function _persistirDocsStatic() {
  if (!isAdmin()) return;
  const cards = document.querySelectorAll('#docs-static-grid .doc-card');
  const registros = [];
  cards.forEach(card => {
    const nome = card.querySelector('.doc-static-nome')?.textContent?.trim() || '';
    if (!nome) return;
    registros.push({
      nome,
      cat:     card.getAttribute('data-cat')       || '',
      url:     card.getAttribute('data-drive-url') || '',
      tamanho: card.getAttribute('data-tamanho')   || '',
    });
  });

  // Estratégia: apaga todos e recria (upsert simples via insert com id=nome)
  try {
    for (const reg of registros) {
      // Tenta atualizar; se falhar (não existe), insere
      try {
        await apiPost({
          action: 'update',
          sheet:  'ConfigDocumentos',
          id:     reg.nome,
          row:    reg,
        });
      } catch(_) {
        await apiPost({
          action: 'insert',
          sheet:  'ConfigDocumentos',
          row:    { id: reg.nome, ...reg },
        });
      }
    }
  } catch(e) {
    console.warn('_persistirDocsStatic:', e.message);
  }
}

/**
 * Restaura o estado dos cards estáticos a partir da sheet ConfigDocumentos.
 */
async function _restaurarDocsStatic() {
  try {
    const data = await apiGet({ action: 'getAll', sheet: 'ConfigDocumentos' });
    if (!data || data.length === 0) return;

    const cards = document.querySelectorAll('#docs-static-grid .doc-card');
    const badgeMap = {
      Ata:'lav', Financeiro:'gold', Regulamento:'teal', Marketing:'lav',
      Pesquisa:'teal', 'Extensão':'sage', Ensino:'sage', Imagem:'lav', Geral:'sage',
    };

    cards.forEach(card => {
      const nomeEl  = card.querySelector('.doc-static-nome');
      const nomeAtual = nomeEl?.textContent?.trim() || '';
      // Encontra o registro pelo nome atual do card
      const reg = data.find(r => String(r.nome || r.id || '').toLowerCase() === nomeAtual.toLowerCase());
      if (!reg) return;

      if (reg.cat)     card.setAttribute('data-cat',       reg.cat);
      if (reg.url)     card.setAttribute('data-drive-url', reg.url);
      if (reg.tamanho) card.setAttribute('data-tamanho',   reg.tamanho);
      if (reg.nome)    card.setAttribute('data-nome',      reg.nome.toLowerCase());

      if (nomeEl && reg.nome) nomeEl.textContent = reg.nome;

      const tamEl = card.querySelector('.doc-static-tamanho');
      if (tamEl && reg.tamanho) tamEl.textContent = reg.tamanho;

      const linkInd = card.querySelector('.doc-link-indicator');
      if (linkInd) linkInd.style.display = reg.url ? 'block' : 'none';

      const badge = card.querySelector('.badge');
      if (badge && reg.cat) {
        badge.className = 'badge ' + (badgeMap[reg.cat] || 'teal');
        badge.textContent = reg.cat;
        badge.style.cssText = 'font-size:9px;position:absolute;top:8px;right:8px';
      }
    });
  } catch(e) {
    console.warn('_restaurarDocsStatic:', e.message);
  }
}

// ══════════════════════════════════════════════════════════════
//  GOOGLE APPS SCRIPT — Código de referência para o backend
// ══════════════════════════════════════════════════════════════
/*
  ┌─────────────────────────────────────────────────────────────┐
  │  Cole o código abaixo no Google Apps Script e reimplante   │
  │  como Web App (acesso: qualquer pessoa, mesmo anônima)      │
  └─────────────────────────────────────────────────────────────┘

// ── Configurações ──────────────────────────────────────────────
const SS_ID         = SpreadsheetApp.getActiveSpreadsheet().getId();
const DRIVE_FOLDER  = ''; // (Opcional) ID da pasta no Drive para uploads

// ── GET: getAll / getById ──────────────────────────────────────
function doGet(e) {
  try {
    const p      = e.parameter || {};
    const action = p.action || 'getAll';
    const sheet  = p.sheet  || 'Membros';
    const ss     = SpreadsheetApp.openById(SS_ID);

    if (action === 'getAll') {
      const data = sheetToObjects(ss.getSheetByName(sheet));
      return jsonOk(data);
    }
    if (action === 'getById') {
      const data = sheetToObjects(ss.getSheetByName(sheet));
      const row  = data.find(r => String(r.id) === String(p.id));
      return jsonOk(row || null);
    }
    return jsonErr('Ação GET não reconhecida: ' + action);
  } catch(err) {
    return jsonErr(err.message);
  }
}

// ── POST: insert / update / uploadFile ────────────────────────
function doPost(e) {
  try {
    const payload = JSON.parse(e.postData.contents);
    const action  = payload.action;
    const sheet   = payload.sheet;
    const ss      = SpreadsheetApp.openById(SS_ID);

    // ── INSERT ────────────────────────────────────────────────
    if (action === 'insert') {
      const ws   = getOrCreateSheet(ss, sheet);
      const row  = payload.row || {};
      row.id     = row.id || Utilities.getUuid();
      appendRow(ws, row);
      return jsonOk({ id: row.id });
    }

    // ── UPDATE ────────────────────────────────────────────────
    if (action === 'update') {
      const ws   = ss.getSheetByName(sheet);
      if (!ws) return jsonErr('Sheet não encontrada: ' + sheet);
      const rows = sheetToObjects(ws);
      const idx  = rows.findIndex(r => String(r.id) === String(payload.id));
      if (idx < 0) return jsonErr('Registro não encontrado: id=' + payload.id);
      const updated = Object.assign(rows[idx], payload.row || {});
      writeRow(ws, idx + 2, ws.getRange(1,1,1, ws.getLastColumn()).getValues()[0], updated);
      return jsonOk({ updated: true });
    }

    // ── UPLOAD FILE → Google Drive + registro em "Documentos" ─
    if (action === 'uploadFile') {
      const bytes    = Utilities.base64Decode(payload.data);
      const blob     = Utilities.newBlob(bytes, payload.mimeType, payload.fileName);

      // Salva no Drive
      let folder;
      try {
        folder = DRIVE_FOLDER ? DriveApp.getFolderById(DRIVE_FOLDER) : DriveApp.getRootFolder();
      } catch(_) {
        folder = DriveApp.getRootFolder();
      }
      const file = folder.createFile(blob);
      file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);
      const fileUrl = file.getUrl();

      // Registra na sheet "Documentos"
      const docsSheet = getOrCreateSheet(ss, 'Documentos');
      const docRow = {
        id:         Utilities.getUuid(),
        fileName:   payload.fileName   || '',
        mimeType:   payload.mimeType   || '',
        categoria:  payload.categoria  || 'Geral',
        descricao:  payload.descricao  || '',
        tamanho:    payload.tamanho    || '',
        dataUpload: payload.dataUpload || new Date().toISOString().split('T')[0],
        url:        fileUrl,
      };
      appendRow(docsSheet, docRow);

      return jsonOk({ url: fileUrl, id: docRow.id });
    }

    // ── DELETE ────────────────────────────────────────────────
    if (action === 'delete') {
      const ws   = ss.getSheetByName(sheet);
      if (!ws) return jsonErr('Sheet não encontrada: ' + sheet);
      const rows = sheetToObjects(ws);
      const idx  = rows.findIndex(r => String(r.id) === String(payload.id));
      if (idx < 0) return jsonErr('Registro não encontrado.');
      ws.deleteRow(idx + 2);
      return jsonOk({ deleted: true });
    }

    return jsonErr('Ação POST não reconhecida: ' + action);
  } catch(err) {
    return jsonErr(err.message);
  }
}

// ── Helpers ───────────────────────────────────────────────────
function sheetToObjects(ws) {
  if (!ws) return [];
  const [headers, ...rows] = ws.getDataRange().getValues();
  return rows.map(r => Object.fromEntries(headers.map((h, i) => [h, r[i]])));
}

function appendRow(ws, obj) {
  if (ws.getLastRow() === 0) {
    ws.appendRow(Object.keys(obj));
  }
  const headers = ws.getRange(1, 1, 1, ws.getLastColumn()).getValues()[0];
  ws.appendRow(headers.map(h => obj[h] ?? ''));
}

function writeRow(ws, rowNum, headers, obj) {
  ws.getRange(rowNum, 1, 1, headers.length)
    .setValues([headers.map(h => obj[h] ?? '')]);
}

function getOrCreateSheet(ss, name) {
  return ss.getSheetByName(name) || ss.insertSheet(name);
}

function jsonOk(data) {
  return ContentService
    .createTextOutput(JSON.stringify({ success: true, data }))
    .setMimeType(ContentService.MimeType.JSON);
}

function jsonErr(msg) {
  return ContentService
    .createTextOutput(JSON.stringify({ success: false, error: msg }))
    .setMimeType(ContentService.MimeType.JSON);
}
*/
// ── Fim do código de referência do Apps Script ────────────────

// ══════════════════════════════════════════════════════════════
//  LOADER — RELATÓRIOS (gráficos dinâmicos)
// ══════════════════════════════════════════════════════════════

async function loadRelatorios() {
  try {
    const [eventos, membros] = await Promise.all([
      apiGet({ action: 'getAll', sheet: 'Eventos' }),
      apiGet({ action: 'getAll', sheet: 'Membros' }),
    ]);

    _renderRelEventosMes(eventos);
    _renderRelMembrosSemestre(membros);
  } catch(e) {
    console.warn('loadRelatorios:', e);
  }
}

/**
 * Gráfico de barras: eventos por mês no ano corrente.
 * Usa dados reais da sheet Eventos (campo: Data = "YYYY-MM-DD").
 */
function _renderRelEventosMes(eventos) {
  const chart = document.getElementById('rel-chart-eventos');
  if (!chart) return;

  const anoAtual = new Date().getFullYear();
  const meses = ['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'];
  const contagem = new Array(12).fill(0);

  if (eventos && eventos.length > 0) {
    eventos.forEach(ev => {
      const d = new Date((ev.Data || '') + 'T00:00:00');
      if (!isNaN(d) && d.getFullYear() === anoAtual) {
        contagem[d.getMonth()]++;
      }
    });
  }

  const maxVal  = Math.max(...contagem, 1);
  const mesAtual = new Date().getMonth();
  const gradient = 'linear-gradient(0deg,var(--teal),var(--sky))';

  chart.innerHTML = meses.map((mes, i) => {
    const val     = contagem[i];
    const altura  = Math.max(8, Math.round((val / maxVal) * 90));
    const isFuturo = i > mesAtual;
    const opacidade = isFuturo ? 'opacity:.25;' : '';
    return `<div class="bar" style="height:${altura}%;background:${gradient};${opacidade}position:relative"
              data-label="${mes}" title="${mes}: ${val} evento(s)">
      <span style="position:absolute;top:-18px;width:100%;text-align:center;font-size:10px;color:var(--text2);font-weight:600">${val > 0 ? val : '—'}</span>
    </div>`;
  }).join('');
}

/**
 * Gráfico de barras: membros cadastrados por semestre de ingresso.
 * Usa dados reais da sheet Membros (campo: DataIngresso = "YYYY-MM-DD").
 * Agrupa nos últimos 6 semestres.
 */
function _renderRelMembrosSemestre(membros) {
  const chart = document.getElementById('rel-chart-membros');
  if (!chart) return;

  // Gera os 6 semestres mais recentes (inclusive o atual)
  const semestres = [];
  const hoje = new Date();
  let ano = hoje.getFullYear();
  let sem = hoje.getMonth() < 6 ? 1 : 2;
  for (let i = 0; i < 6; i++) {
    semestres.unshift({ label: `${ano}.${sem}`, ano, sem });
    sem--;
    if (sem === 0) { sem = 2; ano--; }
  }

  const contagem = {};
  semestres.forEach(s => { contagem[s.label] = 0; });

  if (membros && membros.length > 0) {
    membros.forEach(m => {
      const d = new Date((m.DataIngresso || '') + 'T00:00:00');
      if (isNaN(d)) return;
      const mSem   = d.getMonth() < 6 ? 1 : 2;
      const mLabel = `${d.getFullYear()}.${mSem}`;
      if (contagem[mLabel] !== undefined) contagem[mLabel]++;
    });
  }

  const valores  = semestres.map(s => contagem[s.label]);
  const maxVal   = Math.max(...valores, 1);
  const gradient = 'linear-gradient(0deg,var(--lavender),var(--sky))';

  chart.innerHTML = semestres.map((s, i) => {
    const val    = valores[i];
    const altura = Math.max(8, Math.round((val / maxVal) * 90));
    return `<div class="bar" style="height:${altura}%;background:${gradient};position:relative"
              data-label="${s.label}" title="${s.label}: ${val} membro(s) ingressante(s)">
      <span style="position:absolute;top:-18px;width:100%;text-align:center;font-size:10px;color:var(--text2);font-weight:600">${val > 0 ? val : '—'}</span>
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
//  GRÁFICO DONUT — Distribuição por setor (dinâmico)
// ══════════════════════════════════════════════════════════════

function renderDonutSetor(membros) {
  const wrap = document.getElementById('home-setor-donut');
  if (!wrap) return;

  if (!membros || membros.length === 0) {
    wrap.innerHTML = '<div style="text-align:center;width:100%;padding:20px;color:var(--text3);font-size:13px">Sem dados de membros</div>';
    return;
  }

  // Conta membros ativos por setor
  const contagem = {};
  membros.filter(m => m.Status === 'Ativo' || !m.Status).forEach(m => {
    const s = m.Setor || 'Outros';
    contagem[s] = (contagem[s] || 0) + 1;
  });

  const total = Object.values(contagem).reduce((a, b) => a + b, 0);
  if (total === 0) { wrap.innerHTML = '<div style="text-align:center;width:100%;padding:20px;color:var(--text3)">Nenhum membro ativo</div>'; return; }

  const cores = {
    Pesquisa:   'var(--teal)',
    Marketing:  'var(--lavender)',
    Tesouraria: 'var(--gold)',
    Extensão:   'var(--sky)',
    Ensino:     'var(--sage)',
    Secretaria: 'var(--coral)',
    Outros:     'var(--text3)',
  };
  const coresFallback = ['var(--teal)','var(--lavender)','var(--gold)','var(--sage)','var(--sky)','var(--coral)'];

  const sorted  = Object.entries(contagem).sort((a, b) => b[1] - a[1]);
  const circ    = 2 * Math.PI * 40; // circumference

  let offset = 0;
  const arcs = sorted.map(([setor, cnt], i) => {
    const pct  = cnt / total;
    const dash = circ * pct;
    const cor  = cores[setor] || coresFallback[i % coresFallback.length];
    const arc  = `<circle cx="55" cy="55" r="40" fill="none" stroke="${cor}" stroke-width="18"
      stroke-dasharray="${dash.toFixed(2)} ${circ.toFixed(2)}"
      stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 55 55)"/>`;
    offset += dash;
    return { arc, cor, setor, cnt };
  });

  const svgArcs = arcs.map(a => a.arc).join('\n');
  const legendHtml = arcs.map(a =>
    `<div class="legend-item"><div class="legend-dot" style="background:${a.cor}"></div>${a.setor} <strong style="margin-left:auto">${a.cnt}</strong></div>`
  ).join('');

  wrap.innerHTML = `
    <svg class="donut-svg" width="110" height="110" viewBox="0 0 110 110">
      <circle cx="55" cy="55" r="40" fill="none" stroke="var(--bg3)" stroke-width="18"/>
      ${svgArcs}
      <text x="55" y="59" text-anchor="middle" fill="var(--text)" font-size="14" font-weight="700" font-family="Syne,sans-serif">${total}</text>
    </svg>
    <div class="donut-legend">${legendHtml}</div>`;
}

// ══════════════════════════════════════════════════════════════
//  GRÁFICO DE BARRAS — Atividade por setor (dinâmico)
// ══════════════════════════════════════════════════════════════

function renderBarChart(membros) {
  const chart = document.getElementById('home-atividade-chart');
  if (!chart) return;

  const setores = ['Secretaria','Tesouraria','Marketing','Pesquisa','Extensão','Ensino'];
  const gradientes = [
    'linear-gradient(0deg,var(--teal),var(--sky))',
    'linear-gradient(0deg,var(--gold),var(--coral))',
    'linear-gradient(0deg,var(--lavender),var(--sky))',
    'linear-gradient(0deg,var(--teal),var(--sage))',
    'linear-gradient(0deg,var(--sage),var(--teal))',
    'linear-gradient(0deg,var(--sky),var(--sage))',
  ];

  let contagem = {};
  if (membros && membros.length > 0) {
    membros.forEach(m => {
      const s = m.Setor || 'Outros';
      contagem[s] = (contagem[s] || 0) + 1;
    });
  }

  const maxVal = Math.max(...setores.map(s => contagem[s] || 0), 1);

  chart.innerHTML = setores.map((s, i) => {
    const val = contagem[s] || 0;
    const h   = maxVal > 0 ? Math.max(8, Math.round((val / maxVal) * 90)) : 15;
    return `<div class="bar" style="height:${h}%;background:${gradientes[i]};position:relative" data-label="${s}" title="${s}: ${val} membro(s)">
      <span style="position:absolute;top:-18px;width:100%;text-align:center;font-size:10px;color:var(--text2);font-weight:600">${val || '—'}</span>
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
//  BADGES DINÂMICOS DA SIDEBAR
// ══════════════════════════════════════════════════════════════

function _updateNavBadges({ eventos, ouvidoria, financeiro }) {
  // Agenda: eventos próximos (próximos 30 dias)
  const badgeAg = document.getElementById('nav-badge-agenda');
  if (badgeAg && eventos) {
    const hoje = new Date(); hoje.setHours(0,0,0,0);
    const em30 = new Date(hoje); em30.setDate(hoje.getDate() + 30);
    const prox = eventos.filter(e => {
      const d = new Date((e.Data || '') + 'T00:00:00');
      return d >= hoje && d <= em30;
    }).length;
    badgeAg.textContent = prox;
    badgeAg.style.display = prox > 0 ? '' : 'none';
  }

  // Ouvidoria: pendências
  const badgeOuv = document.getElementById('nav-badge-ouvidoria');
  if (badgeOuv && ouvidoria) {
    const pend = ouvidoria.filter(o => o.Status !== 'Resolvido').length;
    badgeOuv.textContent = pend;
    badgeOuv.style.display = pend > 0 ? '' : 'none';
  }

  // Tesouraria: saldo negativo → alerta
  const badgeTes = document.getElementById('nav-badge-tesouraria');
  if (badgeTes && financeiro) {
    let saldo = 0;
    financeiro.forEach(m => {
      const v = parseFloat(m.Valor) || 0;
      saldo += String(m.Tipo).toLowerCase() === 'receita' ? v : -v;
    });
    badgeTes.style.display = saldo < 0 ? '' : 'none';
  }
}

// ══════════════════════════════════════════════════════════════
//  ATUALIZA STATS DAS PÁGINAS DE EXTENSÃO, PESQUISA E ENSINO
// ══════════════════════════════════════════════════════════════

function _updateExtensaoStats(data) {
  const total   = data ? data.length : 0;
  const pessoas = data ? data.reduce((a, r) => a + (parseInt(r.Participantes) || 0), 0) : 0;

  const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  setEl('ext-stat-acoes',       total || '—');
  setEl('ext-stat-acoes-sub',   total > 0 ? `${total} ação(ões) registrada(s)` : 'Nenhuma ação ainda');
  setEl('ext-stat-pessoas',     pessoas > 0 ? pessoas.toLocaleString('pt-BR') : '—');
  setEl('ext-stat-pessoas-sub', pessoas > 0 ? 'Participantes somados' : 'Sem dados de participantes');
  // NOTA: ext-stat-parcerias é atualizado exclusivamente por loadExtensao,
  // que carrega a sheet Parceiros em paralelo. Não tocar aqui.
}

function _updatePesquisaStats(data) {
  const ativos   = data ? data.filter(p => ['Coleta de dados','Análise','Escrita','Aguardando CEP','Planejamento'].includes(p.Status)).length : 0;
  const publicados = data ? data.filter(p => p.Status === 'Publicado').length : 0;
  const total    = data ? data.length : 0;

  const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const setHTML = (id, v) => { const el = document.getElementById(id); if (el) el.innerHTML = v; };
  setEl('pesq-stat-ativos',     ativos || '—');
  setHTML('pesq-stat-ativos-sub', `<i class="fas fa-flask"></i> ${total - ativos - publicados} em análise`);
  setEl('pesq-stat-pub',        publicados || '—');
  setHTML('pesq-stat-pub-sub',   `<i class="fas fa-book"></i> ${ativos} em andamento`);
  // Congressos não temos sheet → indicador manual via configurações
  setEl('pesq-stat-cong',       '—');
  setHTML('pesq-stat-cong-sub',  `<i class="fas fa-info-circle"></i> Configure via Configuracoes`);
}

function _updateEnsinoStats(data) {
  const ativos = data ? data.filter(c => c.Status !== 'Encerrado').length : 0;
  const horas  = data ? data.reduce((a, c) => a + (parseInt(c.CargaHoraria) || 0), 0) : 0;

  const setEl = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const setHTML = (id, v) => { const el = document.getElementById(id); if (el) el.innerHTML = v; };
  setEl('ens-stat-cursos',       ativos || '—');
  setHTML('ens-stat-cursos-sub', `<i class="fas fa-book-open"></i> ${data ? data.length : 0} total cadastrado(s)`);
  setEl('ens-stat-horas',        horas > 0 ? horas + 'h' : '—');
  setHTML('ens-stat-horas-sub',  `<i class="fas fa-clock"></i> Carga total ofertada`);
}

// ══════════════════════════════════════════════════════════════
//  LAST REFRESH INDICATOR
// ══════════════════════════════════════════════════════════════

function _updateLastRefresh() {
  const el = document.getElementById('last-refresh');
  if (!el) return;
  const now = new Date();
  el.innerHTML = `<i class="fas fa-circle" style="color:var(--sage);font-size:7px"></i> ${now.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'})}`;
}

// ══════════════════════════════════════════════════════════════
//  RECARREGAR TODOS OS DADOS (botão refresh)
// ══════════════════════════════════════════════════════════════

async function recarregarDados() {
  // Limpa cache para forçar re-fetch
  Object.keys(_apiCache).forEach(k => delete _apiCache[k]);

  const btn = document.getElementById('btn-refresh');
  if (btn) { btn.style.pointerEvents = 'none'; btn.querySelector('i').classList.add('fa-spin'); }

  // Recarrega a página atual
  const active = document.querySelector('.page.active');
  if (active) {
    const id = active.id.replace('page-','');
    const loaders = {
      home: loadHomeStats, membros: loadMembros, secretaria: loadSecretaria,
      tesouraria: loadTesouraria, agenda: loadAgenda, pesquisa: loadPesquisa,
      extensao: loadExtensao, ensino: loadEnsino, ouvidoria: loadOuvidoria,
      marketing: loadMarketing, documentos: loadDocumentos, relatorios: loadRelatorios,
    };
    if (loaders[id]) await loaders[id]();
  }

  if (btn) { btn.style.pointerEvents = ''; btn.querySelector('i').classList.remove('fa-spin'); }
  _updateLastRefresh();
  showToast('Dados atualizados!', 'success');
}

// ══════════════════════════════════════════════════════════════
//  INICIALIZAÇÃO
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
//  SIDEBAR MOBILE — toggle, overlay e fechamento automático
// ══════════════════════════════════════════════════════════════

function toggleMobileSidebar() {
  const sidebar  = document.querySelector('.sidebar');
  const overlay  = document.getElementById('sidebar-overlay');
  const icon     = document.getElementById('hamburger-icon');
  const isOpen   = sidebar.classList.contains('mobile-open');
  if (isOpen) {
    closeMobileSidebar();
  } else {
    sidebar.classList.add('mobile-open');
    overlay.classList.add('visible');
    icon.className = 'fas fa-times';
  }
}

function closeMobileSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  const icon    = document.getElementById('hamburger-icon');
  sidebar.classList.remove('mobile-open');
  overlay.classList.remove('visible');
  if (icon) icon.className = 'fas fa-bars';
}

// Fecha ao pressionar ESC (complementa o fechamento de modais)
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && document.querySelector('.sidebar.mobile-open')) {
    closeMobileSidebar();
  }
});

document.addEventListener('DOMContentLoaded', async () => {
  // Fecha sidebar mobile ao clicar em qualquer item de navegação
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      if (window.innerWidth <= 900) closeMobileSidebar();
    });
  });
  applyTheme();
  setupKanbanIds();
  // NOTA: _restaurarDocsStatic() é chamada em loginSuccess() — após autenticação.

  // Verifica sessão salva
  const savedRole = sessionStorage.getItem('lapa-role');
  if (savedRole && CREDENTIALS[savedRole]) {
    // Auto-login com sessão existente
    loginSuccess(savedRole);
  } else {
    // Foca no campo de senha
    setTimeout(() => document.getElementById('login-senha')?.focus(), 300);
  }
});
