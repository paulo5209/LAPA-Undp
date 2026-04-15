// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — Arquivo Principal de Inicialização
// ═══════════════════════════════════════════════════════════════

'use strict';

/**
 * Estrutura modular do LAPA Dashboard:
 * - auth.js: Autenticação e segurança
 * - api.js: Comunicação com Google Apps Script
 * - ui.js: Interface e navegação
 * - utils.js: Utilitários gerais
 * - members.js: Gestão de membros
 * - main.js: Lógica específica das páginas (legado)
 */

// Carregar módulo de autenticação primeiro
(async function init() {
  // Restaurar sessão se existir
  const savedRole = localStorage.getItem('lapa-role');
  if (savedRole) {
    window.auth.currentRole = savedRole;
    document.getElementById('login-section')?.classList.add('hidden');
    document.getElementById('app-container')?.classList.remove('hidden');
    showPage('home');
  } else {
    showPage('login');
  }
  
  // Aplicar tema salvo
  applyTheme();
  
  // Setup de validação inline
  setupInlineValidation();
  
  // Event listeners globais
  setupGlobalListeners();
  
  console.log('LAPA Dashboard inicializado com sucesso!');
})();

function setupGlobalListeners() {
  // Fechar modal ao clicar fora
  document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal')) {
      closeModal(e.target.id);
    }
  });
  
  // Enter em campos de login
  document.getElementById('login-senha')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  
  // Tecla ESC fecha modais
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal.open').forEach(modal => {
        closeModal(modal.id);
      });
    }
  });
}

// Função de login principal (integra módulos)
async function doLogin() {
  const senha = document.getElementById('login-senha')?.value || '';
  const role = window.auth.getSelectedRole();
  
  // Verificar bloqueio por rate limiting
  const bloqueioMsg = window.auth.checkLock();
  if (bloqueioMsg) {
    showLoginError(bloqueioMsg);
    return;
  }
  
  if (!senha) {
    showLoginError('Digite sua senha.');
    return;
  }
  
  try {
    // Derivar hash da senha
    const salt = role === 'admin' ? 'lapa-admin-salt-2024' : 'lapa-membro-salt-2024';
    const hash = await window.auth.deriveKey(senha, salt);
    
    // Comparar com credencial armazenada
    const storedHash = window.auth.CREDENTIALS[role];
    
    if (window.auth._comparacaoSegura(hash, storedHash)) {
      window.auth.loginSuccess(role);
    } else {
      window.auth.registerFailure();
      showLoginError('Senha incorreta.');
    }
  } catch (error) {
    console.error('Erro no login:', error);
    showLoginError('Erro ao fazer login. Tente novamente.');
  }
}

// Carregamento de dados por página
async function loadPageData(pageId) {
  switch (pageId) {
    case 'home':
      await loadHomeData();
      break;
    case 'membros':
      await window.members.renderSecMembros();
      break;
    case 'eventos':
      await loadEventosData();
      break;
    case 'documentos':
      await loadDocumentosData();
      break;
    case 'relatorios':
      await loadRelatoriosData();
      break;
    case 'financeiro':
      await loadFinanceiroData();
      break;
  }
}

async function loadHomeData() {
  setLoadingMsg('home-stats', 'Carregando dashboard...');
  
  try {
    const data = await window.api.fetchWithCache({ action: 'getDashboard' });
    if (data) {
      renderHomeStats(data);
      renderHomeTimeline(data.eventos || []);
      renderHomeMembros(data.membros || []);
    }
  } catch (error) {
    console.error('Erro ao carregar dashboard:', error);
  }
}

function renderHomeStats(data) {
  const counters = [
    { el: document.getElementById('stat-membros'), value: data.totalMembros || 0 },
    { el: document.getElementById('stat-eventos'), value: data.totalEventos || 0 },
    { el: document.getElementById('stat-documentos'), value: data.totalDocumentos || 0 },
    { el: document.getElementById('stat-horas'), value: data.totalHoras || 0, suffix: 'h' }
  ];
  
  counters.forEach(({ el, value, suffix }) => {
    if (el) animateCounter(el, value, '', suffix || '');
  });
}

async function loadEventosData() {
  // Implementar carregamento de eventos
  console.log('Carregando eventos...');
}

async function loadDocumentosData() {
  // Implementar carregamento de documentos
  console.log('Carregando documentos...');
}

async function loadRelatoriosData() {
  // Implementar carregamento de relatórios
  console.log('Carregando relatórios...');
}

async function loadFinanceiroData() {
  // Implementar carregamento de financeiro
  console.log('Carregando financeiro...');
}

// Atualização de badges da sidebar
function _updateNavBadges({ eventos, ouvidoria, financeiro }) {
  // Implementar atualização de contadores na sidebar
}

// Atualizar timestamp de refresh
function _updateLastRefresh() {
  const el = document.getElementById('last-refresh');
  if (el) {
    el.textContent = new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  }
}

// Exportar para escopo global
window.loadPageData = loadPageData;
window.doLogin = doLogin;
