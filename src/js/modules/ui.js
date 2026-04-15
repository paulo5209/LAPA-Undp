// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — Módulo de UI e Navegação
// ═══════════════════════════════════════════════════════════════

'use strict';

// Mapeamento de páginas
const pageMap = {
  home: 'Dashboard',
  membros: 'Membros',
  eventos: 'Eventos',
  documentos: 'Documentos',
  relatorios: 'Relatórios',
  ouvidoria: 'Ouvidoria',
  financeiro: 'Financeiro',
  extensao: 'Extensão',
  ensino: 'Ensino',
  pesquisa: 'Pesquisa',
  configuracoes: 'Configurações'
};

function showPage(id) {
  // Esconde todas as seções
  document.querySelectorAll('.page-section').forEach(section => {
    section.classList.remove('active');
  });
  
  // Remove active dos nav items
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.remove('active');
  });
  
  // Mostra a seção desejada
  const targetSection = document.getElementById(`sec-${id}`);
  if (targetSection) {
    targetSection.classList.add('active');
  }
  
  // Marca nav item como ativo
  const navItem = document.querySelector(`.nav-item[data-page="${id}"]`);
  if (navItem) {
    navItem.classList.add('active');
  }
  
  // Fecha sidebar no mobile
  if (window.innerWidth <= 768) {
    closeMobileSidebar();
  }
  
  // Carrega dados específicos da página
  loadPageData(id);
}

function switchTab(el, panelId) {
  const parent = el.closest('.tabs-container');
  if (!parent) return;
  
  parent.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  parent.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
  
  el.classList.add('active');
  document.getElementById(panelId)?.classList.add('active');
}

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('open');
    document.body.style.overflow = '';
    clearModalForm(modalId);
  }
}

function clearModalForm(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  
  modal.querySelectorAll('input:not([type="hidden"]), textarea, select').forEach(field => {
    if (field.type !== 'checkbox' && field.type !== 'radio') {
      field.value = '';
    } else {
      field.checked = false;
    }
  });
  
  modal.querySelectorAll('.error-msg').forEach(err => err.textContent = '');
  modal.querySelectorAll('.invalid').forEach(el => el.classList.remove('invalid'));
}

// Tema claro/escuro
let lightMode = localStorage.getItem('lapa-theme') === 'light';

function toggleTheme() {
  lightMode = !lightMode;
  localStorage.setItem('lapa-theme', lightMode ? 'light' : 'dark');
  applyTheme();
}

function applyTheme() {
  document.body.classList.toggle('light-mode', lightMode);
  const icon = document.getElementById('theme-toggle-icon');
  if (icon) {
    icon.className = lightMode ? 'fas fa-moon' : 'fas fa-sun';
  }
}

// Toast notifications
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container') || createToastContainer();
  
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function createToastContainer() {
  const container = document.createElement('div');
  container.id = 'toast-container';
  container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:10px;';
  document.body.appendChild(container);
  return container;
}

// Animação de contadores
function animateCounter(el, target, prefix = '', suffix = '') {
  if (!el) return;
  
  const duration = 1500;
  const start = 0;
  const startTime = performance.now();
  
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Ease-out quart
    const ease = 1 - Math.pow(1 - progress, 4);
    const current = Math.floor(start + (target - start) * ease);
    
    el.textContent = prefix + current.toLocaleString('pt-BR') + suffix;
    
    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }
  
  requestAnimationFrame(update);
}

// Modal de confirmação customizado
let _confirmCallback = null;

function customConfirm({ title, message, confirmLabel = 'Confirmar', cancelLabel = 'Cancelar', onConfirm }) {
  _confirmCallback = onConfirm;
  
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-message').textContent = message;
  document.getElementById('confirm-btn').textContent = confirmLabel;
  document.getElementById('cancel-btn').textContent = cancelLabel;
  
  openModal('modal-confirm');
}

// Mobile sidebar
function toggleMobileSidebar() {
  document.body.classList.toggle('sidebar-open');
  const overlay = document.getElementById('sidebar-overlay');
  if (overlay) overlay.style.display = 'block';
}

function closeMobileSidebar() {
  document.body.classList.remove('sidebar-open');
  const overlay = document.getElementById('sidebar-overlay');
  if (overlay) overlay.style.display = 'none';
}

// Exportar funções públicas
window.ui = {
  pageMap,
  showPage,
  switchTab,
  openModal,
  closeModal,
  clearModalForm,
  toggleTheme,
  applyTheme,
  showToast,
  animateCounter,
  customConfirm,
  toggleMobileSidebar,
  closeMobileSidebar,
  isLightMode: () => lightMode
};
