// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — Módulo de Utilitários
// ═══════════════════════════════════════════════════════════════

'use strict';

// Escapar HTML
function esc(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Formatar data
function formatDate(val) {
  if (!val) return '';
  const date = new Date(val);
  return date.toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric'
  });
}

// Formatar data com hora
function formatDateTime(val) {
  if (!val) return '';
  const date = new Date(val);
  return date.toLocaleString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

// Cor do setor
function setorCor(setor) {
  const cores = {
    'Administrativo': '#38bdf8',
    'Ensino': '#22c55e',
    'Pesquisa': '#f59e0b',
    'Extensão': '#f97316',
    'Evento': '#ef4444',
    'Comunicação': '#a855f7',
    'Financeiro': '#14b8a6'
  };
  return cores[setor] || '#94a3b8';
}

// Badge de status
function statusBadge(s) {
  const styles = {
    'Ativo': 'badge-success',
    'Inativo': 'badge-secondary',
    'Pendente': 'badge-warning',
    'Aprovado': 'badge-success',
    'Rejeitado': 'badge-danger',
    'Em andamento': 'badge-info',
    'Concluído': 'badge-success'
  };
  const style = styles[s] || 'badge-secondary';
  return `<span class="badge ${style}">${esc(s)}</span>`;
}

// Loading message
function setLoadingMsg(containerId, msg = 'Carregando…') {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = `
      <div class="loading-state">
        <i class="fas fa-circle-notch fa-spin"></i>
        <p>${esc(msg)}</p>
      </div>
    `;
  }
}

// Empty state message
function setEmptyMsg(containerId, icon, msg) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="${icon}"></i>
        <p>${esc(msg)}</p>
      </div>
    `;
  }
}

// Debounce para busca
let _searchDebounceTimer = null;

function debounce(fn, delay) {
  return function(...args) {
    clearTimeout(_searchDebounceTimer);
    _searchDebounceTimer = setTimeout(() => fn.apply(this, args), delay);
  };
}

// Validação de formulário
function setupInlineValidation() {
  document.querySelectorAll('[data-validate]').forEach(el => {
    el.addEventListener('blur', () => _validateField(el));
    el.addEventListener('input', () => {
      if (el.classList.contains('invalid')) {
        _validateField(el);
      }
    });
  });
}

function _validateField(el) {
  const rules = el.dataset.validate?.split('|') || [];
  const value = el.value.trim();
  let error = '';
  
  for (const rule of rules) {
    if (rule === 'required' && !value) {
      error = 'Campo obrigatório';
      break;
    }
    if (rule === 'email' && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      error = 'E-mail inválido';
      break;
    }
    if (rule === 'minlength:3' && value.length < 3) {
      error = 'Mínimo 3 caracteres';
      break;
    }
    if (rule.startsWith('min:') && value.length < parseInt(rule.split(':')[1])) {
      error = `Mínimo ${rule.split(':')[1]} caracteres`;
      break;
    }
  }
  
  const errorEl = el.parentElement?.querySelector('.error-msg');
  if (errorEl) errorEl.textContent = error;
  
  el.classList.toggle('invalid', !!error);
  return !error;
}

function _validateModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return false;
  
  let valid = true;
  modal.querySelectorAll('[data-validate]').forEach(el => {
    if (!_validateField(el)) valid = false;
  });
  
  return valid;
}

// Exportar funções públicas
window.utils = {
  esc,
  formatDate,
  formatDateTime,
  setorCor,
  statusBadge,
  setLoadingMsg,
  setEmptyMsg,
  debounce,
  setupInlineValidation,
  validateField: _validateField,
  validateModal: _validateModal
};
