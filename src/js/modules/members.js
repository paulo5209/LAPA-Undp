// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — Módulo de Gestão de Membros
// ═══════════════════════════════════════════════════════════════

'use strict';

let _membrosData   = [];   // dataset completo filtrado
let _membrosSortKey = null;
let _membrosSortDir = 1;   // 1 = asc, -1 = desc
let _membrosPagina  = 1;
const _membrosPorPagina = 15;

function sortMembros(key) {
  if (_membrosSortKey === key) {
    _membrosSortDir *= -1;
  } else {
    _membrosSortKey = key;
    _membrosSortDir = 1;
  }
  _renderMembrosTable();
}

function _getMembrosFiltrados() {
  const setorFilter = document.getElementById('filtro-setor')?.value || 'todos';
  const statusFilter = document.getElementById('filtro-status')?.value || 'todos';
  const busca = document.getElementById('busca-membros')?.value.toLowerCase() || '';
  
  return _membrosData.filter(m => {
    const matchSetor = setorFilter === 'todos' || m.setor === setorFilter;
    const matchStatus = statusFilter === 'todos' || m.status === statusFilter;
    const matchBusca = !busca || 
      m.nome.toLowerCase().includes(busca) || 
      m.email.toLowerCase().includes(busca) ||
      (m.matricula && m.matricula.includes(busca));
    return matchSetor && matchStatus && matchBusca;
  });
}

function _renderMembrosTable() {
  const container = document.getElementById('tabela-membros');
  if (!container) return;
  
  const filtrados = _getMembrosFiltrados();
  const total = filtrados.length;
  const inicio = (_membrosPagina - 1) * _membrosPorPagina;
  const fim = inicio + _membrosPorPagina;
  const paginaAtual = filtrados.slice(inicio, fim);
  
  if (paginaAtual.length === 0) {
    setEmptyMsg('tabela-membros', 'fas fa-users-slash', 'Nenhum membro encontrado.');
    return;
  }
  
  let html = `
    <table class="data-table">
      <thead>
        <tr>
          <th onclick="sortMembros('nome')">Nome ${_getSortIcon('nome')}</th>
          <th>Email</th>
          <th onclick="sortMembros('setor')">Setor ${_getSortIcon('setor')}</th>
          <th onclick="sortMembros('status')">Status ${_getSortIcon('status')}</th>
          <th>Ações</th>
        </tr>
      </thead>
      <tbody>
  `;
  
  paginaAtual.forEach(m => {
    html += `
      <tr>
        <td><strong>${esc(m.nome)}</strong></td>
        <td>${esc(m.email)}</td>
        <td><span class="badge" style="background:${setorCor(m.setor)}">${esc(m.setor)}</span></td>
        <td>${statusBadge(m.status)}</td>
        <td class="actions-cell">
          <button class="btn-icon" onclick="editMembro('${m.id}')" title="Editar">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn-icon btn-danger" onclick="deleteMembro('${m.id}')" title="Excluir">
            <i class="fas fa-trash"></i>
          </button>
        </td>
      </tr>
    `;
  });
  
  html += '</tbody></table>';
  
  // Paginação
  const totalPages = Math.ceil(total / _membrosPorPagina);
  if (totalPages > 1) {
    html += `
      <div class="pagination">
        <button ${_membrosPagina === 1 ? 'disabled' : ''} onclick="_membrosPagina-- ; _renderMembrosTable()">
          <i class="fas fa-chevron-left"></i>
        </button>
        <span>Página ${_membrosPagina} de ${totalPages}</span>
        <button ${_membrosPagina === totalPages ? 'disabled' : ''} onclick="_membrosPagina++ ; _renderMembrosTable()">
          <i class="fas fa-chevron-right"></i>
        </button>
      </div>
    `;
  }
  
  container.innerHTML = html;
}

function _getSortIcon(key) {
  if (_membrosSortKey !== key) return '';
  return _membrosSortDir === 1 ? '<i class="fas fa-sort-up"></i>' : '<i class="fas fa-sort-down"></i>';
}

function filterMembros() {
  _membrosPagina = 1;
  _renderMembrosTable();
}

async function renderSecMembros(data) {
  setLoadingMsg('tabela-membros', 'Carregando membros...');
  
  try {
    _membrosData = data || await window.api.fetchWithCache({ action: 'getMembros' });
    _renderMembrosTable();
  } catch (error) {
    setEmptyMsg('tabela-membros', 'fas fa-exclamation-triangle', 'Erro ao carregar membros.');
  }
}

function editMembro(id) {
  const membro = _membrosData.find(m => m.id === id);
  if (!membro) return;
  
  document.getElementById('edit-membro-id').value = membro.id;
  document.getElementById('edit-membro-nome').value = membro.nome;
  document.getElementById('edit-membro-email').value = membro.email;
  document.getElementById('edit-membro-setor').value = membro.setor;
  document.getElementById('edit-membro-status').value = membro.status;
  
  openModal('modal-edit-membro');
}

async function saveMembro() {
  if (!_validateModal('modal-edit-membro')) return;
  
  const payload = {
    id: document.getElementById('edit-membro-id').value,
    nome: document.getElementById('edit-membro-nome').value.trim(),
    email: document.getElementById('edit-membro-email').value.trim(),
    setor: document.getElementById('edit-membro-setor').value,
    status: document.getElementById('edit-membro-status').value
  };
  
  const result = await window.api.postData('saveMembro', payload);
  if (result?.success) {
    showToast('Membro salvo com sucesso!', 'success');
    closeModal('modal-edit-membro');
    renderSecMembros();
  }
}

async function deleteMembro(id) {
  customConfirm({
    title: 'Excluir membro',
    message: 'Tem certeza que deseja excluir este membro? Esta ação não pode ser desfeita.',
    confirmLabel: 'Excluir',
    cancelLabel: 'Cancelar',
    onConfirm: async () => {
      const result = await window.api.postData('deleteMembro', { id });
      if (result?.success) {
        showToast('Membro excluído com sucesso!', 'success');
        renderSecMembros();
      }
    }
  });
}

// Exportar funções públicas
window.members = {
  sortMembros,
  filterMembros,
  renderSecMembros,
  editMembro,
  saveMembro,
  deleteMembro,
  getData: () => _membrosData,
  getFiltered: _getMembrosFiltrados
};
