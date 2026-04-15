// ═══════════════════════════════════════════════════════════════
//  LAPA Dashboard v1.0 — Módulo de API e Cache
// ═══════════════════════════════════════════════════════════════

'use strict';

// ─── Cache de respostas (TTL: 30s) ────────────────────────
const _apiCache = {};
const _apiCacheTTL = 30000;

function _cacheKey(params) { 
  return JSON.stringify(params); 
}

async function fetchWithCache(params, forceRefresh = false) {
  const key = _cacheKey(params);
  const now = Date.now();
  
  if (!forceRefresh && _apiCache[key] && (now - _apiCache[key].timestamp) < _apiCacheTTL) {
    return _apiCache[key].data;
  }
  
  try {
    const url = new URL(window.auth.API_URL);
    url.search = new URLSearchParams(params).toString();
    
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    _apiCache[key] = { data, timestamp: now };
    return data;
  } catch (error) {
    console.error('Erro na requisição:', error);
    showToast('Erro ao carregar dados.', 'error');
    return null;
  }
}

async function postData(action, payload) {
  try {
    const response = await fetch(window.auth.API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, ...payload })
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    return await response.json();
  } catch (error) {
    console.error('Erro ao enviar dados:', error);
    showToast('Erro ao salvar dados.', 'error');
    return null;
  }
}

// Exportar funções públicas
window.api = {
  fetchWithCache,
  postData,
  getCache: () => _apiCache,
  clearCache: () => { Object.keys(_apiCache).forEach(k => delete _apiCache[k]); }
};

// Alias para compatibilidade com módulos existentes
window.fetchWithCache = fetchWithCache;
window.postData = postData;
