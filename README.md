# LAPA — Liga de Primeiros Auxílios

Dashboard administrativo moderno e modular para gestão da LAPA.

## 📁 Estrutura do Projeto

```
/workspace
├── index.html              # Arquivo HTML principal (estrutura + conteúdo)
├── src/
│   ├── css/
│   │   └── styles.css      # Todos os estilos CSS
│   └── js/
│       ├── app.js          # Inicialização e orquestração
│       ├── main.js         # Lógica legado (para migração futura)
│       └── modules/
│           ├── auth.js     # Autenticação e segurança
│           ├── api.js      # Comunicação com Google Apps Script
│           ├── ui.js       # Interface e navegação
│           ├── utils.js    # Utilitários gerais
│           └── members.js  # Gestão de membros
└── assets/                 # Recursos estáticos (imagens, ícones)
```

## 🔐 Segurança

- **Autenticação:** PBKDF2-HMAC-SHA256 com 200.000 iterações
- **Rate Limiting:** Progressivo (30s → 2min → 5min → 15min)
- **Comparação em tempo constante:** Previne timing attacks
- **HTTPS obrigatório:** Utiliza Web Crypto API

## 🚀 Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| Dashboard | Stats em tempo real, timeline, membros ativos |
| Gestão de Membros | CRUD completo, filtros, busca, setores |
| Eventos | Calendário, kanban, upload de arquivos |
| Documentos | Preview, edição, armazenamento |
| Relatórios | Gráficos por setor, status, período |
| Financeiro | Controle de entradas/saídas |

## 🛠️ Módulos JavaScript

### `auth.js`
Gerencia autenticação, sessão e segurança:
- `doLogin()` / `doLogout()`
- `deriveKey(senha, salt)` - Derivação PBKDF2
- `checkLock()` - Verifica rate limiting
- `loginSuccess(role)` - Sucesso no login

### `api.js`
Comunicação com backend (Google Apps Script):
- `fetchWithCache(params, forceRefresh)` - GET com cache
- `postData(action, payload)` - POST para API

### `ui.js`
Interface e navegação SPA:
- `showPage(id)` - Navegação entre páginas
- `openModal(id)` / `closeModal(id)` - Gestão de modais
- `showToast(message, type)` - Notificações
- `toggleTheme()` - Modo claro/escuro

### `utils.js`
Utilitários gerais:
- `esc(str)` - Escapar HTML
- `formatDate(val)` - Formatar data
- `setorCor(setor)` - Cor por setor
- `statusBadge(s)` - Badge de status
- `setupInlineValidation()` - Validação de formulários

### `members.js`
Gestão de membros:
- `renderSecMembros(data)` - Renderizar tabela
- `editMembro(id)` - Editar membro
- `saveMembro()` - Salvar membro
- `deleteMembro(id)` - Excluir membro

## 📦 Como Usar

### Desenvolvimento

1. Clone o repositório
2. Abra `index.html` em um servidor local (recomendado Live Server)
3. Edite os módulos em `src/js/modules/`

### Produção

1. Faça deploy em um servidor estático (Vercel, Netlify, GitHub Pages)
2. Configure a URL do Google Apps Script no módulo `auth.js`
3. Atualize as credenciais hash no módulo `auth.js`

## 🔧 Personalização

### Trocar Senhas

1. Abra o console do navegador após login
2. Execute:
```javascript
await window.auth.generateHash('nova-senha', 'admin')
// ou 'membro'
```
3. Copie o resultado e atualize em `src/js/modules/auth.js`

### Adicionar Novo Módulo

1. Crie `src/js/modules/nome-modulo.js`
2. Exporte funções públicas:
```javascript
window.nomeModulo = {
  funcaoPublica1,
  funcaoPublica2
};
```
3. Importe em `index.html`:
```html
<script src="src/js/modules/nome-modulo.js"></script>
```

## 📝 Notas

- O arquivo `main.js` contém lógica legado que será migrada gradualmente
- A URL da API é ofuscada via concatenação em runtime
- Todo o tráfego deve ser HTTPS para funcionar com Web Crypto API

## 📄 Licença

Projeto interno da LAPA - Uso restrito
