/**
 * ZapClone Backend
 * Servidor de mensagens em tempo real com suporte a:
 * - Mensagens de texto
 * - Áudio gravado (estilo WhatsApp)
 * - Fotos e vídeos
 * - Push-to-Talk (PTT estilo Nextel)
 */

require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

// ============================================
// CONFIGURAÇÃO INICIAL
// ============================================
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' },
  maxHttpBufferSize: 10 * 1024 * 1024 // 10MB para chunks de áudio PTT
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'troque-isso-em-producao-' + Date.now();

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// ============================================
// DIRETÓRIO DE DADOS PERSISTENTES
// ============================================
// No Railway, montamos um Volume em /data → tudo que vai pra lá sobrevive
// a deploys e restarts. Localmente, usamos a pasta do projeto.
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
console.log(`📁 Usando diretório de dados: ${DATA_DIR}`);

// Pasta para uploads (fotos, vídeos, áudios)
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// ============================================
// BANCO DE DADOS (SQLite no volume persistente)
// ============================================
const DB_PATH = path.join(DATA_DIR, 'zapclone.db');
console.log(`💾 Banco em: ${DB_PATH}`);
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    last_seen INTEGER,
    is_admin INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('text','audio','image','video','ptt')),
    content TEXT,
    media_url TEXT,
    duration_ms INTEGER,
    delivered INTEGER DEFAULT 0,
    read_at INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_conversation 
    ON messages(sender_id, receiver_id, created_at DESC);
`);

// Migração: adiciona is_admin se ainda não existe (pra bancos antigos)
try {
  db.prepare('SELECT is_admin FROM users LIMIT 1').get();
} catch {
  db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0');
}

// ============================================
// UPLOAD DE ARQUIVOS (multer)
// ============================================
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB máx
});

// ============================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ============================================
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token ausente' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}

function adminMiddleware(req, res, next) {
  // Reaproveita authMiddleware antes
  authMiddleware(req, res, () => {
    const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.user.id);
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Apenas administradores' });
    }
    next();
  });
}

// ============================================
// ROTAS REST - AUTH
// ============================================
app.post('/api/register', async (req, res) => {
  const { username, password, displayName } = req.body;
  if (!username || !password || !displayName) {
    return res.status(400).json({ error: 'Dados incompletos' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);

    // Primeiro usuário cadastrado vira admin automaticamente
    const userCount = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
    const isAdmin = userCount === 0 ? 1 : 0;

    const result = db.prepare(
      'INSERT INTO users (username, password_hash, display_name, is_admin) VALUES (?, ?, ?, ?)'
    ).run(username, hash, displayName, isAdmin);

    const token = jwt.sign({ id: result.lastInsertRowid, username, isAdmin }, JWT_SECRET);
    res.json({
      token,
      user: { id: result.lastInsertRowid, username, displayName, isAdmin: !!isAdmin }
    });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'Usuário já existe' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Credenciais inválidas' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, isAdmin: user.is_admin },
    JWT_SECRET
  );
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      isAdmin: !!user.is_admin
    }
  });
});

// ============================================
// ROTAS REST - CONTATOS E MENSAGENS
// ============================================
app.get('/api/contacts', authMiddleware, (req, res) => {
  const contacts = db.prepare(
    'SELECT id, username, display_name as displayName, avatar_url as avatarUrl, last_seen as lastSeen FROM users WHERE id != ?'
  ).all(req.user.id);
  res.json(contacts);
});

app.get('/api/messages/:contactId', authMiddleware, (req, res) => {
  const { contactId } = req.params;
  const messages = db.prepare(`
    SELECT * FROM messages 
    WHERE (sender_id = ? AND receiver_id = ?) 
       OR (sender_id = ? AND receiver_id = ?)
    ORDER BY created_at ASC
    LIMIT 200
  `).all(req.user.id, contactId, contactId, req.user.id);
  res.json(messages);
});

// Retorna a última mensagem + contagem de não lidas de cada contato
// (usado pra mostrar "última msg" e badge na lista de contatos)
app.get('/api/conversations', authMiddleware, (req, res) => {
  const userId = req.user.id;

  // Pega todos os usuários (potenciais conversas)
  const users = db.prepare('SELECT id, username, display_name as displayName FROM users WHERE id != ?').all(userId);

  const conversations = users.map(user => {
    // Última mensagem entre os dois
    const lastMsg = db.prepare(`
      SELECT * FROM messages
      WHERE (sender_id = ? AND receiver_id = ?)
         OR (sender_id = ? AND receiver_id = ?)
      ORDER BY created_at DESC
      LIMIT 1
    `).get(userId, user.id, user.id, userId);

    // Conta não lidas (mensagens recebidas sem read_at)
    const unread = db.prepare(`
      SELECT COUNT(*) as n FROM messages
      WHERE sender_id = ? AND receiver_id = ? AND read_at IS NULL
    `).get(user.id, userId).n;

    return {
      contactId: user.id,
      contactName: user.displayName,
      contactUsername: user.username,
      lastMessage: lastMsg,
      unread
    };
  });

  res.json(conversations);
});

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sem arquivo' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// ============================================
// CRASH REPORTS
// ============================================
const CRASH_DIR = path.join(DATA_DIR, 'crash_reports');
if (!fs.existsSync(CRASH_DIR)) fs.mkdirSync(CRASH_DIR, { recursive: true });

app.post('/api/crash', (req, res) => {
  const { report } = req.body || {};
  if (!report) return res.status(400).json({ error: 'Sem report' });
  const filename = `crash_${Date.now()}.txt`;
  fs.writeFileSync(path.join(CRASH_DIR, filename), report);
  console.error('🐛 Crash report recebido:', filename);
  res.json({ ok: true, saved: filename });
});

// Lista os reports para você visualizar
app.get('/api/crash', authMiddleware, (req, res) => {
  const files = fs.readdirSync(CRASH_DIR).sort().reverse();
  const reports = files.slice(0, 50).map(f => ({
    filename: f,
    content: fs.readFileSync(path.join(CRASH_DIR, f), 'utf-8')
  }));
  res.json(reports);
});

// ============================================
// ADMIN - GESTÃO DE USUÁRIOS
// ============================================

// Verifica se o usuário logado é admin
app.get('/api/admin/me', adminMiddleware, (req, res) => {
  res.json({ isAdmin: true });
});

// Lista todos os usuários
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, display_name as displayName, is_admin as isAdmin, 
           last_seen as lastSeen, created_at as createdAt
    FROM users
    ORDER BY id ASC
  `).all();
  res.json(users);
});

// Reseta a senha de um usuário
app.post('/api/admin/users/:id/reset-password', adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'Senha precisa ter no mínimo 4 caracteres' });
  }
  const user = db.prepare('SELECT id, username FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, id);

  console.log(`🔑 Admin resetou senha de ${user.username}`);
  res.json({ ok: true, username: user.username });
});

// Promove/rebaixa admin
app.post('/api/admin/users/:id/toggle-admin', adminMiddleware, (req, res) => {
  const { id } = req.params;
  const user = db.prepare('SELECT id, is_admin FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

  // Impede que o último admin se rebaixe
  if (user.is_admin) {
    const adminCount = db.prepare('SELECT COUNT(*) as n FROM users WHERE is_admin = 1').get().n;
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Não pode rebaixar o último admin' });
    }
  }

  const newValue = user.is_admin ? 0 : 1;
  db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(newValue, id);
  res.json({ ok: true, isAdmin: !!newValue });
});

// Apaga um usuário (e suas mensagens)
app.delete('/api/admin/users/:id', adminMiddleware, (req, res) => {
  const { id } = req.params;
  if (parseInt(id) === req.user.id) {
    return res.status(400).json({ error: 'Não pode apagar a si mesmo' });
  }
  db.prepare('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?').run(id, id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ============================================
// PAGINA WEB ADMIN
// ============================================
app.get('/admin', (req, res) => {
  res.send(ADMIN_HTML);
});

// ============================================
// SOCKET.IO - TEMPO REAL
// ============================================
const onlineUsers = new Map(); // userId -> socketId

// Autenticação no socket
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Sem token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Token inválido'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  onlineUsers.set(userId, socket.id);
  console.log(`✓ ${socket.user.username} conectou`);

  // Avisa todos que esse usuário ficou online
  socket.broadcast.emit('user:online', { userId });

  // ----------------------------------------
  // ENVIA MENSAGENS PENDENTES (recebidas enquanto estava offline)
  // ----------------------------------------
  try {
    const pending = db.prepare(`
      SELECT * FROM messages
      WHERE receiver_id = ? AND delivered = 0
      ORDER BY created_at ASC
    `).all(userId);

    if (pending.length > 0) {
      console.log(`📬 Entregando ${pending.length} mensagens pendentes para ${socket.user.username}`);
      for (const msg of pending) {
        socket.emit('message:new', msg);
      }
      // Marca todas como entregues
      db.prepare('UPDATE messages SET delivered = 1 WHERE receiver_id = ? AND delivered = 0')
        .run(userId);
    }
  } catch (e) {
    console.error('Erro ao entregar pendentes:', e);
  }

  // ----------------------------------------
  // MENSAGEM (texto, áudio gravado, imagem, vídeo)
  // ----------------------------------------
  // Constante: ID especial pra broadcast (grupo "Todos")
  // Frontend envia receiverId = -1 quando quer mandar pra todos
  const BROADCAST_ID = -1;

  socket.on('message:send', (data, ack) => {
    const { receiverId, type, content, mediaUrl, durationMs } = data;

    if (receiverId === BROADCAST_ID) {
      // Broadcast: salva uma mensagem por usuário cadastrado (exceto o remetente)
      // Quem está offline recebe quando abrir o app (carrega do histórico)
      const allUsers = db.prepare('SELECT id FROM users WHERE id != ?').all(userId);
      const recipients = [];

      for (const { id: uid } of allUsers) {
        const result = db.prepare(`
          INSERT INTO messages (sender_id, receiver_id, type, content, media_url, duration_ms, delivered)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          userId, uid, type,
          content || null, mediaUrl || null, durationMs || null,
          onlineUsers.has(uid) ? 1 : 0
        );

        const msg = {
          id: result.lastInsertRowid,
          sender_id: userId,
          receiver_id: uid,
          type, content, media_url: mediaUrl,
          duration_ms: durationMs,
          created_at: Math.floor(Date.now() / 1000),
          is_broadcast: true,
          delivered: onlineUsers.has(uid) ? 1 : 0
        };

        // Entrega na hora se estiver online
        const sid = onlineUsers.get(uid);
        if (sid) {
          io.to(sid).emit('message:new', msg);
        }
        recipients.push(uid);
      }
      if (ack) ack({ ok: true, broadcast: true, recipients: recipients.length });
      return;
    }

    const result = db.prepare(`
      INSERT INTO messages (sender_id, receiver_id, type, content, media_url, duration_ms)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(userId, receiverId, type, content || null, mediaUrl || null, durationMs || null);

    const message = {
      id: result.lastInsertRowid,
      sender_id: userId,
      receiver_id: receiverId,
      type, content, media_url: mediaUrl,
      duration_ms: durationMs,
      created_at: Math.floor(Date.now() / 1000)
    };

    // Entrega ao destinatário se online
    const receiverSocket = onlineUsers.get(receiverId);
    if (receiverSocket) {
      io.to(receiverSocket).emit('message:new', message);
      db.prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(message.id);
      message.delivered = 1;
    }
    if (ack) ack({ ok: true, message });
  });

  // ----------------------------------------
  // PUSH-TO-TALK (PTT estilo Nextel)
  // Stream de áudio em tempo real via chunks
  // ----------------------------------------

  // Aviso de início (alerta sonoro tipo "bip" do Nextel no destinatário)
  socket.on('ptt:start', ({ receiverId }) => {
    if (receiverId === BROADCAST_ID) {
      for (const [uid, sid] of onlineUsers) {
        if (uid === userId) continue;
        io.to(sid).emit('ptt:incoming', {
          fromUserId: userId,
          fromUsername: socket.user.username,
          isBroadcast: true
        });
      }
      return;
    }
    const target = onlineUsers.get(receiverId);
    if (target) {
      io.to(target).emit('ptt:incoming', {
        fromUserId: userId,
        fromUsername: socket.user.username
      });
    }
  });

  // Chunks de áudio sendo transmitidos em tempo real
  socket.on('ptt:chunk', ({ receiverId, chunk, seq }) => {
    if (receiverId === BROADCAST_ID) {
      for (const [uid, sid] of onlineUsers) {
        if (uid === userId) continue;
        io.to(sid).emit('ptt:chunk', { fromUserId: userId, chunk, seq });
      }
      return;
    }
    const target = onlineUsers.get(receiverId);
    if (target) {
      io.to(target).emit('ptt:chunk', { fromUserId: userId, chunk, seq });
    }
  });

  // Fim da transmissão PTT
  socket.on('ptt:end', ({ receiverId, totalDurationMs, fullAudioUrl }) => {
    if (receiverId === BROADCAST_ID) {
      for (const [uid, sid] of onlineUsers) {
        if (uid === userId) continue;
        io.to(sid).emit('ptt:end', { fromUserId: userId, totalDurationMs });
      }
      return;
    }
    const target = onlineUsers.get(receiverId);
    if (target) {
      io.to(target).emit('ptt:end', { fromUserId: userId, totalDurationMs });
    }
    if (fullAudioUrl) {
      db.prepare(`
        INSERT INTO messages (sender_id, receiver_id, type, media_url, duration_ms)
        VALUES (?, ?, 'ptt', ?, ?)
      `).run(userId, receiverId, fullAudioUrl, totalDurationMs);
    }
  });

  // ----------------------------------------
  // ALERTA (cutucada estilo Nextel)
  // Toca um chirp insistente no celular do destinatário
  // ----------------------------------------
  socket.on('alert', ({ receiverId }) => {
    const fromInfo = {
      fromUserId: userId,
      fromUsername: socket.user.username
    };
    if (receiverId === BROADCAST_ID) {
      for (const [uid, sid] of onlineUsers) {
        if (uid === userId) continue;
        io.to(sid).emit('alert:incoming', fromInfo);
      }
    } else {
      const target = onlineUsers.get(receiverId);
      if (target) io.to(target).emit('alert:incoming', fromInfo);
    }
  });

  // ----------------------------------------
  // STATUS (digitando, lido)
  // ----------------------------------------
  socket.on('typing', ({ receiverId, isTyping }) => {
    const target = onlineUsers.get(receiverId);
    if (target) io.to(target).emit('typing', { fromUserId: userId, isTyping });
  });

  socket.on('message:read', ({ messageIds }) => {
    const now = Math.floor(Date.now() / 1000);
    const stmt = db.prepare('UPDATE messages SET read_at = ? WHERE id = ? AND receiver_id = ?');
    messageIds.forEach(id => stmt.run(now, id, userId));
  });

  // ----------------------------------------
  // DESCONEXÃO
  // ----------------------------------------
  socket.on('disconnect', () => {
    onlineUsers.delete(userId);
    db.prepare('UPDATE users SET last_seen = ? WHERE id = ?')
      .run(Math.floor(Date.now() / 1000), userId);
    socket.broadcast.emit('user:offline', { userId });
    console.log(`✗ ${socket.user.username} desconectou`);
  });
});

// ============================================
// HEALTH CHECK / ROOT
// ============================================
app.get('/', (req, res) => {
  res.json({
    name: 'Fodinha Private Backend',
    status: 'running',
    health: '/health'
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    onlineUsers: onlineUsers.size,
    uptime: process.uptime()
  });
});

// Captura erros não tratados para o Railway logar (em vez de morrer silencioso)
process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('💥 Unhandled Rejection:', reason);
});

// Bind em 0.0.0.0 para o Railway conseguir rotear o tráfego
// ============================================
// PÁGINA WEB DE ADMIN (HTML standalone)
// ============================================
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin · Fodinha Private</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
  body { background: #0b141a; color: #e9edef; min-height: 100vh; padding: 20px; }
  .container { max-width: 720px; margin: 0 auto; }
  h1 { color: #25d366; margin-bottom: 20px; }
  .card { background: #1f2c34; padding: 20px; border-radius: 12px; margin-bottom: 16px; }
  input, button {
    width: 100%; padding: 12px; border-radius: 6px; border: none;
    font-size: 14px; margin-bottom: 8px;
  }
  input { background: #2a3942; color: #e9edef; }
  button { background: #25d366; color: #000; cursor: pointer; font-weight: bold; }
  button:hover { background: #1ebd5a; }
  button.danger { background: #ef4444; color: #fff; }
  button.secondary { background: #6b7280; color: #fff; }
  .user-row {
    display: flex; align-items: center; padding: 12px; gap: 12px;
    border-bottom: 1px solid #2a3942;
  }
  .user-row:last-child { border-bottom: none; }
  .user-info { flex: 1; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; background: #25d366; color: #000;
  }
  .actions { display: flex; gap: 6px; }
  .actions button { width: auto; padding: 6px 12px; font-size: 12px; margin: 0; }
  .toast {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    background: #25d366; color: #000; padding: 12px 24px; border-radius: 6px;
    font-weight: bold; opacity: 0; transition: opacity 0.3s;
  }
  .toast.show { opacity: 1; }
  .toast.error { background: #ef4444; color: #fff; }
  .hidden { display: none; }
  small { color: #8696a0; }
</style>
</head>
<body>
<div class="container">
  <h1>🔐 Admin · Fodinha Private</h1>

  <div id="loginCard" class="card">
    <h3 style="margin-bottom: 12px;">Login de Administrador</h3>
    <input id="loginUser" placeholder="Usuário admin" autocomplete="username">
    <input id="loginPass" type="password" placeholder="Senha" autocomplete="current-password">
    <button onclick="login()">Entrar</button>
    <p id="loginErr" style="color:#ef4444;margin-top:8px;"></p>
  </div>

  <div id="panel" class="hidden">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <h3>Usuários cadastrados</h3>
        <button class="secondary" style="width:auto;padding:6px 12px;" onclick="logout()">Sair</button>
      </div>
      <div id="usersList" style="margin-top: 16px;"></div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
</div>

<script>
let token = localStorage.getItem('admin_token');
const $ = (id) => document.getElementById(id);

function toast(msg, isError = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isError ? ' error' : '');
  setTimeout(() => t.className = 'toast', 3000);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: 'Bearer ' + token } : {}),
      ...(opts.headers || {})
    }
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Erro' }));
    throw new Error(err.error || 'Erro ' + res.status);
  }
  return res.json();
}

async function login() {
  $('loginErr').textContent = '';
  try {
    const resp = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({
        username: $('loginUser').value,
        password: $('loginPass').value
      })
    });
    if (!resp.user.isAdmin) {
      $('loginErr').textContent = 'Esse usuário não é administrador.';
      return;
    }
    token = resp.token;
    localStorage.setItem('admin_token', token);
    showPanel();
  } catch (e) {
    $('loginErr').textContent = e.message;
  }
}

function logout() {
  token = null;
  localStorage.removeItem('admin_token');
  $('panel').classList.add('hidden');
  $('loginCard').classList.remove('hidden');
}

async function showPanel() {
  try {
    await api('/api/admin/me');
    $('loginCard').classList.add('hidden');
    $('panel').classList.remove('hidden');
    await loadUsers();
  } catch {
    logout();
  }
}

async function loadUsers() {
  const users = await api('/api/admin/users');
  const list = $('usersList');
  list.innerHTML = users.map(u => \`
    <div class="user-row">
      <div class="user-info">
        <strong>\${u.displayName}</strong>
        \${u.isAdmin ? '<span class="badge">admin</span>' : ''}
        <br><small>@\${u.username} · id \${u.id}</small>
      </div>
      <div class="actions">
        <button onclick="resetPwd(\${u.id}, '\${u.username}')">🔑 Resetar</button>
        <button class="secondary" onclick="toggleAdmin(\${u.id})">\${u.isAdmin ? '↓' : '↑'} Admin</button>
        <button class="danger" onclick="deleteUser(\${u.id}, '\${u.username}')">🗑</button>
      </div>
    </div>
  \`).join('');
}

async function resetPwd(id, username) {
  const newPassword = prompt('Nova senha para ' + username + ':');
  if (!newPassword) return;
  if (newPassword.length < 4) return toast('Senha curta demais', true);
  try {
    await api('/api/admin/users/' + id + '/reset-password', {
      method: 'POST',
      body: JSON.stringify({ newPassword })
    });
    toast('Senha de ' + username + ' resetada!');
  } catch (e) {
    toast(e.message, true);
  }
}

async function toggleAdmin(id) {
  try {
    await api('/api/admin/users/' + id + '/toggle-admin', { method: 'POST' });
    await loadUsers();
    toast('Permissão atualizada');
  } catch (e) {
    toast(e.message, true);
  }
}

async function deleteUser(id, username) {
  if (!confirm('Apagar ' + username + ' e todas as mensagens? Não tem volta.')) return;
  try {
    await api('/api/admin/users/' + id, { method: 'DELETE' });
    await loadUsers();
    toast('Usuário apagado');
  } catch (e) {
    toast(e.message, true);
  }
}

// Tenta auto-login se já tem token
if (token) showPanel();
</script>
</body>
</html>`;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════╗
║  Fodinha Private Backend rodando       ║
║  Porta: ${PORT}                              ║
║  Pronto pra receber conexões!          ║
╚════════════════════════════════════════╝
  `);
});
