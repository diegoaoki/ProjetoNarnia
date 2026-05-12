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

// Pasta para uploads (fotos, vídeos, áudios)
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// ============================================
// BANCO DE DADOS (SQLite)
// ============================================
const db = new Database(path.join(__dirname, 'zapclone.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    last_seen INTEGER,
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
    const result = db.prepare(
      'INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)'
    ).run(username, hash, displayName);

    const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET);
    res.json({ token, user: { id: result.lastInsertRowid, username, displayName } });
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
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
  res.json({
    token,
    user: { id: user.id, username: user.username, displayName: user.display_name }
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

app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sem arquivo' });
  res.json({ url: `/uploads/${req.file.filename}` });
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
  // MENSAGEM (texto, áudio gravado, imagem, vídeo)
  // ----------------------------------------
  socket.on('message:send', (data, ack) => {
    const { receiverId, type, content, mediaUrl, durationMs } = data;
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
    const target = onlineUsers.get(receiverId);
    if (target) {
      io.to(target).emit('ptt:chunk', {
        fromUserId: userId,
        chunk,  // buffer de áudio (base64 ou binário)
        seq
      });
    }
  });

  // Fim da transmissão PTT
  socket.on('ptt:end', ({ receiverId, totalDurationMs, fullAudioUrl }) => {
    const target = onlineUsers.get(receiverId);
    if (target) {
      io.to(target).emit('ptt:end', { fromUserId: userId, totalDurationMs });
    }
    // Salva no histórico como mensagem PTT
    if (fullAudioUrl) {
      db.prepare(`
        INSERT INTO messages (sender_id, receiver_id, type, media_url, duration_ms)
        VALUES (?, ?, 'ptt', ?, ?)
      `).run(userId, receiverId, fullAudioUrl, totalDurationMs);
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
server.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════╗
║  Fodinha Private Backend rodando       ║
║  Porta: ${PORT}                              ║
║  Pronto pra receber conexões!          ║
╚════════════════════════════════════════╝
  `);
});
