'use strict';
// Точка входа CyberShield API: http-сервер, роутер /api/*, CORS, статика фронтенда, rate limit.
// Запуск: node src/index.js (порт из process.env.PORT, по умолчанию 3000).

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const db = require('./db');
const auth = require('./auth');
const mail = require('./mail');

const { ApiError } = auth;

const PORT = Number(process.env.PORT || 3000);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
// Внимание: корень статики — родительский каталог папки server (то есть сам проект)
const STATIC_ROOT = path.join(__dirname, '..', '..');
const RATE_LIMIT_MAX = 20;             // запросов
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // за минуту, на один IP, только /api/auth/*
const MAX_BODY_BYTES = 1024 * 1024;    // 1 МБ на тело запроса
// Каталоги, которые никогда не раздаются как статика
const BLOCKED_STATIC_DIRS = new Set(['server', 'data', 'node_modules', '.git', '.vscode']);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
const CATEGORIES = ['passwords', 'phishing', 'privacy', 'networks', 'help'];
const SEVERITIES = ['high', 'medium', 'low'];
const THREAT_TYPES = ['site', 'app', 'practice'];

// ---------- Общие утилиты ----------

const corsHeaders = () => ({
  'Access-Control-Allow-Origin': CORS_ORIGIN,
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Max-Age': '86400',
});

function json(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
    ...corsHeaders(),
  });
  res.end(body);
}

// Очистка строк: убираем управляющие символы (кроме перевода строки и табуляции) и обрезаем длину
function clean(value, maxLen) {
  if (typeof value !== 'string') return '';
  const withoutControls = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  const trimmed = withoutControls.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

function normalizeIp(value) {
  if (!value) return '';
  let ip = String(value).split(',')[0].trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip === '::1') ip = '127.0.0.1';
  return ip.slice(0, 60);
}

function clientIp(req) {
  return normalizeIp(
    req.headers['x-forwarded-for'] ||
    req.headers['x-real-ip'] ||
    (req.socket && req.socket.remoteAddress) ||
    ''
  );
}

// IP из тела запроса или из заголовков
function requestIp(req, body) {
  const nested = body && body.device && typeof body.device === 'object' ? body.device : null;
  return normalizeIp((nested && nested.ip) || (body && body.ip) || clientIp(req));
}

function requestDevice(req, body) {
  const nested = body && body.device && typeof body.device === 'object' ? body.device : null;
  const deviceId = clean(
    (nested && nested.deviceId) || (body && body.deviceId) || req.headers['x-device-id'],
    120
  );
  const deviceLabel =
    clean(
      (nested && nested.deviceLabel) || (body && body.deviceLabel) || req.headers['x-device-label'],
      120
    ) || deviceId;
  return { deviceId, deviceLabel };
}

// Код можно вернуть клиенту только вне production или при явном разрешении
function devCodeAllowed() {
  return process.env.NODE_ENV !== 'production' || process.env.ALLOW_DEV_CODE === '1';
}

function readBody(req, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new ApiError(400, 'Слишком большой запрос'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', (err) => reject(err));
  });
}

async function readJson(req) {
  const buffer = await readBody(req);
  if (!buffer.length) return {};
  let parsed;
  try {
    parsed = JSON.parse(buffer.toString('utf8'));
  } catch {
    throw new ApiError(400, 'Некорректный JSON в запросе');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  return parsed;
}

// ---------- Rate limit в памяти ----------
const buckets = new Map();

function rateLimit(ip) {
  const now = Date.now();
  let bucket = buckets.get(ip);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    buckets.set(ip, bucket);
  }
  bucket.count += 1;
  // редкая уборка, чтобы карта не росла бесконечно
  if (buckets.size > 5000) {
    for (const [key, value] of buckets) {
      if (value.resetAt <= now) buckets.delete(key);
    }
  }
  return bucket.count <= RATE_LIMIT_MAX;
}

// ---------- Сериализация записей ----------
const userJson = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  isAdmin: Boolean(user.is_admin),
  createdAt: user.created_at,
});

const resultJson = (row) => ({
  id: row.id,
  score: row.score,
  total: row.total,
  percent: row.percent,
  createdAt: row.created_at,
});

const threatJson = (row) => ({
  id: row.id,
  title: row.title,
  description: row.description,
  severity: row.severity,
  type: row.type,
  example: row.example,
  createdAt: row.created_at,
});

const postJson = (row) => ({
  id: row.id,
  body: row.body,
  authorName: row.author_name,
  authorId: row.author_id,
  createdAt: row.created_at,
});

function topicJson(topic, posts) {
  return {
    id: topic.id,
    title: topic.title,
    body: topic.body,
    category: topic.category,
    authorName: topic.author_name,
    authorId: topic.author_id,
    pinned: Boolean(topic.pinned),
    locked: Boolean(topic.locked),
    views: Number(topic.views || 0),
    createdAt: topic.created_at,
    updatedAt: topic.updated_at,
    posts: posts.map(postJson),
  };
}

function loadTopic(id) {
  const topic = db.q.get('SELECT * FROM topics WHERE id = ?', id);
  if (!topic) return null;
  const posts = db.q.all('SELECT * FROM posts WHERE topic_id = ? ORDER BY created_at ASC, rowid ASC', id);
  return topicJson(topic, posts);
}

function listTopics() {
  const topics = db.q.all('SELECT * FROM topics ORDER BY pinned DESC, updated_at DESC');
  const posts = db.q.all('SELECT * FROM posts ORDER BY created_at ASC, rowid ASC');
  const byTopic = new Map();
  for (const post of posts) {
    if (!byTopic.has(post.topic_id)) byTopic.set(post.topic_id, []);
    byTopic.get(post.topic_id).push(post);
  }
  return topics.map((topic) => topicJson(topic, byTopic.get(topic.id) || []));
}

// ---------- Аутентификация по токену ----------
function bearerToken(req) {
  const header = req.headers.authorization || '';
  const match = /^Bearer\s+([A-Fa-f0-9]{16,200})$/.exec(String(header).trim());
  return match ? match[1] : '';
}

function requireUser(req) {
  const user = auth.getSessionUser(bearerToken(req));
  if (!user) throw new ApiError(401, 'Требуется вход в аккаунт');
  return user;
}

function requireAdmin(req) {
  const user = requireUser(req);
  if (!user.is_admin) throw new ApiError(403, 'Доступно только администратору');
  return user;
}

// ---------- Обработчики авторизации ----------

async function handleRegister(req, res) {
  const body = await readJson(req);
  const name = clean(body.name, 80);
  const email = clean(body.email, 190).toLowerCase();
  const password = typeof body.password === 'string' ? body.password : '';

  if (name.length < 2) throw new ApiError(400, 'Имя должно содержать минимум 2 символа');
  if (!EMAIL_RE.test(email)) throw new ApiError(400, 'Некорректный email');
  if (password.length < 6) throw new ApiError(400, 'Пароль должен содержать минимум 6 символов');
  if (password.length > 200) throw new ApiError(400, 'Пароль слишком длинный');

  const existing = db.getUserByEmail(email);
  if (existing && auth.isEmailVerified(existing.id)) {
    throw new ApiError(400, 'Пользователь с таким email уже существует');
  }

  const salt = auth.makeSalt();
  const hash = auth.hashPassword(password, salt);
  let userId;
  if (existing) {
    // повторная регистрация неподтверждённого аккаунта: обновляем данные и старые коды
    userId = existing.id;
    db.q.run('UPDATE users SET name = ?, password_hash = ?, salt = ? WHERE id = ?', name, hash, salt, userId);
    db.q.run("UPDATE codes SET consumed = 1 WHERE user_id = ? AND kind = 'register' AND consumed = 0", userId);
  } else {
    userId = db.newId();
    db.q.run(
      'INSERT INTO users (id, name, email, password_hash, salt, is_admin, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)',
      userId, name, email, hash, salt, db.nowIso()
    );
  }

  const { deviceId, deviceLabel } = requestDevice(req, body);
  const ip = requestIp(req, body);
  const { id: pendingToken, code } = auth.createCode({ userId, kind: 'register', deviceId, deviceLabel, ip });
  const mailResult = await mail.sendCode(email, code);
  auth.logSecurity(userId, 'register', 'Запрошен код подтверждения регистрации', ip, deviceLabel);

  const payload = { ok: true, email, pendingToken, emailSent: mailResult.sent };
  if (devCodeAllowed()) payload.devCode = code;
  json(res, 200, payload);
}

async function handleRegisterVerify(req, res) {
  const body = await readJson(req);
  const pendingToken = clean(body.pendingToken, 64);
  const code = clean(body.code, 12);

  const row = auth.getCode(pendingToken);
  if (!row || row.kind !== 'register') {
    throw new ApiError(400, 'Подтверждение недействительно. Зарегистрируйтесь заново.');
  }
  auth.consumeCode(row, code);

  const user = db.getUserById(row.user_id);
  if (!user) throw new ApiError(400, 'Пользователь не найден');

  // Первое устройство/IP становятся доверенными.
  // IP берём из запроса регистрации (row.ip): при подтверждении кода клиент
  // может прийти с другого адреса, и тогда доверенным стал бы не тот IP.
  const { deviceId, deviceLabel } = requestDevice(req, body);
  const ip = row.ip || requestIp(req, body) || '';
  auth.setTrust(user.id, deviceId || row.device_id || '', ip);
  auth.upsertDevice(user.id, deviceId || row.device_id || '', deviceLabel || row.device_label || '', ip);
  auth.logSecurity(user.id, 'register_verified', 'Email подтверждён кодом', ip, deviceLabel || row.device_label || '');

  const token = auth.createSession(user.id);
  json(res, 200, { ok: true, token, user: userJson(user) });
}

async function handleLogin(req, res) {
  const body = await readJson(req);
  const email = clean(body.email, 190).toLowerCase();
  const password = typeof body.password === 'string' ? body.password : '';
  if (!email || !password) throw new ApiError(400, 'Укажите email и пароль');

  const user = db.getUserByEmail(email);
  if (!user || !auth.verifyPassword(password, user.salt, user.password_hash)) {
    auth.logSecurity(user ? user.id : null, 'login_failed', `Неудачный вход: ${email}`, requestIp(req, body), '');
    throw new ApiError(401, 'Неверный email или пароль');
  }
  if (!auth.isEmailVerified(user.id)) {
    throw new ApiError(403, 'Email не подтверждён. Завершите регистрацию: введите код из письма.');
  }

  const { deviceId, deviceLabel } = requestDevice(req, body);
  const ip = requestIp(req, body);
  const trust = auth.getTrust(user.id);

  // Сверяем с доверенными значениями: новое устройство и/или новый IP требуют кода
  const reasons = [];
  if (trust) {
    if (trust.first_device_id && deviceId && trust.first_device_id !== deviceId) reasons.push('device');
    if (trust.first_ip && ip && trust.first_ip !== ip) reasons.push('ip');
  }

  if (reasons.length === 0) {
    if (!trust) auth.setTrust(user.id, deviceId, ip); // самый первый вход без записи доверия
    auth.upsertDevice(user.id, deviceId, deviceLabel, ip);
    const token = auth.createSession(user.id);
    auth.logSecurity(user.id, 'login', 'Вход выполнен', ip, deviceLabel);
    return json(res, 200, { ok: true, token, user: userJson(user) });
  }

  const { id: challengeToken, code } = auth.createCode({
    userId: user.id, kind: 'login', deviceId, deviceLabel, ip,
  });
  const mailResult = await mail.sendCode(user.email, code);
  auth.logSecurity(
    user.id, 'login_challenge',
    `Требуется подтверждение входа (${reasons.join(', ')})`, ip, deviceLabel
  );

  const payload = {
    ok: false,
    challenge: true,
    challengeToken,
    reasons,
    email: user.email,
    emailSent: mailResult.sent,
  };
  if (devCodeAllowed()) payload.devCode = code;
  json(res, 200, payload);
}

async function handleLoginVerify(req, res) {
  const body = await readJson(req);
  const challengeToken = clean(body.challengeToken, 64);
  const code = clean(body.code, 12);

  const row = auth.getCode(challengeToken);
  if (!row || row.kind !== 'login') {
    throw new ApiError(400, 'Подтверждение входа недействительно. Войдите заново.');
  }
  auth.consumeCode(row, code);

  const user = db.getUserById(row.user_id);
  if (!user) throw new ApiError(400, 'Пользователь не найден');

  // Новое устройство/IP после успешного кода становятся доверенными
  auth.setTrust(user.id, row.device_id || '', row.ip || '');
  auth.upsertDevice(user.id, row.device_id || '', row.device_label || '', row.ip || '');
  auth.logSecurity(user.id, 'login_verified', 'Вход подтверждён кодом с нового устройства/IP', row.ip, row.device_label);

  const token = auth.createSession(user.id);
  json(res, 200, { ok: true, token, user: userJson(user) });
}

async function handleResend(req, res) {
  const body = await readJson(req);
  const challengeToken = clean(body.challengeToken, 64);
  const row = auth.getCode(challengeToken);
  if (!row || (row.kind !== 'login' && row.kind !== 'register')) {
    throw new ApiError(400, 'Запрос недействителен. Начните заново.');
  }
  const user = db.getUserById(row.user_id);
  if (!user) throw new ApiError(400, 'Пользователь не найден');

  const code = auth.refreshCode(row); // внутри проверка паузы 30 секунд (иначе 429)
  const mailResult = await mail.sendCode(user.email, code);
  auth.logSecurity(user.id, 'code_resent', 'Код отправлен повторно', row.ip, row.device_label);

  const payload = { ok: true, cooldown: auth.RESEND_COOLDOWN_SEC, emailSent: mailResult.sent };
  if (devCodeAllowed()) payload.devCode = code;
  json(res, 200, payload);
}

// ---------- Форум ----------
async function handleTopicCreate(req, res) {
  const user = requireUser(req);
  const body = await readJson(req);
  const title = clean(body.title, 120);
  const text = clean(body.body, 4000);
  let category = clean(body.category, 30).toLowerCase();
  if (!CATEGORIES.includes(category)) category = 'help';

  if (title.length < 3) throw new ApiError(400, 'Заголовок темы должен содержать минимум 3 символа');
  if (text.length < 5) throw new ApiError(400, 'Сообщение темы слишком короткое');

  const id = db.newId();
  const now = db.nowIso();
  db.q.run(
    `INSERT INTO topics (id, title, body, category, author_id, author_name, pinned, locked, views, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)`,
    id, title, text, category, user.id, user.name, now, now
  );
  json(res, 200, { topic: loadTopic(id) });
}

async function handlePostCreate(req, res, topicId) {
  const user = requireUser(req);
  const body = await readJson(req);
  const text = clean(body.body, 4000);
  if (text.length < 1) throw new ApiError(400, 'Сообщение не может быть пустым');

  const topic = db.q.get('SELECT * FROM topics WHERE id = ?', topicId);
  if (!topic) throw new ApiError(404, 'Тема не найдена');
  if (topic.locked) throw new ApiError(403, 'Тема закрыта: новые ответы запрещены');

  const now = db.nowIso();
  db.q.run(
    'INSERT INTO posts (id, topic_id, author_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    db.newId(), topic.id, user.id, user.name, text, now
  );
  db.q.run('UPDATE topics SET updated_at = ? WHERE id = ?', now, topic.id);
  json(res, 200, { topic: loadTopic(topic.id) });
}

async function handleTopicPatch(req, res, topicId) {
  requireAdmin(req);
  const body = await readJson(req);
  const topic = db.q.get('SELECT * FROM topics WHERE id = ?', topicId);
  if (!topic) throw new ApiError(404, 'Тема не найдена');

  const pinned = body.pinned === undefined ? topic.pinned : body.pinned ? 1 : 0;
  const locked = body.locked === undefined ? topic.locked : body.locked ? 1 : 0;
  db.q.run('UPDATE topics SET pinned = ?, locked = ?, updated_at = ? WHERE id = ?', pinned, locked, db.nowIso(), topic.id);
  json(res, 200, { topic: loadTopic(topic.id) });
}

async function handleTopicDelete(req, res, topicId) {
  const user = requireUser(req);
  const topic = db.q.get('SELECT * FROM topics WHERE id = ?', topicId);
  if (!topic) throw new ApiError(404, 'Тема не найдена');
  if (!user.is_admin && topic.author_id !== user.id) {
    throw new ApiError(403, 'Удалять тему может только автор или администратор');
  }
  db.q.run('DELETE FROM posts WHERE topic_id = ?', topic.id);
  db.q.run('DELETE FROM topics WHERE id = ?', topic.id);
  json(res, 200, { ok: true });
}

async function handlePostDelete(req, res, topicId, postId) {
  const user = requireUser(req);
  const topic = db.q.get('SELECT * FROM topics WHERE id = ?', topicId);
  if (!topic) throw new ApiError(404, 'Тема не найдена');
  const post = db.q.get('SELECT * FROM posts WHERE id = ? AND topic_id = ?', postId, topicId);
  if (!post) throw new ApiError(404, 'Сообщение не найдено');
  if (!user.is_admin && post.author_id !== user.id) {
    throw new ApiError(403, 'Удалять сообщение может только его автор или администратор');
  }
  db.q.run('DELETE FROM posts WHERE id = ?', post.id);
  db.q.run('UPDATE topics SET updated_at = ? WHERE id = ?', db.nowIso(), topic.id);
  json(res, 200, { topic: loadTopic(topic.id) });
}

// ---------- Реестр опасностей ----------
async function handleThreatCreate(req, res) {
  requireAdmin(req);
  const body = await readJson(req);
  const title = clean(body.title, 120);
  const description = clean(body.description, 4000);
  const severity = clean(body.severity, 10).toLowerCase();
  const type = clean(body.type, 10).toLowerCase();
  const example = clean(body.example, 300);

  if (title.length < 3) throw new ApiError(400, 'Заголовок должен содержать минимум 3 символа');
  if (description.length < 5) throw new ApiError(400, 'Описание слишком короткое');
  if (!SEVERITIES.includes(severity)) throw new ApiError(400, 'severity должен быть high, medium или low');
  if (!THREAT_TYPES.includes(type)) throw new ApiError(400, 'type должен быть site, app или practice');

  const id = db.newId();
  db.q.run(
    'INSERT INTO threats (id, title, description, severity, type, example, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    id, title, description, severity, type, example, db.nowIso()
  );
  json(res, 200, { threat: threatJson(db.q.get('SELECT * FROM threats WHERE id = ?', id)) });
}

async function handleThreatDelete(req, res, threatId) {
  requireAdmin(req);
  const threat = db.q.get('SELECT * FROM threats WHERE id = ?', threatId);
  if (!threat) throw new ApiError(404, 'Запись не найдена');
  db.q.run('DELETE FROM threats WHERE id = ?', threat.id);
  json(res, 200, { ok: true });
}

// ---------- Роутер API ----------
async function handleApi(req, res, url, method) {
  const p = url.pathname.length > 4 ? url.pathname.replace(/\/+$/, '') : url.pathname;

  // Rate limit только для авторизации
  if (p.startsWith('/api/auth/') && !rateLimit(clientIp(req))) {
    throw new ApiError(429, 'Слишком много запросов. Попробуйте через минуту.');
  }

  // health
  if (p === '/api/health' && method === 'GET') {
    return json(res, 200, {
      ok: true,
      mailer: mail.mailerMode(),
      users: db.q.count('users'),
      topics: db.q.count('topics'),
    });
  }

  // авторизация
  if (p === '/api/auth/register' && method === 'POST') return handleRegister(req, res);
  if (p === '/api/auth/register/verify' && method === 'POST') return handleRegisterVerify(req, res);
  if (p === '/api/auth/login' && method === 'POST') return handleLogin(req, res);
  if (p === '/api/auth/login/verify' && method === 'POST') return handleLoginVerify(req, res);
  if (p === '/api/auth/resend' && method === 'POST') return handleResend(req, res);
  if (p === '/api/auth/me' && method === 'GET') {
    const user = requireUser(req);
    return json(res, 200, { user: userJson(user) });
  }
  if (p === '/api/auth/logout' && method === 'POST') {
    auth.destroySession(bearerToken(req));
    return json(res, 200, { ok: true });
  }

  // результаты теста
  if (p === '/api/results' && method === 'POST') {
    const user = requireUser(req);
    const body = await readJson(req);
    const score = Number(body.score);
    const total = Number(body.total);
    let percent = Number(body.percent);
    if (!Number.isFinite(score) || !Number.isFinite(total) || total <= 0) {
      throw new ApiError(400, 'Некорректные значения score/total');
    }
    if (!Number.isFinite(percent)) percent = Math.round((score / total) * 100);
    percent = Math.max(0, Math.min(100, Math.round(percent)));

    const id = db.newId();
    db.q.run(
      'INSERT INTO results (id, user_id, score, total, percent, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      id, user.id, Math.round(score), Math.round(total), percent, db.nowIso()
    );
    return json(res, 200, { ok: true, result: resultJson(db.q.get('SELECT * FROM results WHERE id = ?', id)) });
  }

  // форум
  if (p === '/api/forum' && method === 'GET') return json(res, 200, { topics: listTopics() });
  if (p === '/api/forum/topics' && method === 'POST') return handleTopicCreate(req, res);

  const postRoute = /^\/api\/forum\/topics\/([^/]+)\/posts$/.exec(p);
  if (postRoute && method === 'POST') return handlePostCreate(req, res, decodeURIComponent(postRoute[1]));

  const onePostRoute = /^\/api\/forum\/topics\/([^/]+)\/posts\/([^/]+)$/.exec(p);
  if (onePostRoute && method === 'DELETE') {
    return handlePostDelete(req, res, decodeURIComponent(onePostRoute[1]), decodeURIComponent(onePostRoute[2]));
  }

  const topicRoute = /^\/api\/forum\/topics\/([^/]+)$/.exec(p);
  if (topicRoute && method === 'PATCH') return handleTopicPatch(req, res, decodeURIComponent(topicRoute[1]));
  if (topicRoute && method === 'DELETE') return handleTopicDelete(req, res, decodeURIComponent(topicRoute[1]));

  // реестр опасностей
  if (p === '/api/threats' && method === 'GET') {
    const threats = db.q.all('SELECT * FROM threats ORDER BY created_at DESC');
    return json(res, 200, { threats: threats.map(threatJson) });
  }
  if (p === '/api/threats' && method === 'POST') return handleThreatCreate(req, res);

  const threatRoute = /^\/api\/threats\/([^/]+)$/.exec(p);
  if (threatRoute && method === 'DELETE') return handleThreatDelete(req, res, decodeURIComponent(threatRoute[1]));

  // админ-панель
  if (p === '/api/admin/users' && method === 'GET') {
    requireAdmin(req);
    const users = db.q.all('SELECT * FROM users ORDER BY created_at ASC');
    const results = db.q.all('SELECT * FROM results ORDER BY created_at DESC');
    const byUser = new Map();
    for (const row of results) {
      if (!byUser.has(row.user_id)) byUser.set(row.user_id, []);
      byUser.get(row.user_id).push(resultJson(row));
    }
    return json(res, 200, {
      users: users.map((user) => ({
        id: user.id,
        name: user.name,
        email: user.email,
        isAdmin: Boolean(user.is_admin),
        createdAt: user.created_at,
        results: byUser.get(user.id) || [],
      })),
    });
  }

  if (p === '/api/admin/security' && method === 'GET') {
    requireAdmin(req);
    const log = db.q.all(
      `SELECT l.*, u.email AS email FROM security_log l
       LEFT JOIN users u ON u.id = l.user_id
       ORDER BY l.created_at DESC LIMIT 200`
    );
    return json(res, 200, {
      log: log.map((row) => ({
        email: row.email || '',
        type: row.type,
        message: row.message,
        ip: row.ip,
        deviceLabel: row.device_label,
        createdAt: row.created_at,
      })),
    });
  }

  throw new ApiError(404, 'Метод API не найден');
}

// ---------- Статика фронтенда ----------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function serveStatic(req, res, pathname) {
  let rel = pathname;
  try {
    rel = decodeURIComponent(pathname);
  } catch {
    return json(res, 400, { error: 'Некорректный путь' });
  }
  if (rel === '/' || rel === '') rel = '/index.html';
  if (rel.includes('\0')) return json(res, 404, { error: 'Файл не найден' });

  // Служебные каталоги проекта наружу не отдаём (исходники бэкенда, база, git)
  const firstSegment = rel.split('/').filter(Boolean)[0] || '';
  if (BLOCKED_STATIC_DIRS.has(firstSegment.toLowerCase())) {
    return json(res, 404, { error: 'Файл не найден' });
  }

  // Защита от path traversal: путь обязан остаться внутри корня
  const abs = path.resolve(STATIC_ROOT, '.' + (rel.startsWith('/') ? rel : '/' + rel));
  if (abs !== STATIC_ROOT && !abs.startsWith(STATIC_ROOT + path.sep)) {
    return json(res, 404, { error: 'Файл не найден' });
  }
  const ext = path.extname(abs).toLowerCase();
  if (!MIME[ext]) return json(res, 404, { error: 'Файл не найден' });

  fs.stat(abs, (err, stat) => {
    if (err || !stat.isFile()) return json(res, 404, { error: 'Файл не найден' });
    res.writeHead(200, {
      'Content-Type': MIME[ext],
      'Content-Length': stat.size,
      'Cache-Control': 'no-cache',
      ...corsHeaders(),
    });
    if (req.method === 'HEAD') return res.end();
    const stream = fs.createReadStream(abs);
    stream.on('error', () => res.destroy());
    stream.pipe(res);
  });
}

// ---------- Обработка запроса ----------
async function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const method = String(req.method || 'GET').toUpperCase();

  if (method === 'OPTIONS') {
    res.writeHead(204, corsHeaders());
    return res.end();
  }
  if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
    return handleApi(req, res, url, method);
  }
  if (method === 'GET' || method === 'HEAD') {
    return serveStatic(req, res, url.pathname);
  }
  json(res, 404, { error: 'Страница не найдена' });
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    if (err instanceof ApiError) {
      json(res, err.status, { error: err.message });
      return;
    }
    console.error('[api] внутренняя ошибка:', err);
    json(res, 500, { error: 'Внутренняя ошибка сервера' });
  });
});

server.listen(PORT, () => {
  console.log(`[api] CyberShield запущен на http://localhost:${PORT}`);
  console.log(`[api] база: ${db.DB_PATH}`);
  console.log(`[api] почта: ${mail.mailerMode()}`);
});

// Аккуратное завершение по Ctrl+C
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
