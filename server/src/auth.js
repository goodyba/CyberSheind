'use strict';
// Безопасность аккаунтов: scrypt-хеши паролей, токены сессий, коды подтверждения,
// доверие устройству/IP и журнал событий безопасности.

const crypto = require('node:crypto');
const db = require('./db');

// Сроки и лимиты
const SESSION_DAYS = 30;           // срок жизни сессии
const CODE_TTL_MIN = 10;           // срок жизни кода
const CODE_ATTEMPTS = 5;           // максимум попыток ввода кода
const RESEND_COOLDOWN_SEC = 30;    // пауза между повторными отправками

// Ошибка API со статусом (используется роутером)
class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// --- Пароли ---
function makeSalt() {
  return crypto.randomBytes(16).toString('hex');
}
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
function verifyPassword(password, salt, expectedHash) {
  const actual = Buffer.from(hashPassword(password, salt), 'hex');
  const expected = Buffer.from(String(expectedHash || ''), 'hex');
  if (actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(actual, expected);
}

// --- Токены и коды ---
function newSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}
function newCode() {
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}
// Сравнение с постоянным временем: хешируем обе стороны, чтобы длины всегда совпадали
function codesEqual(a, b) {
  const left = crypto.createHash('sha256').update(String(a), 'utf8').digest();
  const right = crypto.createHash('sha256').update(String(b), 'utf8').digest();
  return crypto.timingSafeEqual(left, right);
}

// --- Сессии ---
function createSession(userId) {
  const token = newSessionToken();
  const created = db.nowIso();
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  db.q.run('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)', token, userId, created, expires);
  return token;
}

function getSessionUser(token) {
  if (!token) return null;
  const row = db.q.get('SELECT * FROM sessions WHERE token = ?', token);
  if (!row) return null;
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    db.q.run('DELETE FROM sessions WHERE token = ?', token);
    return null;
  }
  return db.getUserById(row.user_id);
}

function destroySession(token) {
  if (!token) return;
  db.q.run('DELETE FROM sessions WHERE token = ?', token);
}

// --- Коды подтверждения (kind: 'register' | 'login') ---
function createCode({ userId, kind, deviceId, deviceLabel, ip }) {
  const id = db.newId();
  const code = newCode();
  const now = Date.now();
  db.q.run(
    `INSERT INTO codes (id, user_id, kind, code, device_id, device_label, ip, attempts, created_at, expires_at, consumed)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0)`,
    id, userId, kind, code, deviceId || null, deviceLabel || null, ip || null,
    new Date(now).toISOString(), new Date(now + CODE_TTL_MIN * 60 * 1000).toISOString()
  );
  return { id, code };
}

function getCode(id) {
  if (!id) return null;
  return db.q.get('SELECT * FROM codes WHERE id = ?', String(id)) || null;
}

// Проверка кода: срок, число попыток, постоянное время сравнения, пометка «использован»
function consumeCode(row, code) {
  if (!row) throw new ApiError(400, 'Код не найден. Запросите новый.');
  if (row.consumed) throw new ApiError(400, 'Код уже использован. Запросите новый.');
  if (new Date(row.expires_at).getTime() <= Date.now()) {
    throw new ApiError(400, 'Срок действия кода истёк. Запросите новый.');
  }
  if (Number(row.attempts) >= CODE_ATTEMPTS) {
    throw new ApiError(429, 'Слишком много неверных попыток. Запросите новый код.');
  }
  if (!codesEqual(row.code, String(code == null ? '' : code).trim())) {
    const attempts = Number(row.attempts) + 1;
    db.q.run('UPDATE codes SET attempts = ? WHERE id = ?', attempts, row.id);
    const left = CODE_ATTEMPTS - attempts;
    if (left <= 0) throw new ApiError(429, 'Слишком много неверных попыток. Запросите новый код.');
    throw new ApiError(400, `Неверный код. Осталось попыток: ${left}`);
  }
  db.q.run('UPDATE codes SET consumed = 1 WHERE id = ?', row.id);
  return true;
}

// Перевыпуск кода в рамках того же запроса подтверждения (с проверкой паузы 30 секунд)
function refreshCode(row) {
  const now = Date.now();
  const ageSec = (now - new Date(row.created_at).getTime()) / 1000;
  if (!row.consumed && ageSec < RESEND_COOLDOWN_SEC) {
    const left = Math.ceil(RESEND_COOLDOWN_SEC - ageSec);
    throw new ApiError(429, `Код уже отправлен. Повторите через ${left} с.`);
  }
  const code = newCode();
  db.q.run(
    'UPDATE codes SET code = ?, attempts = 0, consumed = 0, created_at = ?, expires_at = ? WHERE id = ?',
    code, new Date(now).toISOString(), new Date(now + CODE_TTL_MIN * 60 * 1000).toISOString(), row.id
  );
  return code;
}

// Признак подтверждённого email: есть использованный код регистрации
function isEmailVerified(userId) {
  const row = db.q.get(
    "SELECT 1 AS v FROM codes WHERE user_id = ? AND kind = 'register' AND consumed = 1 LIMIT 1",
    userId
  );
  return Boolean(row);
}

// --- Доверие устройству/IP, список устройств, журнал ---
function getTrust(userId) {
  return db.q.get('SELECT * FROM trust WHERE user_id = ?', userId) || null;
}

function setTrust(userId, deviceId, ip) {
  const now = db.nowIso();
  db.q.run(
    `INSERT INTO trust (user_id, first_device_id, first_ip, first_seen) VALUES (?, ?, ?, ?)
     ON CONFLICT(user_id) DO UPDATE SET
       first_device_id = excluded.first_device_id,
       first_ip = excluded.first_ip,
       first_seen = excluded.first_seen`,
    userId, deviceId || null, ip || null, now
  );
}

function upsertDevice(userId, deviceId, label, ip) {
  if (!deviceId) return;
  const now = db.nowIso();
  db.q.run(
    `INSERT INTO devices (user_id, device_id, label, ip, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, device_id) DO UPDATE SET
       label = COALESCE(excluded.label, devices.label),
       ip = excluded.ip,
       last_seen = excluded.last_seen`,
    userId, String(deviceId), label || null, ip || null, now, now
  );
}

function logSecurity(userId, type, message, ip, deviceLabel) {
  db.q.run(
    'INSERT INTO security_log (id, user_id, type, message, ip, device_label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    db.newId(), userId || null, type, message || '', ip || null, deviceLabel || null, db.nowIso()
  );
}

module.exports = {
  ApiError,
  SESSION_DAYS,
  CODE_TTL_MIN,
  CODE_ATTEMPTS,
  RESEND_COOLDOWN_SEC,
  makeSalt,
  hashPassword,
  verifyPassword,
  newSessionToken,
  newCode,
  codesEqual,
  createSession,
  getSessionUser,
  destroySession,
  createCode,
  getCode,
  consumeCode,
  refreshCode,
  isEmailVerified,
  getTrust,
  setTrust,
  upsertDevice,
  logSecurity,
};
