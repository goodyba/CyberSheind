'use strict';
// Отправка писем с кодом подтверждения.
// Если SMTP настроен — реальная отправка через node:tls (implicit TLS, порт 465),
// иначе фолбэк: код печатается в консоль сервера.

const tls = require('node:tls');

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const CLIENT_NAME = 'cybershield.local';

function isConfigured() {
  return Boolean(SMTP_HOST && SMTP_PORT && SMTP_USER && SMTP_PASS);
}

// 'smtp' — письма уходят на почту, 'console' — только в лог сервера
function mailerMode() {
  return isConfigured() ? 'smtp' : 'console';
}

// --- Минимальный SMTP-клиент (ответы вида "250 текст", многострочные "250-...") ---
class SmtpClient {
  constructor(socket) {
    this.socket = socket;
    this.buffer = '';
    this.partial = [];
    this.responses = [];
    this.waiters = [];
    this.failure = null;

    socket.setEncoding('utf8');
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', (err) => this.fail(err));
    socket.on('close', () => this.fail(new Error('SMTP: соединение закрыто')));
    socket.setTimeout(20000, () => socket.destroy(new Error('SMTP: таймаут соединения')));
  }

  onData(chunk) {
    this.buffer += chunk;
    let idx;
    while ((idx = this.buffer.indexOf('\r\n')) >= 0) {
      const line = this.buffer.slice(0, idx);
      this.buffer = this.buffer.slice(idx + 2);
      this.onLine(line);
    }
  }

  onLine(line) {
    const match = /^(\d{3})([ -])(.*)$/.exec(line);
    if (!match) return;
    this.partial.push(line);
    if (match[2] === ' ') {
      const response = { code: Number(match[1]), text: this.partial.join('\n') };
      this.partial = [];
      const waiter = this.waiters.shift();
      if (waiter) waiter.resolve(response);
      else this.responses.push(response);
    }
  }

  fail(err) {
    this.failure = this.failure || err;
    while (this.waiters.length) this.waiters.shift().reject(this.failure);
  }

  read() {
    if (this.responses.length) return Promise.resolve(this.responses.shift());
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  async command(line, expect) {
    if (line !== null && line !== undefined) this.socket.write(line + '\r\n');
    const response = await this.read();
    if (expect && response.code !== expect) {
      throw new Error(`SMTP: ожидался код ${expect}, получен ${response.code} (${response.text})`);
    }
    return response;
  }
}

function connectSocket() {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: SMTP_HOST, port: SMTP_PORT, servername: SMTP_HOST });
    const onError = (err) => {
      socket.destroy();
      reject(err);
    };
    socket.once('error', onError);
    socket.once('secureConnect', () => {
      socket.removeListener('error', onError);
      resolve(socket);
    });
  });
}

// --- Сборка письма: тема в RFC 2047, тело в base64 ---
function encodeHeaderValue(value) {
  return `=?UTF-8?B?${Buffer.from(String(value), 'utf8').toString('base64')}?=`;
}

function buildMessage({ to, subject, text }) {
  // base64 с переносами по 76 символов
  const body = Buffer.from(String(text), 'utf8').toString('base64').replace(/(.{76})/g, '$1\r\n');
  return [
    `From: ${encodeHeaderValue('CyberShield')} <${SMTP_FROM}>`,
    `To: <${to}>`,
    `Subject: ${encodeHeaderValue(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@cybershield.local>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    body,
  ].join('\r\n');
}

async function sendViaSmtp({ to, subject, text }) {
  const socket = await connectSocket();
  const client = new SmtpClient(socket);
  try {
    await client.command(null, 220);                              // приветствие сервера
    await client.command(`EHLO ${CLIENT_NAME}`, 250);             // представление
    await client.command('AUTH LOGIN', 334);                      // начало авторизации
    await client.command(Buffer.from(SMTP_USER, 'utf8').toString('base64'), 334);
    await client.command(Buffer.from(SMTP_PASS, 'utf8').toString('base64'), 235);
    await client.command(`MAIL FROM:<${SMTP_FROM}>`, 250);
    await client.command(`RCPT TO:<${to}>`, 250);
    await client.command('DATA', 354);
    await client.command(buildMessage({ to, subject, text }) + '\r\n.', 250);
    try {
      await client.command('QUIT', 221);
    } catch {
      /* сервер мог закрыть соединение сразу после QUIT — это нормально */
    }
    return true;
  } finally {
    socket.destroy();
  }
}

// Публичная функция: отправить код. Никогда не бросает исключение наружу.
async function sendCode(email, code) {
  const subject = 'Код подтверждения CyberShield';
  const text = [
    'Здравствуйте!',
    '',
    `Ваш код подтверждения: ${code}`,
    '',
    'Код действует 10 минут и подходит только для одного действия.',
    'Никому не сообщайте этот код: сотрудники CyberShield никогда его не спрашивают.',
    '',
    'Если вы не запрашивали код, просто проигнорируйте письмо.',
    '',
    '— CyberShield',
  ].join('\n');

  if (!isConfigured()) {
    console.log(`[mail] код для ${email}: ${code}`);
    return { sent: false };
  }

  try {
    await sendViaSmtp({ to: email, subject, text });
    return { sent: true };
  } catch (err) {
    console.error('[mail] не удалось отправить письмо:', err && err.message ? err.message : err);
    console.log(`[mail] код для ${email}: ${code}`);
    return { sent: false };
  }
}

module.exports = { sendCode, mailerMode, isConfigured };
