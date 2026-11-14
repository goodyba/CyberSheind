'use strict';
// Слой данных CyberShield: путь к файлу SQLite, схема таблиц, хелперы и стартовое наполнение.
// Используется только встроенный node:sqlite (DatabaseSync).

const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Путь к базе: по умолчанию server/data/cybershield.db, можно переопределить через DB_PATH
const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, '..', 'data', 'cybershield.db');

// Каталог под файл базы создаётся при старте
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new DatabaseSync(DB_PATH);

// --- Схема ---
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  salt TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  score INTEGER,
  total INTEGER,
  percent INTEGER,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  created_at TEXT,
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS codes (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  kind TEXT,
  code TEXT,
  device_id TEXT,
  device_label TEXT,
  ip TEXT,
  attempts INTEGER DEFAULT 0,
  created_at TEXT,
  expires_at TEXT,
  consumed INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  device_id TEXT,
  label TEXT,
  ip TEXT,
  first_seen TEXT,
  last_seen TEXT,
  UNIQUE (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS trust (
  user_id TEXT PRIMARY KEY,
  first_device_id TEXT,
  first_ip TEXT,
  first_seen TEXT
);

CREATE TABLE IF NOT EXISTS security_log (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  type TEXT,
  message TEXT,
  ip TEXT,
  device_label TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS threats (
  id TEXT PRIMARY KEY,
  title TEXT,
  description TEXT,
  severity TEXT,
  type TEXT,
  example TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS topics (
  id TEXT PRIMARY KEY,
  title TEXT,
  body TEXT,
  category TEXT,
  author_id TEXT,
  author_name TEXT,
  pinned INTEGER DEFAULT 0,
  locked INTEGER DEFAULT 0,
  views INTEGER DEFAULT 0,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  topic_id TEXT,
  author_id TEXT,
  author_name TEXT,
  body TEXT,
  created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_results_user ON results (user_id);
CREATE INDEX IF NOT EXISTS idx_posts_topic ON posts (topic_id);
CREATE INDEX IF NOT EXISTS idx_codes_user ON codes (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
`);

// --- Базовые хелперы ---
const nowIso = () => new Date().toISOString();
const newId = () => crypto.randomUUID();

function run(sql, ...params) {
  return db.prepare(sql).run(...params);
}
function get(sql, ...params) {
  return db.prepare(sql).get(...params);
}
function all(sql, ...params) {
  return db.prepare(sql).all(...params);
}
function count(table) {
  const row = get(`SELECT COUNT(*) AS c FROM ${table}`);
  return row ? Number(row.c) : 0;
}

function getUserByEmail(email) {
  return get('SELECT * FROM users WHERE email = ?', String(email || '').toLowerCase()) || null;
}
function getUserById(id) {
  return get('SELECT * FROM users WHERE id = ?', id) || null;
}

// --- Стартовое наполнение (идемпотентно) ---
function seed() {
  // Администратор: admin@cyber.ru / admin123
  if (count('users') === 0) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync('admin123', salt, 64).toString('hex');
    run(
      'INSERT INTO users (id, name, email, password_hash, salt, is_admin, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)',
      newId(), 'Администратор', 'admin@cyber.ru', hash, salt, nowIso()
    );
  }

  const admin = get('SELECT * FROM users WHERE is_admin = 1 ORDER BY created_at ASC LIMIT 1') || get('SELECT * FROM users LIMIT 1');
  if (!admin) return; // без пользователя форум не наполнить

  // Маркер подтверждённого email для админа: без него вход в свежую базу был бы заблокирован
  if (admin.is_admin) {
    const marker = get("SELECT 1 AS v FROM codes WHERE user_id = ? AND kind = 'register' AND consumed = 1 LIMIT 1", admin.id);
    if (!marker) {
      run(
        `INSERT INTO codes (id, user_id, kind, code, device_id, device_label, ip, attempts, created_at, expires_at, consumed)
         VALUES (?, ?, 'register', '000000', NULL, NULL, NULL, 0, ?, ?, 1)`,
        newId(), admin.id, nowIso(), nowIso()
      );
    }
  }

  // Пять стартовых тем форума (одна закреплена)
  if (count('topics') === 0) {
    const base = Date.now();
    const isoAgo = (minutes) => new Date(base - minutes * 60000).toISOString();

    const seedTopics = [
      {
        title: 'Парольная фраза вместо пароля: как придумать и не забыть',
        category: 'passwords',
        pinned: 1,
        views: 342,
        ago: 60 * 24 * 6,
        body: 'Длинная парольная фраза из 4–5 случайных слов почти всегда надёжнее короткого «P@ssw0rd123»: её сложнее подобрать и легче запомнить. Главное правило — не брать слова из одной песни или цитаты и не использовать одну фразу везде.\n\nВопрос к сообществу: где вы храните такие фразы — держите в голове, в менеджере паролей или записываете на бумаге?',
        replies: [
          { ago: 60 * 24 * 5, body: 'Держу всё в менеджере паролей, в голове только одна мастер-фраза. Мозг честно не удержит 40 разных фраз, и это нормально.' },
          { ago: 60 * 24 * 4, body: 'Совет для запоминания: возьмите 4 случайных слова и свяжите их в нелепую картинку. Абсурдные образы держатся в памяти гораздо дольше осмысленных.' }
        ]
      },
      {
        title: 'Письмо «ваша карта заблокирована» — это фишинг?',
        category: 'phishing',
        pinned: 0,
        views: 198,
        ago: 60 * 24 * 5,
        body: 'Пришло письмо от «банка»: «Ваша карта заблокирована, перейдите по ссылке и подтвердите данные». Обратный адрес выглядит странно, в письме просят полный номер карты и CVV.\n\nНасколько это типичная схема и что делать, если я уже успел ввести номер карты?',
        replies: [
          { ago: 60 * 24 * 5 + 30, body: 'Классический фишинг. Банк никогда не спрашивает CVV и код из SMS в письме или по ссылке. Если данные уже ввели — сразу звоните в банк по номеру с обратной стороны карты, блокируйте карту и меняйте пароль в интернет-банке.' }
        ]
      },
      {
        title: 'Насколько опасен публичный Wi-Fi в кафе?',
        category: 'networks',
        pinned: 0,
        views: 274,
        ago: 60 * 24 * 3,
        body: 'Часто работаю из кафе и подключаюсь к открытым сетям. Знакомый говорит, что так можно потерять пароли. Что реально угрожает в публичном Wi-Fi и достаточно ли HTTPS, чтобы не переживать?',
        replies: [
          { ago: 60 * 24 * 3 - 20, body: 'С HTTPS трафик шифруется, и подменить содержимое сайта уже сложно. Но остаются поддельные точки доступа с похожим именем и перехват DNS. Проверяйте адрес и замок в строке браузера, не входите в банк из кафе и включите VPN, если сеть совсем чужая.' },
          { ago: 60 * 24 * 2, body: 'Ещё полезно отключить автоподключение к открытым сетям — иначе телефон сам цепляется к «Free_WiFi» мошенника.' }
        ]
      },
      {
        title: 'Приватность в соцсетях: что действительно стоит скрывать',
        category: 'privacy',
        pinned: 0,
        views: 156,
        ago: 60 * 24 * 2,
        body: 'Пытаюсь сократить цифровой след: закрыл профиль, убрал геометки. Что ещё реально влияет на приватность, а что лишь создаёт ощущение безопасности?',
        replies: [
          { ago: 60 * 24 * 2 - 15, body: 'Самое ценное — список контактов и переписка: по ним строят схемы «мама, я попал в беду». Ещё проверьте, какие приложения имеют доступ к фото и микрофону, и отзовите лишние разрешения.' }
        ]
      },
      {
        title: 'Помогите новичку: с чего начать защиту аккаунтов',
        category: 'help',
        pinned: 0,
        views: 89,
        ago: 60 * 24 * 1,
        body: 'Мне 52 года, недавно начал пользоваться интернет-банком и почтой. С чего начать, чтобы не наделать ошибок? Слишком много советов сразу, хочется простой план на неделю.',
        replies: [
          { ago: 60 * 24 * 1 - 40, body: 'План на неделю: 1) включите двухэтапную проверку в почте и банке; 2) поставьте менеджер паролей и смените пароль на почте на уникальный; 3) проверьте, есть ли резервные коды восстановления, и распечатайте их. Этого уже хватит, чтобы отбить большинство атак.' },
          { ago: 60 * 24 * 1 - 90, body: 'И правило на каждый день: код из SMS не сообщаем никому — ни «сотруднику банка», ни «родственнику». Банк код не спрашивает никогда.' }
        ]
      }
    ];

    for (const t of seedTopics) {
      const topicId = newId();
      const created = isoAgo(t.ago);
      run(
        'INSERT INTO topics (id, title, body, category, author_id, author_name, pinned, locked, views, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)',
        topicId, t.title, t.body, t.category, admin.id, admin.name, t.pinned, t.views, created, created
      );
      let last = created;
      for (const r of t.replies) {
        last = isoAgo(r.ago);
        run(
          'INSERT INTO posts (id, topic_id, author_id, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?)',
          newId(), topicId, admin.id, admin.name, r.body, last
        );
      }
      run('UPDATE topics SET updated_at = ? WHERE id = ?', last, topicId);
    }
  }

  // Десять записей реестра опасностей
  if (count('threats') === 0) {
    const base = Date.now();
    const threats = [
      {
        title: 'Поддельные зеркала Госуслуг',
        severity: 'high', type: 'site', example: 'gosuslugi-online.ru',
        description: 'Клоны портала с почти настоящим дизайном просят СНИЛС, паспорт и код из SMS «для входа». Данные сразу уходят мошенникам, а аккаунт на настоящем портале пытаются перехватить.'
      },
      {
        title: 'Письмо «карта заблокирована» с вложением',
        severity: 'high', type: 'practice', example: 'Письмо от «банка» с файлом card_block.html',
        description: 'Фишинговое письмо требует срочно «подтвердить данные карты» по ссылке или во вложенном файле. Банк никогда не запрашивает CVV и коды из SMS в письмах и по телефону.'
      },
      {
        title: '«Бесплатный» VPN из неизвестного магазина',
        severity: 'high', type: 'app', example: 'SuperFreeVPN.apk',
        description: 'Такие приложения получают полный доступ к трафику и часто перепродают его третьим лицам. Ставьте VPN только из официальных магазинов и от известных разработчиков.'
      },
      {
        title: 'Один пароль на все сервисы',
        severity: 'high', type: 'practice', example: 'password123 в почте, банке и на форуме',
        description: 'После утечки одного сайта злоумышленник подставляет ту же пару логин/пароль в банк и почту. У каждого важного сервиса должен быть свой уникальный пароль.'
      },
      {
        title: 'Открытый Wi-Fi без проверки HTTPS',
        severity: 'medium', type: 'practice', example: 'Сеть «Free_Cafe_WiFi»',
        description: 'В открытых сетях возможны поддельные точки доступа и перехват трафика. Не входите в банк из кафе, проверяйте замок и адрес в браузере, при сомнениях используйте VPN.'
      },
      {
        title: 'Сайты «проверки утечек» по номеру телефона',
        severity: 'medium', type: 'site', example: 'proverka-utechek.info',
        description: 'Сервис просит телефон и пароль «для проверки», а на деле собирает данные для взлома. Проверять утечки стоит только в известных сервисах и без ввода паролей.'
      },
      {
        title: 'Фейковый клиент мессенджера',
        severity: 'medium', type: 'app', example: 'Telegram-Premium-Mod.apk',
        description: 'Неофициальные сборки мессенджеров перехватывают переписку и коды входа. Скачивайте приложение только с официального сайта или из магазина приложений.'
      },
      {
        title: 'Ссылки на «розыгрыш билетов» в соцсетях',
        severity: 'medium', type: 'site', example: 'vk-promo-bilety.ru',
        description: 'Яркая страница розыгрыша требует авторизоваться через соцсеть или ввести данные карты «для оплаты доставки». Это сбор данных и подписки на платные услуги.'
      },
      {
        title: 'Скриншоты паспорта и карт в облаке',
        severity: 'low', type: 'practice', example: 'Папка «Документы» в общем доступе',
        description: 'Фото документов в облаке с открытой ссылкой легко находят поисковые системы. Храните сканы в защищённом хранилище и удаляйте, когда они больше не нужны.'
      },
      {
        title: 'Браузерные «ускорители интернета»',
        severity: 'low', type: 'app', example: 'Расширение «Турбо-кнопка»',
        description: 'Сомнительные расширения читают содержимое всех страниц, включая формы оплаты. Держите включёнными только те дополнения, которыми реально пользуетесь.'
      }
    ];
    threats.forEach((th, i) => {
      run(
        'INSERT INTO threats (id, title, description, severity, type, example, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        newId(), th.title, th.description, th.severity, th.type, th.example, new Date(base - i * 3600000).toISOString()
      );
    });
  }
}

seed();

module.exports = {
  DB_PATH,
  db,
  q: { run, get, all, count },
  nowIso,
  newId,
  getUserById,
  getUserByEmail,
};
