/* ============================================================================
   CyberShield — клиент API.

   Одна и та же сборка работает в двух режимах:
     • server — рядом есть backend (/api/health отвечает): общая база SQLite,
                настоящие письма с кодом, общий форум для всех посетителей;
     • local  — backend недоступен (GitHub Pages, file://): всё хранится в
                localStorage браузера, код показывается на странице.

   Решение принимается один раз при загрузке через detect().
   ========================================================================= */
(function () {
  'use strict';

  var cfg = window.CYBERSHIELD_CONFIG || {};
  var TOKEN_KEY = 'cybershield:token:v1';
  var memoryToken = '';

  var state = {
    base: '',
    server: false,
    mailer: 'console',
    checked: false
  };

  /* --- Токен сессии: localStorage, а при его недоступности — память ------- */
  function readToken() {
    try {
      return window.localStorage.getItem(TOKEN_KEY) || '';
    } catch (error) {
      return memoryToken;
    }
  }

  function writeToken(value) {
    memoryToken = value || '';
    try {
      if (value) window.localStorage.setItem(TOKEN_KEY, value);
      else window.localStorage.removeItem(TOKEN_KEY);
    } catch (error) {
      /* хранилище недоступно — токен останется в памяти до перезагрузки */
    }
  }

  function resolveBase() {
    var configured = String(cfg.apiBase || '').trim().replace(/\/+$/, '');
    if (configured) return configured;
    if (location.protocol === 'file:') return '';
    return location.origin;
  }

  function apiError(message, status, payload) {
    var error = new Error(message || 'Ошибка запроса');
    error.status = status || 0;
    error.payload = payload || null;
    return error;
  }

  /* Универсальный запрос с таймаутом и разбором JSON-ошибок сервера. */
  async function request(path, options) {
    var opts = options || {};
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = controller ? window.setTimeout(function () { controller.abort(); }, opts.timeout || 15000) : null;

    var headers = { Accept: 'application/json' };
    if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    var token = readToken();
    if (token) headers.Authorization = 'Bearer ' + token;

    var response;
    try {
      response = await fetch(state.base + path, {
        method: opts.method || 'GET',
        headers: headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        cache: 'no-store',
        signal: controller ? controller.signal : undefined
      });
    } catch (error) {
      if (timer) window.clearTimeout(timer);
      throw apiError('Сервер не отвечает. Проверьте соединение.', 0, null);
    } finally {
      if (timer) window.clearTimeout(timer);
    }

    var payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }

    if (!response.ok) {
      var message = payload && payload.error ? payload.error : 'Ошибка ' + response.status;
      throw apiError(message, response.status, payload);
    }
    return payload || {};
  }

  /* --- Определение режима ------------------------------------------------ */
  async function detect() {
    state.base = resolveBase();
    state.checked = true;
    state.server = false;

    if (!state.base) return false;

    try {
      var health = await request('/api/health', { timeout: 4000 });
      if (health && health.ok) {
        state.server = true;
        state.mailer = health.mailer === 'smtp' ? 'smtp' : 'console';
        return true;
      }
    } catch (error) {
      state.server = false;
    }
    return false;
  }

  function devicePayload(device) {
    return {
      deviceId: String((device && device.deviceId) || ''),
      deviceLabel: String((device && device.deviceLabel) || ''),
      ip: (device && device.ip) || null
    };
  }

  window.CS_API = {
    isServer: function () { return state.server; },
    isChecked: function () { return state.checked; },
    mailer: function () { return state.mailer; },
    base: function () { return state.base; },
    detect: detect,
    token: readToken,
    clearToken: function () { writeToken(''); },
    devicePayload: devicePayload,

    /* --- Аккаунты ------------------------------------------------------- */
    register: function (data) {
      return request('/api/auth/register', {
        method: 'POST',
        body: {
          name: data.name,
          email: data.email,
          password: data.password,
          device: devicePayload(data.device)
        }
      });
    },

    verifyRegistration: function (pendingToken, code) {
      return request('/api/auth/register/verify', {
        method: 'POST',
        body: { pendingToken: pendingToken, code: code }
      }).then(function (result) {
        if (result && result.token) writeToken(result.token);
        return result;
      });
    },

    login: function (data) {
      return request('/api/auth/login', {
        method: 'POST',
        body: {
          email: data.email,
          password: data.password,
          device: devicePayload(data.device)
        }
      }).then(function (result) {
        if (result && result.token) writeToken(result.token);
        return result;
      });
    },

    verifyLogin: function (challengeToken, code) {
      return request('/api/auth/login/verify', {
        method: 'POST',
        body: { challengeToken: challengeToken, code: code }
      }).then(function (result) {
        if (result && result.token) writeToken(result.token);
        return result;
      });
    },

    resend: function (challengeToken) {
      return request('/api/auth/resend', {
        method: 'POST',
        body: { challengeToken: challengeToken }
      });
    },

    me: function () {
      if (!readToken()) return Promise.resolve(null);
      return request('/api/auth/me').then(function (result) {
        return result && result.user ? result.user : null;
      }).catch(function () {
        return null;
      });
    },

    logout: function () {
      var done = function () { writeToken(''); };
      return request('/api/auth/logout', { method: 'POST' }).then(done, done);
    },

    saveResult: function (result) {
      return request('/api/results', { method: 'POST', body: result });
    },

    /* --- Форум ---------------------------------------------------------- */
    forum: {
      list: function () {
        return request('/api/forum').then(function (r) { return r.topics || []; });
      },
      createTopic: function (data) {
        return request('/api/forum/topics', { method: 'POST', body: data });
      },
      addPost: function (topicId, body) {
        return request('/api/forum/topics/' + encodeURIComponent(topicId) + '/posts', {
          method: 'POST',
          body: { body: body }
        });
      },
      updateTopic: function (topicId, patch) {
        return request('/api/forum/topics/' + encodeURIComponent(topicId), {
          method: 'PATCH',
          body: patch
        });
      },
      removeTopic: function (topicId) {
        return request('/api/forum/topics/' + encodeURIComponent(topicId), { method: 'DELETE' });
      },
      removePost: function (topicId, postId) {
        return request('/api/forum/topics/' + encodeURIComponent(topicId) + '/posts/' + encodeURIComponent(postId), {
          method: 'DELETE'
        });
      }
    },

    /* --- Реестр опасностей ---------------------------------------------- */
    threats: {
      list: function () {
        return request('/api/threats').then(function (r) { return r.threats || []; });
      },
      create: function (data) {
        return request('/api/threats', { method: 'POST', body: data });
      },
      remove: function (id) {
        return request('/api/threats/' + encodeURIComponent(id), { method: 'DELETE' });
      }
    },

    /* --- Админка -------------------------------------------------------- */
    admin: {
      users: function () {
        return request('/api/admin/users').then(function (r) { return r.users || []; });
      },
      security: function () {
        return request('/api/admin/security').then(function (r) { return r.log || []; });
      }
    }
  };
})();
