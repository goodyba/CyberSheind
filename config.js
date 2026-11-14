/* CyberShield — конфигурация фронтенда.
   apiBase:
     ''  — автоопределение: если страница открыта с того же сервера, что и API
           (http(s)://host/ → /api/...), используется серверный режим с общей
           базой и настоящими письмами. Если API нет (GitHub Pages, file://),
           сайт работает в локальном демо-режиме на localStorage.
     'https://api.example.com' — явный адрес API (например, когда фронтенд
           лежит на GitHub Pages, а сервер — отдельно).
   Внимание: адрес API должен быть без завершающего слэша. */
window.CYBERSHIELD_CONFIG = {
  apiBase: '',
  siteName: 'CyberShield'
};
