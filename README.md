# BDU Domain Analyzer

Веб-панель для аналитики ИБ целевого домена: базовые проверки DNS/HTTP/TLS, поиск типовых чувствительных путей, адаптеры внешних сканеров из практикума и обогащение результатов через локальную БДУ ФСТЭК России.

## Что найдено в практикуме

В практикуме исследуются классификации OWASP Top 10, CVE, CWE, CAPEC и БДУ ФСТЭК, а также группы БДУ: W01 ввод данных, W02 доступ и защита данных, W03 структуры данных, W04 аутентификация, W05 ресурсы.

Инструменты: OpenVAS/Greenbone, SonarQube, Burp Suite, Wfuzz, Prometheus, SQLMap, XSS-практика и OWASP Juice Shop, Metasploit/Nmap, SkipFish, Legion, JMeter и DDoS-раздел. Для доменов/сайтов применимы OpenVAS, Burp Suite, Wfuzz, SQLMap по конкретным URL, Nmap, SkipFish, Legion, Nikto, WhatWeb, SSLyzer/SSLScan и Wapiti из соседнего проекта. Для поддоменов явно подходит Wfuzz; в этом проекте также есть встроенный DNS-перебор небольшого словаря.

## Запуск

```bash
python3 app.py
```

Откройте `http://127.0.0.1:5059`.

Базовый профиль работает без внешних зависимостей. Активный профиль запускает выбранные CLI-сканеры, только если они установлены: `nmap`, `wapiti`, `wfuzz`, `whatweb`, `nikto`, `sqlmap`. Wapiti также ищется в старом проекте `/Users/evgenijasakov/Wapiti_Gui/Сканер + БДУ/wapiti_scan /.venv/bin/wapiti`.

Если часть CLI не установлена, приложение не ломается:

- `Wfuzz` заменяется встроенным `Wfuzz-lite` для словарного поиска путей;
- `WhatWeb` заменяется встроенным `WhatWeb-lite` для fingerprint веб-технологий;
- `Nikto` заменяется встроенным `Nikto-lite` с безопасными GET-проверками известных служебных endpoints;
- `Nmap` при таймауте заменяется быстрым TCP socket-сканом популярных портов;
- `Wapiti` подключён как полноценный локальный сканер через найденный бинарь Wapiti 3.2.3.
- `OpenVAS / Greenbone` заменяется встроенным `OpenVAS-lite` сетевым baseline;
- `Burp Suite` заменяется встроенным `Burp-lite` для пассивной карты сайта, форм и CSRF-эвристик;
- `SkipFish` заменяется встроенным `SkipFish-lite` для безопасного web-crawl;
- `Legion` заменяется встроенным `Legion-lite`, который оркестрирует socket scan, fingerprint и web exposure checks.

## XSS/SQL-инъекции

Для проверки XSS и SQL-инъекций включите блок `XSS/SQLi и авторизованный режим`:

- `Глубокая проверка XSS/SQL-инъекций` автоматически включает активный профиль, Wapiti, SQLMap и Burp-lite;
- `Cookie авторизованной сессии` передаётся во встроенные HTTP-проверки, Wapiti и SQLMap;
- `Authorization или полный HTTP-заголовок` можно указать как `Bearer ...` или как `Authorization: Bearer ...`;
- `Raw HTTP-запрос для SQLMap` позволяет проверить конкретный запрос с параметрами, формой или API endpoint.

Секреты не попадают в HTML/JSON-отчёт. Для Wapiti session/config используются временные каталоги системы, а raw-запрос SQLMap удаляется после запуска.

## Сессии и шифрование

Базовый профиль также проверяет признаки, которые повышают риск перехвата или угона сессии:

- недоверенный, самоподписанный или просроченный TLS-сертификат;
- согласованную версию TLS и слабые cipher suites, если их удалось определить;
- отсутствие HSTS;
- cookie без `Secure`, `HttpOnly`, `SameSite`;
- нарушение префиксов cookie `__Host-` и `__Secure-`;
- отправку форм на `http://`;
- mixed content на HTTPS-странице;
- похожие на session/token/auth параметры в URL;
- кэширование авторизованных страниц при проверке с cookie/header.

Эти проверки не перехватывают трафик и не атакуют пользователя. Они показывают конфигурации, при которых перехват в реальной сети или утечка сессии становятся более вероятными.

Официальные исходники анализаторов:

- Wapiti: https://github.com/wapiti-scanner/wapiti
- Nmap: https://github.com/nmap/nmap
- SQLMap: https://github.com/sqlmapproject/sqlmap
- Wfuzz: https://github.com/xmendez/wfuzz
- WhatWeb: https://github.com/urbanadventurer/WhatWeb
- Nikto: https://github.com/sullo/nikto
- Greenbone/OpenVAS: https://github.com/greenbone/openvas-scanner
- Legion: https://github.com/GoVanguard/legion

Целиком вендорить эти проекты внутрь приложения не стоит: у них разные языки, лицензии, зависимости и режимы обновления. В проекте выбран более поддерживаемый вариант: адаптеры к CLI плюс собственные безопасные fallback-проверки.

## БДУ ФСТЭК

В `data/bdu.db` уже перенесена локальная база из проекта Wapiti Gui. Найденные CVE сопоставляются с БДУ напрямую, а находки без CVE получают контекст по CWE.

Для обновления базы положите XML/OVAL-файлы в `data/bdu_xml/` и выполните:

```bash
python3 -c "from bdu_analyzer.bdu import BDUHandler; print(BDUHandler().import_all_xml())"
```

## Результаты

Каждый запуск сохраняет отчёты в `reports/`:

- `scan_<id>.json` — структурированные данные;
- `scan_<id>.html` — автономная HTML-версия отчёта.

Сканируйте только свои домены или цели, на проверку которых у вас есть разрешение.
