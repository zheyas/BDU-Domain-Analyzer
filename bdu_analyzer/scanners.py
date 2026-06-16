# -*- coding: utf-8 -*-

import json
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .bdu import BDUHandler, extract_cves
from .config import (
    EXTERNAL_TIMEOUTS,
    LEGACY_WAPITI_BIN,
    MAX_HTML_BYTES,
    REPORTS_DIR,
    REQUEST_TIMEOUT,
    WORDLIST_DIR,
)
from .models import Finding, ScanContext, ScanReport, ToolStatus
from .target import base_url, safe_filename


COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "api",
    "app",
    "admin",
    "dev",
    "test",
    "stage",
    "staging",
    "beta",
    "portal",
    "vpn",
    "sso",
    "cdn",
    "static",
    "files",
    "docs",
    "blog",
    "shop",
    "m",
]

INTERESTING_PATHS = [
    "/admin/",
    "/login",
    "/wp-admin/",
    "/phpinfo.php",
    "/server-status",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/robots.txt",
    "/.well-known/security.txt",
]

COMMON_TCP_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

NIKTO_LITE_PATHS = [
    "/manager/html",
    "/phpmyadmin/",
    "/adminer.php",
    "/actuator/env",
    "/actuator/heapdump",
    "/solr/",
    "/debug/default/view",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/.svn/entries",
    "/.hg/",
    "/config.php~",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/cgi-bin/",
]

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"generator\" content=\"WordPress"],
    "Bitrix": [r"/bitrix/", r"BITRIX_SM", r"1c-bitrix"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Django": [r"csrftoken", r"django"],
    "React": [r"react", r"__REACT_DEVTOOLS"],
    "Vue.js": [r"vue", r"data-v-"],
    "Angular": [r"ng-version", r"ng-app"],
    "Bootstrap": [r"bootstrap"],
    "jQuery": [r"jquery"],
}


def discover_tools(selected: set[str] | None = None) -> list[ToolStatus]:
    selected = selected or set()
    tools = [
        _tool("nmap", "nmap", "optional", "Сетевые порты и версии сервисов. Если Nmap зависнет, включится socket fallback.", selected),
        _tool("wapiti", "wapiti", "optional", "DAST веб-приложений; найден локальный Wapiti используется автоматически.", selected),
        _tool_with_fallback("Wfuzz", "wfuzz", "Фаззинг каталогов и URL через словарь.", "встроенный Wfuzz-lite", selected),
        _tool_with_fallback("WhatWeb", "whatweb", "Фингерпринт технологий веб-сайта.", "встроенный WhatWeb-lite", selected),
        _tool_with_fallback("Nikto", "nikto", "Проверка веб-сервера на известные misconfiguration.", "встроенный Nikto-lite", selected),
        _tool("sqlmap", "sqlmap", "active", "SQL-инъекции; запускается только при активном профиле.", selected),
        _platform_with_fallback("OpenVAS / Greenbone", "openvas", ["gvm-cli", "openvas"], "Сетевой baseline и поиск рискованных сервисов.", "встроенный OpenVAS-lite", selected),
        _platform_with_fallback("Burp Suite", "burp", ["burpsuite"], "Пассивная карта сайта, формы и первичная web-аудитика.", "встроенный Burp-lite", selected),
        _platform_with_fallback("SkipFish", "skipfish", ["skipfish"], "Активная карта сайта и web-crawl.", "встроенный SkipFish-lite", selected),
        _platform_with_fallback("Legion", "legion", ["legion"], "Оркестрация сетевых и web-проверок.", "встроенный Legion-lite", selected),
    ]
    return tools


def run_assessment(ctx: ScanContext, bdu: BDUHandler) -> ScanReport:
    start = time.time()
    notes: list[str] = []
    assets: dict[str, Any] = {
        "dns": {},
        "subdomains": [],
        "http": {},
        "tls": {},
        "paths": [],
        "external_reports": [],
        "scan_context": {
            "active_mode": ctx.active_mode,
            "injection_profile": ctx.injection_profile,
            "auth_cookie_provided": bool(ctx.auth_cookie),
            "auth_header_provided": bool(ctx.auth_header),
            "raw_request_provided": bool(ctx.raw_request),
        },
    }
    findings: list[Finding] = []
    if ctx.injection_profile:
        notes.append("Включён профиль XSS/SQLi: Wapiti и SQLMap запускаются с расширенными параметрами проверки.")
    if ctx.auth_cookie or ctx.auth_header:
        notes.append("Авторизационные данные переданы сканерам и встроенным HTTP-проверкам; секреты не сохраняются в отчёт.")
    if ctx.raw_request:
        notes.append("SQLMap использует raw HTTP-запрос как основную цель проверки параметров.")

    builtins = [
        DNSAnalyzer(),
        HTTPAnalyzer(),
        TokenExposureAnalyzer(),
        TLSAnalyzer(),
        DirectoryProbeAnalyzer(),
    ]
    for analyzer in builtins:
        result = analyzer.run(ctx)
        assets.update(_deep_merge(assets, result.get("assets", {})))
        findings.extend(result.get("findings", []))
        notes.extend(result.get("notes", []))

    external_map = {
        "nmap": NmapAdapter(),
        "wapiti": WapitiAdapter(),
        "wfuzz": WfuzzAdapter(),
        "whatweb": WhatWebAdapter(),
        "nikto": NiktoAdapter(),
        "sqlmap": SQLMapAdapter(),
        "openvas": OpenVASAdapter(),
        "burp": BurpAdapter(),
        "skipfish": SkipFishAdapter(),
        "legion": LegionAdapter(),
    }
    if ctx.active_mode:
        for key in sorted(ctx.selected_tools):
            adapter = external_map.get(key)
            if not adapter:
                continue
            result = adapter.run(ctx)
            assets.update(_deep_merge(assets, result.get("assets", {})))
            findings.extend(result.get("findings", []))
            result_notes = result.get("notes", [])
            notes.extend(result_notes)
            if not result_notes and not result.get("findings", []):
                notes.append(f"{adapter.label}: выполнен, новых находок не добавил.")
    elif ctx.selected_tools:
        notes.append("Внешние активные сканеры не запускались: включите активный профиль проверки.")

    findings = normalize_findings(findings)
    enriched = [bdu.enrich(item) for item in findings]
    enriched.sort(key=lambda item: (severity_rank(item.severity), item.title), reverse=True)
    return ScanReport(
        scan_id=ctx.scan_id,
        target_url=ctx.target_url,
        host=ctx.host,
        generated_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        duration_seconds=round(time.time() - start, 2),
        findings=enriched,
        assets=assets,
        tool_statuses=discover_tools(ctx.selected_tools),
        bdu_stats=bdu.stats(),
        notes=notes,
    )


class DNSAnalyzer:
    def run(self, ctx: ScanContext) -> dict[str, Any]:
        records = {
            "A": dig_records(ctx.host, "A"),
            "AAAA": dig_records(ctx.host, "AAAA"),
            "MX": dig_records(ctx.host, "MX"),
            "NS": dig_records(ctx.host, "NS"),
            "TXT": dig_records(ctx.host, "TXT"),
            "DMARC": dig_records(f"_dmarc.{ctx.host}", "TXT"),
        }
        findings: list[Finding] = []

        if not records["A"] and not records["AAAA"]:
            findings.append(
                Finding(
                    "Домен не разрешается в A/AAAA записи",
                    "Высокий",
                    "DNS",
                    "Built-in DNS",
                    "Целевой домен не удалось разрешить в IP-адреса. Для публичного сайта это означает недоступность или ошибку DNS.",
                    evidence=ctx.host,
                    remediation="Проверьте зону DNS, NS-серверы и актуальность A/AAAA записей.",
                    cwe=["CWE-350"],
                )
            )

        txt_joined = " ".join(records["TXT"]).lower()
        if records["MX"] and "v=spf1" not in txt_joined:
            findings.append(
                Finding(
                    "Для почтового домена не найден SPF",
                    "Низкий",
                    "DNS email security",
                    "Built-in DNS",
                    "У домена есть MX-записи, но в TXT не найден SPF. Это повышает риск spoofing-писем от имени домена.",
                    evidence=", ".join(records["MX"]),
                    remediation="Добавьте SPF TXT-запись с перечнем разрешённых отправителей.",
                    cwe=["CWE-345"],
                )
            )
        if records["MX"] and not any("v=dmarc1" in value.lower() for value in records["DMARC"]):
            findings.append(
                Finding(
                    "Для почтового домена не найден DMARC",
                    "Низкий",
                    "DNS email security",
                    "Built-in DNS",
                    "У домена есть MX-записи, но не обнаружена политика DMARC.",
                    evidence=f"_dmarc.{ctx.host}",
                    remediation="Опубликуйте DMARC TXT-запись и постепенно ужесточайте p=none до quarantine/reject.",
                    cwe=["CWE-345"],
                )
            )

        subdomains = []
        for label in COMMON_SUBDOMAINS:
            name = f"{label}.{ctx.host}"
            a = dig_records(name, "A")
            cname = dig_records(name, "CNAME")
            if a or cname:
                subdomains.append({"host": name, "a": a, "cname": cname})
                if label in {"admin", "dev", "test", "stage", "staging"}:
                    findings.append(
                        Finding(
                            f"Найден служебный поддомен {name}",
                            "Инфо",
                            "Subdomain discovery",
                            "Built-in DNS",
                            "Служебные поддомены расширяют поверхность атаки и требуют такой же защиты, как основной сайт.",
                            evidence=", ".join(a + cname),
                            remediation="Проверьте доступность, аутентификацию и обновления сервисов на поддомене.",
                            cwe=["CWE-200"],
                        )
                    )

        return {"assets": {"dns": records, "subdomains": subdomains}, "findings": findings, "notes": []}


class HTTPAnalyzer:
    def run(self, ctx: ScanContext) -> dict[str, Any]:
        findings: list[Finding] = []
        http_info: dict[str, Any] = {}
        headers = scan_headers(ctx)
        response = fetch(ctx.target_url, "GET", headers=headers)
        if response.get("error"):
            findings.append(
                Finding(
                    "HTTP-цель недоступна",
                    "Средний",
                    "Availability",
                    "Built-in HTTP",
                    "Не удалось получить HTTP-ответ от целевого адреса.",
                    evidence=response["error"],
                    remediation="Проверьте доступность сайта, DNS, TLS и сетевые ACL.",
                    cwe=["CWE-400"],
                )
            )
            return {"assets": {"http": response}, "findings": findings, "notes": []}

        headers = response.get("headers", {})
        body = response.get("body", "")
        http_info.update(response)
        http_info["title"] = extract_title(body)
        http_info["forms"] = extract_forms(body, response.get("final_url") or ctx.target_url)
        http_info["mixed_content"] = find_mixed_content(body, response.get("final_url") or ctx.target_url)
        http_info["session_tokens_in_urls"] = find_session_tokens_in_urls(body, response.get("final_url") or ctx.target_url, ctx.host)
        if response.get("tls_verification_bypassed"):
            findings.append(
                Finding(
                    "HTTP-анализ выполнен без проверки TLS-сертификата",
                    "Инфо",
                    "Scan diagnostics",
                    "Built-in HTTP",
                    "Сертификат не прошёл доверенную проверку, поэтому содержимое страницы было получено в диагностическом режиме без проверки цепочки.",
                    evidence=response.get("verify_error", ""),
                    remediation="Исправьте доверенную цепочку сертификата. После этого повторите сканирование в обычном режиме.",
                    cwe=["CWE-295"],
                )
            )

        findings.extend(analyze_transport_and_session(ctx, response, http_info))

        parsed = urlparse(ctx.target_url)
        if parsed.scheme == "http":
            final_url = response.get("final_url", "")
            if not final_url.startswith("https://"):
                findings.append(
                    Finding(
                        "HTTP не перенаправляется на HTTPS",
                        "Средний",
                        "Transport security",
                        "Built-in HTTP",
                        "Страница доступна по незашифрованному HTTP без автоматического перехода на HTTPS.",
                        evidence=final_url or ctx.target_url,
                        remediation="Настройте 301/308 редирект на HTTPS для всего сайта.",
                        cwe=["CWE-319"],
                    )
                )

        security_headers = {
            "strict-transport-security": (
                "Отсутствует HSTS",
                "Средний",
                "Добавьте Strict-Transport-Security для HTTPS-сайта.",
                "CWE-319",
            ),
            "content-security-policy": (
                "Отсутствует Content-Security-Policy",
                "Средний",
                "Добавьте CSP с ограничением источников скриптов, стилей и фреймов.",
                "CWE-693",
            ),
            "x-frame-options": (
                "Не задана защита от clickjacking",
                "Низкий",
                "Добавьте X-Frame-Options или CSP frame-ancestors.",
                "CWE-1021",
            ),
            "x-content-type-options": (
                "Не запрещён MIME sniffing",
                "Низкий",
                "Добавьте X-Content-Type-Options: nosniff.",
                "CWE-16",
            ),
            "referrer-policy": (
                "Не задан Referrer-Policy",
                "Низкий",
                "Добавьте Referrer-Policy, например strict-origin-when-cross-origin.",
                "CWE-200",
            ),
        }
        header_keys = {key.lower() for key in headers}
        for header, (title, severity, remediation, cwe) in security_headers.items():
            if header == "strict-transport-security" and not response.get("final_url", "").startswith("https://"):
                continue
            if header not in header_keys:
                findings.append(
                    Finding(
                        title,
                        severity,
                        "HTTP headers",
                        "Built-in HTTP",
                        f"В ответе не найден заголовок {header}.",
                        evidence=response.get("final_url") or ctx.target_url,
                        remediation=remediation,
                        cwe=[cwe],
                    )
                )

        server_header = headers.get("Server") or headers.get("server") or ""
        powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
        if re.search(r"/\d", server_header) or powered:
            findings.append(
                Finding(
                    "Сервер раскрывает технологические версии",
                    "Низкий",
                    "Information disclosure",
                    "Built-in HTTP",
                    "HTTP-заголовки раскрывают сервер или платформу. Это помогает сопоставлять цель с известными CVE.",
                    evidence="; ".join(item for item in [server_header, powered] if item),
                    remediation="Сократите баннеры Server/X-Powered-By и обновляйте раскрытые компоненты.",
                    cwe=["CWE-200"],
                )
            )

        for cookie in parse_set_cookies(response):
            missing = []
            lower = cookie.lower()
            if "httponly" not in lower:
                missing.append("HttpOnly")
            if response.get("final_url", "").startswith("https://") and "secure" not in lower:
                missing.append("Secure")
            if "samesite" not in lower:
                missing.append("SameSite")
            if "samesite=none" in lower and "secure" not in lower:
                missing.append("Secure для SameSite=None")
            if missing:
                findings.append(
                    Finding(
                        "Cookie без защитных флагов",
                        "Средний" if "HttpOnly" in missing or "Secure" in missing else "Низкий",
                        "Session security",
                        "Built-in HTTP",
                        "Одна из cookie установлена без полного набора защитных атрибутов.",
                        evidence=f"{cookie_name(cookie)}: отсутствует {', '.join(missing)}",
                        remediation="Добавьте HttpOnly, Secure и SameSite=Lax/Strict для сессионных cookie.",
                        cwe=["CWE-614", "CWE-1004"],
                    )
                )
            findings.extend(analyze_cookie_prefixes(cookie, response))

        if http_info["forms"]:
            password_forms = [form for form in http_info["forms"] if form.get("has_password")]
            if password_forms and not response.get("final_url", "").startswith("https://"):
                findings.append(
                    Finding(
                        "Форма пароля доступна без HTTPS",
                        "Высокий",
                        "Transport security",
                        "Built-in HTTP",
                        "На странице обнаружена форма пароля, а итоговый URL не использует HTTPS.",
                        evidence=", ".join(form.get("action", "") for form in password_forms[:3]),
                        remediation="Перенесите форму входа на HTTPS и включите Secure cookie.",
                        cwe=["CWE-319"],
                    )
                )

        return {"assets": {"http": http_info}, "findings": findings, "notes": []}


class TokenExposureAnalyzer:
    def run(self, ctx: ScanContext) -> dict[str, Any]:
        findings: list[Finding] = []
        assets: dict[str, Any] = {"api_token_checks": []}
        endpoint = urljoin(base_url(ctx.target_url) + "/", "api/v1/company/auth/getToken")
        response = post_json(endpoint, {}, headers={})
        safe_item = {
            "url": endpoint,
            "status": response.get("status"),
            "json_keys": [],
            "access_token_present": False,
            "access_token_length": 0,
        }
        data = response.get("json")
        if isinstance(data, dict):
            token = data.get("accessToken")
            safe_item.update(
                {
                    "json_keys": sorted(data.keys()),
                    "access_token_present": isinstance(token, str) and bool(token),
                    "access_token_length": len(token) if isinstance(token, str) else 0,
                    "level": data.get("level"),
                    "expiresAt": data.get("expiresAt"),
                }
            )
        elif response.get("error"):
            safe_item["error"] = response.get("error")
        assets["api_token_checks"].append(safe_item)

        if safe_item["access_token_present"]:
            findings.append(
                Finding(
                    "Публичный endpoint выдаёт API access token",
                    "Высокий",
                    "Authentication",
                    "Built-in API",
                    "Endpoint авторизации вернул accessToken на запрос без пользовательской авторизации. Такой токен может позволить обращаться к API от имени уровня, указанного в ответе.",
                    evidence=json.dumps(safe_item, ensure_ascii=False),
                    remediation="Закройте выдачу company-level token на публичном endpoint. Выпускайте токен только после проверки пользователя/сессии, ограничьте scope, TTL и аудит использования.",
                    cwe=["CWE-306", "CWE-287", "CWE-200"],
                    confidence="Высокая",
                )
            )
        return {"assets": assets, "findings": findings, "notes": []}


class TLSAnalyzer:
    def run(self, ctx: ScanContext) -> dict[str, Any]:
        findings: list[Finding] = []
        parsed = urlparse(ctx.target_url)
        if parsed.scheme != "https":
            return {"assets": {"tls": {"checked": False}}, "findings": findings, "notes": []}

        port = parsed.port or 443
        tls_info: dict[str, Any] = {"checked": True}
        try:
            ssl_ctx = ssl.create_default_context()
            with socket.create_connection((ctx.host, port), timeout=REQUEST_TIMEOUT) as sock:
                with ssl_ctx.wrap_socket(sock, server_hostname=ctx.host) as ssock:
                    cert = ssock.getpeercert()
                    tls_info["protocol"] = ssock.version()
                    tls_info["cipher"] = ssock.cipher()
                    tls_info["not_after"] = cert.get("notAfter")
                    tls_info["issuer"] = _name_tuple(cert.get("issuer", ()))
                    tls_info["subject"] = _name_tuple(cert.get("subject", ()))
                    if cert.get("notAfter"):
                        expires = ssl.cert_time_to_seconds(cert["notAfter"])
                        days_left = int((expires - time.time()) // 86400)
                        tls_info["days_left"] = days_left
                        if days_left < 0:
                            findings.append(
                                Finding(
                                    "TLS-сертификат истёк",
                                    "Высокий",
                                    "TLS",
                                    "Built-in TLS",
                                    "Сертификат сайта просрочен.",
                                    evidence=cert["notAfter"],
                                    remediation="Выпустите и установите новый сертификат.",
                                    cwe=["CWE-295"],
                                )
                            )
                        elif days_left < 14:
                            findings.append(
                                Finding(
                                    "TLS-сертификат скоро истечёт",
                                    "Средний",
                                    "TLS",
                                    "Built-in TLS",
                                    "До окончания срока действия сертификата осталось меньше 14 дней.",
                                    evidence=f"{days_left} дней",
                                    remediation="Продлите сертификат заранее и проверьте автоматическое обновление.",
                                    cwe=["CWE-295"],
                                )
                            )
                    if tls_info.get("issuer") and tls_info.get("issuer") == tls_info.get("subject"):
                        findings.append(
                            Finding(
                                "Похож на самоподписанный TLS-сертификат",
                                "Средний",
                                "TLS",
                                "Built-in TLS",
                                "Issuer и Subject сертификата совпадают.",
                                evidence=str(tls_info.get("subject")),
                                remediation="Используйте сертификат доверенного центра сертификации для публичного сайта.",
                                cwe=["CWE-295"],
                            )
                        )
                    findings.extend(analyze_tls_configuration(tls_info))
        except Exception as exc:
            tls_info["error"] = str(exc)
            fallback_info = collect_unverified_tls_info(ctx.host, port)
            if fallback_info:
                tls_info.update({f"unverified_{key}": value for key, value in fallback_info.items()})
                findings.extend(analyze_tls_configuration(fallback_info, unverified=True))
            exc_text = str(exc).lower()
            if "self-signed" in exc_text:
                title = "TLS-сертификат самоподписанный или не доверен"
                description = "Сертификат не подтверждён доверенной цепочкой. Для пользователей это обычно выглядит как предупреждение браузера о небезопасном соединении."
                remediation = "Установите сертификат от доверенного центра сертификации либо корректно разверните внутренний корневой сертификат для закрытого контура."
            else:
                title = "Ошибка проверки TLS"
                description = "Не удалось установить проверенное TLS-соединение."
                remediation = "Проверьте сертификат, цепочку доверия, SNI и доступность порта 443."
            findings.append(
                Finding(
                    title,
                    "Средний",
                    "TLS",
                    "Built-in TLS",
                    description,
                    evidence=str(exc),
                    remediation=remediation,
                    cwe=["CWE-295"],
                )
            )

        return {"assets": {"tls": tls_info}, "findings": findings, "notes": []}


class DirectoryProbeAnalyzer:
    def run(self, ctx: ScanContext) -> dict[str, Any]:
        findings: list[Finding] = []
        paths: list[dict[str, Any]] = []
        root = base_url(ctx.target_url)
        headers = scan_headers(ctx)
        missing_response = fetch(urljoin(root + "/", f"__bdu_probe_missing_{ctx.scan_id or int(time.time())}"), "GET", read_limit=50_000, headers=headers)

        for path in INTERESTING_PATHS:
            url = urljoin(root + "/", path.lstrip("/"))
            response = fetch(url, "GET", read_limit=50_000, headers=headers)
            status = response.get("status")
            if not status:
                continue
            body = response.get("body", "")
            soft_404_like = is_soft_404_response(response, missing_response)
            item = {
                "path": path,
                "url": url,
                "status": status,
                "length": len(body),
                "soft_404_like": soft_404_like,
            }
            paths.append(item)

            if path == "/.git/config" and status == 200 and "[core]" in body:
                findings.append(
                    Finding(
                        "Раскрыт .git/config",
                        "Критический",
                        "Sensitive files",
                        "Built-in path probe",
                        "Сайт отдаёт файл конфигурации Git из веб-корня.",
                        evidence=url,
                        remediation="Удалите .git из web-root, запретите доступ к скрытым файлам и проверьте утечки исходного кода.",
                        cwe=["CWE-200", "CWE-538"],
                    )
                )
            elif path == "/.env" and status == 200 and re.search(r"(PASSWORD|SECRET|TOKEN|KEY)=", body, re.I):
                findings.append(
                    Finding(
                        "Раскрыт .env с потенциальными секретами",
                        "Критический",
                        "Sensitive files",
                        "Built-in path probe",
                        "Сайт отдаёт .env-файл, похожий на файл с секретами приложения.",
                        evidence=url,
                        remediation="Немедленно закройте доступ, ротируйте секреты и проверьте журналы доступа.",
                        cwe=["CWE-200", "CWE-522"],
                    )
                )
            elif path in {"/backup.zip", "/backup.sql", "/db.sql"} and status == 200 and not soft_404_like:
                findings.append(
                    Finding(
                        f"Доступен потенциальный резервный файл {path}",
                        "Высокий",
                        "Sensitive files",
                        "Built-in path probe",
                        "По типичному имени найден файл резервной копии или дампа.",
                        evidence=url,
                        remediation="Удалите резервные копии из web-root и храните их в закрытом хранилище.",
                        cwe=["CWE-530"],
                    )
                )
            elif path == "/server-status" and status == 200 and not soft_404_like:
                findings.append(
                    Finding(
                        "Доступен server-status",
                        "Высокий",
                        "Information disclosure",
                        "Built-in path probe",
                        "Endpoint server-status доступен без явного ограничения.",
                        evidence=url,
                        remediation="Ограничьте server-status по IP или отключите модуль статуса на публичном интерфейсе.",
                        cwe=["CWE-200"],
                    )
                )
            elif path == "/phpinfo.php" and status == 200 and "phpinfo" in body.lower() and not soft_404_like:
                findings.append(
                    Finding(
                        "Доступна страница phpinfo",
                        "Высокий",
                        "Information disclosure",
                        "Built-in path probe",
                        "phpinfo раскрывает версии, пути, переменные окружения и конфигурацию PHP.",
                        evidence=url,
                        remediation="Удалите phpinfo.php с публичного сайта.",
                        cwe=["CWE-200"],
                    )
                )
            elif path in {"/admin/", "/login", "/wp-admin/"} and status in {200, 401, 403} and not soft_404_like:
                findings.append(
                    Finding(
                        f"Найдена административная или login-точка {path}",
                        "Инфо",
                        "Attack surface",
                        "Built-in path probe",
                        "Наличие точки входа не является уязвимостью само по себе, но увеличивает поверхность контроля.",
                        evidence=f"{url} -> HTTP {status}",
                        remediation="Проверьте MFA, rate limit, журналы входа и отсутствие учётных данных по умолчанию.",
                        cwe=["CWE-307"],
                    )
                )

        return {"assets": {"paths": paths}, "findings": findings, "notes": []}


class NmapAdapter:
    key = "nmap"
    label = "Nmap"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = shutil.which("nmap")
        if not path:
            findings, assets = socket_port_scan(ctx.host)
            return {
                "assets": {"nmap_fallback": assets},
                "findings": findings,
                "notes": ["Nmap не найден в PATH, использован встроенный socket-сканер портов."],
            }
        cmd = [
            path,
            "-Pn",
            "-T4",
            "-F",
            "--max-retries",
            "1",
            "--host-timeout",
            "45s",
            "--version-intensity",
            "2",
            "--open",
            "-sV",
            "-oX",
            "-",
            ctx.host,
        ]
        result = run_command(cmd, EXTERNAL_TIMEOUTS["nmap"])
        if result["returncode"] not in {0, 1}:
            findings, assets = socket_port_scan(ctx.host)
            return {
                "assets": {"nmap_fallback": assets},
                "findings": findings,
                "notes": [f"Nmap не успел завершиться, использован встроенный socket-сканер портов. Причина: {result['stderr'][:260]}"],
            }
        findings, assets = parse_nmap_xml(result["stdout"])
        return {"assets": {"nmap": assets}, "findings": findings, "notes": []}


class WapitiAdapter:
    key = "wapiti"
    label = "Wapiti"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_wapiti()
        if not path:
            return {"assets": {}, "findings": [], "notes": ["Wapiti не найден. Установите wapiti3 или добавьте бинарь в PATH."]}
        out = REPORTS_DIR / f"wapiti_{ctx.scan_id}.json"
        private_root = Path(tempfile.gettempdir()) / "bdu_analyzer_wapiti"
        session_dir = private_root / "sessions"
        config_dir = private_root / "config"
        session_dir.mkdir(parents=True, exist_ok=True)
        config_dir.mkdir(parents=True, exist_ok=True)
        max_links = "140" if ctx.injection_profile else "60"
        depth = "3" if ctx.injection_profile else "2"
        max_scan_time = "420" if ctx.injection_profile else "180"
        max_attack_time = "120" if ctx.injection_profile else "60"
        cmd = [
            path,
            "-u",
            ctx.target_url,
            "-m",
            "http_headers,cookieflags,csp,ssl,wapp,nikto,buster,backup,sql,xss",
            "-f",
            "json",
            "-o",
            str(out),
            "--scope",
            "folder",
            "--timeout",
            "10",
            "--max-links",
            max_links,
            "--depth",
            depth,
            "--max-scan-time",
            max_scan_time,
            "--max-attack-time",
            max_attack_time,
            "--store-session",
            str(session_dir),
            "--store-config",
            str(config_dir),
            "--flush-session",
            "--no-bugreport",
        ]
        if ctx.auth_cookie:
            cmd.extend(["--cookie-value", ctx.auth_cookie])
        header_value = cli_header_value(ctx.auth_header)
        if header_value:
            cmd.extend(["--header", header_value])
        if ctx.target_url.startswith("https://"):
            cmd.extend(["--verify-ssl", "0"])
        result = run_command(cmd, EXTERNAL_TIMEOUTS["wapiti"])
        if result["returncode"] != 0:
            return {"assets": {}, "findings": [], "notes": [f"Wapiti завершился с ошибкой: {redact_scan_secrets(result['stderr'][:500], ctx)}"]}
        findings = parse_wapiti_json(out)
        return {"assets": {"external_reports": [{"tool": "Wapiti", "path": str(out)}]}, "findings": findings, "notes": []}


class WfuzzAdapter:
    key = "wfuzz"
    label = "Wfuzz"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = shutil.which("wfuzz")
        if not path:
            findings, assets = builtin_content_discovery(ctx, WORDLIST_DIR / "web_common.txt")
            return {
                "assets": {"wfuzz_lite": assets},
                "findings": findings,
                "notes": ["Wfuzz не найден в PATH, использован встроенный словарный поиск путей."],
            }
        wordlist = WORDLIST_DIR / "web_common.txt"
        out = REPORTS_DIR / f"wfuzz_{ctx.scan_id}.json"
        fuzz_url = urljoin(base_url(ctx.target_url) + "/", "FUZZ")
        cmd = [
            path,
            "-w",
            str(wordlist),
            "--sc",
            "200,204,301,302,307,308,401,403,429",
            "-f",
            f"{out},json",
            fuzz_url,
        ]
        result = run_command(cmd, EXTERNAL_TIMEOUTS["wfuzz"])
        findings: list[Finding] = []
        if out.exists():
            findings.extend(parse_wfuzz_json(out))
        if result["returncode"] not in {0, 1}:
            return {"assets": {}, "findings": findings, "notes": [f"Wfuzz завершился с предупреждением: {result['stderr'][:300]}"]}
        return {"assets": {"external_reports": [{"tool": "Wfuzz", "path": str(out)}]}, "findings": findings, "notes": []}


class WhatWebAdapter:
    key = "whatweb"
    label = "WhatWeb"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = shutil.which("whatweb")
        if not path:
            findings, assets = builtin_technology_fingerprint(ctx)
            return {
                "assets": {"whatweb_lite": assets},
                "findings": findings,
                "notes": ["WhatWeb не найден в PATH, использован встроенный fingerprint веб-технологий."],
            }
        out = REPORTS_DIR / f"whatweb_{ctx.scan_id}.json"
        cmd = [path, "--log-json", str(out), ctx.target_url]
        result = run_command(cmd, EXTERNAL_TIMEOUTS["whatweb"])
        if result["returncode"] != 0:
            return {"assets": {}, "findings": [], "notes": [f"WhatWeb завершился с ошибкой: {result['stderr'][:300]}"]}
        return {"assets": {"whatweb": read_json_file(out), "external_reports": [{"tool": "WhatWeb", "path": str(out)}]}, "findings": [], "notes": []}


class NiktoAdapter:
    key = "nikto"
    label = "Nikto"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = shutil.which("nikto")
        if not path:
            findings, assets = builtin_nikto_lite(ctx)
            return {
                "assets": {"nikto_lite": assets},
                "findings": findings,
                "notes": ["Nikto не найден в PATH, использован встроенный Nikto-like набор безопасных GET-проверок."],
            }
        out = REPORTS_DIR / f"nikto_{ctx.scan_id}.json"
        cmd = [path, "-host", ctx.target_url, "-Format", "json", "-output", str(out), "-nointeractive"]
        result = run_command(cmd, EXTERNAL_TIMEOUTS["nikto"])
        findings = parse_nikto_json(out) if out.exists() else []
        if result["returncode"] not in {0, 1}:
            return {"assets": {}, "findings": findings, "notes": [f"Nikto завершился с ошибкой: {result['stderr'][:300]}"]}
        return {"assets": {"external_reports": [{"tool": "Nikto", "path": str(out)}]}, "findings": findings, "notes": []}


class SQLMapAdapter:
    key = "sqlmap"
    label = "SQLMap"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = shutil.which("sqlmap") or shutil.which("sqlmap.py")
        if not path:
            return {"assets": {}, "findings": [], "notes": ["SQLMap не найден в PATH."]}
        out_dir = REPORTS_DIR / f"sqlmap_{ctx.scan_id}"
        out_dir.mkdir(parents=True, exist_ok=True)
        raw_request_path: Path | None = None
        cmd = [path]
        if ctx.raw_request:
            raw_request_path = Path(tempfile.gettempdir()) / f"bdu_sqlmap_{ctx.scan_id}.req"
            raw_request_path.write_text(ctx.raw_request, encoding="utf-8")
            cmd.extend(["-r", str(raw_request_path)])
        else:
            cmd.extend(["-u", ctx.target_url])
        risk = "2" if ctx.injection_profile else "1"
        level = "3" if ctx.injection_profile else "1"
        crawl = "2" if ctx.injection_profile else "1"
        cmd.extend([
            "--batch",
            f"--crawl={crawl}",
            "--forms",
            f"--risk={risk}",
            f"--level={level}",
            "--smart",
            "--output-dir",
            str(out_dir),
        ])
        if ctx.auth_cookie:
            cmd.extend(["--cookie", ctx.auth_cookie])
        header_value = cli_header_value(ctx.auth_header)
        if header_value:
            cmd.extend([f"--headers={header_value}"])
        try:
            result = run_command(cmd, EXTERNAL_TIMEOUTS["sqlmap"])
        finally:
            if raw_request_path:
                try:
                    raw_request_path.unlink()
                except OSError:
                    pass
        findings: list[Finding] = []
        combined = redact_scan_secrets(result["stdout"] + "\n" + result["stderr"], ctx)
        if "is vulnerable" in combined.lower() or "sql injection" in combined.lower():
            findings.append(
                Finding(
                    "SQLMap обнаружил признаки SQL-инъекции",
                    "Высокий",
                    "SQL Injection",
                    "SQLMap",
                    "Активная проверка SQLMap обнаружила признаки SQL-инъекции или сообщила о vulnerable-параметре.",
                    evidence=combined[-1500:],
                    remediation="Используйте параметризованные запросы/ORM, проверьте все найденные параметры и добавьте regression-тесты.",
                    cwe=["CWE-89"],
                    cve=extract_cves(combined),
                )
            )
        notes = []
        if result["returncode"] not in {0, 1}:
            notes.append(f"SQLMap завершился с предупреждением: {redact_scan_secrets(result['stderr'][:400], ctx)}")
        return {
            "assets": {
                "external_reports": [{"tool": "SQLMap", "path": str(out_dir)}],
                "sqlmap": {
                    "mode": "raw-request" if ctx.raw_request else "crawl-forms",
                    "risk": risk,
                    "level": level,
                    "crawl": crawl,
                    "auth_cookie_used": bool(ctx.auth_cookie),
                    "auth_header_used": bool(ctx.auth_header),
                },
            },
            "findings": findings,
            "notes": notes,
        }


class OpenVASAdapter:
    key = "openvas"
    label = "OpenVAS-lite"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        if "nmap" in ctx.selected_tools:
            return {
                "assets": {"openvas_lite": {"skipped": "network baseline covered by Nmap"}},
                "findings": [],
                "notes": ["OpenVAS-lite сетевой baseline пропущен: выбран Nmap для сетевых портов."],
            }
        findings, assets = socket_port_scan(ctx.host)
        if not findings and assets.get("ports"):
            findings.append(
                Finding(
                    "Сетевые порты обнаружены без критичных признаков",
                    "Инфо",
                    "Network baseline",
                    "OpenVAS-lite",
                    "Встроенный сетевой baseline обнаружил открытые TCP-порты, но среди них нет типично рискованных сервисов из короткого профиля.",
                    evidence=json.dumps(assets.get("ports", []), ensure_ascii=False),
                    remediation="Для полноценной проверки CVE используйте Greenbone/OpenVAS с актуальным NVT feed или Nmap NSE/Vulners.",
                    cwe=["CWE-200"],
                )
            )
        return {
            "assets": {"openvas_lite": assets},
            "findings": findings,
            "notes": ["OpenVAS/Greenbone как платформа не найдена, использован встроенный OpenVAS-lite сетевой baseline."],
        }


class BurpAdapter:
    key = "burp"
    label = "Burp-lite"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        findings, assets = builtin_burp_lite(ctx)
        return {
            "assets": {"burp_lite": assets},
            "findings": findings,
            "notes": ["Burp Suite не подключён как GUI/Proxy, использован встроенный Burp-lite пассивный анализ."],
        }


class SkipFishAdapter:
    key = "skipfish"
    label = "SkipFish-lite"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = shutil.which("skipfish")
        if path:
            out_dir = REPORTS_DIR / f"skipfish_{ctx.scan_id}"
            out_dir.mkdir(parents=True, exist_ok=True)
            cmd = [path, "-o", str(out_dir), "-W", str(WORDLIST_DIR / "web_common.txt"), ctx.target_url]
            result = run_command(cmd, 180)
            if result["returncode"] == 0:
                return {
                    "assets": {"external_reports": [{"tool": "SkipFish", "path": str(out_dir)}]},
                    "findings": [],
                    "notes": ["SkipFish выполнен, откройте HTML-отчёт в папке результата."],
                }
        findings, assets = builtin_skipfish_lite(ctx)
        return {
            "assets": {"skipfish_lite": assets},
            "findings": findings,
            "notes": ["SkipFish CLI не найден или не завершился, использован встроенный SkipFish-lite web-crawl."],
        }


class LegionAdapter:
    key = "legion"
    label = "Legion-lite"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        if "nmap" in ctx.selected_tools:
            port_findings, port_assets = [], {"skipped": "network baseline covered by Nmap"}
        else:
            port_findings, port_assets = socket_port_scan(ctx.host)
        tech_findings, tech_assets = builtin_technology_fingerprint(ctx)
        nikto_findings, nikto_assets = builtin_nikto_lite(ctx)
        findings = port_findings + tech_findings + nikto_findings
        assets = {
            "ports": port_assets,
            "technologies": tech_assets,
            "web_exposure": nikto_assets,
        }
        return {
            "assets": {"legion_lite": assets},
            "findings": findings,
            "notes": ["Legion GUI не найден, использован встроенный Legion-lite оркестратор socket/WhatWeb-lite/Nikto-lite."],
        }


def scan_headers(ctx: ScanContext) -> dict[str, str]:
    headers: dict[str, str] = {}
    if ctx.auth_cookie:
        headers["Cookie"] = ctx.auth_cookie
    name, value = normalized_auth_header(ctx.auth_header)
    if name and value:
        headers[name] = value
    return headers


def normalized_auth_header(value: str) -> tuple[str, str]:
    clean = value.strip()
    if not clean:
        return "", ""
    if ":" in clean:
        name, header_value = clean.split(":", 1)
        return name.strip(), header_value.strip()
    return "Authorization", clean


def cli_header_value(value: str) -> str:
    name, header_value = normalized_auth_header(value)
    return f"{name}: {header_value}" if name and header_value else ""


def redact_scan_secrets(text: str, ctx: ScanContext) -> str:
    redacted = text
    for secret in [ctx.auth_cookie, ctx.auth_header]:
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def fetch(
    url: str,
    method: str = "GET",
    read_limit: int = MAX_HTML_BYTES,
    verify_tls: bool = True,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = {
        "User-Agent": "BDU-Domain-Analyzer/1.0 authorized-security-check",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5",
    }
    request_headers.update(headers or {})
    req = urllib.request.Request(
        url,
        method=method,
        headers=request_headers,
    )
    try:
        return _open_request(req, read_limit, verify_tls=verify_tls)
    except urllib.error.HTTPError as exc:
        body = exc.read(min(read_limit, 50_000)).decode("utf-8", errors="replace")
        return {
            "status": exc.code,
            "final_url": exc.url,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "set_cookies": exc.headers.get_all("Set-Cookie", []) if exc.headers else [],
            "body": body,
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
        }
    except urllib.error.URLError as exc:
        if verify_tls and _looks_like_tls_verify_error(exc):
            fallback = fetch(url, method, read_limit, verify_tls=False, headers=headers)
            fallback["tls_verification_bypassed"] = True
            fallback["verify_error"] = str(exc)
            return fallback
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


def post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    request_headers = {
        "User-Agent": "BDU-Domain-Analyzer/1.0 authorized-security-check",
        "Accept": "application/json,text/plain,*/*",
        "Content-Type": "application/json",
    }
    request_headers.update(headers or {})
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers=request_headers,
    )
    try:
        response = _open_request(req, 80_000, verify_tls=verify_tls)
    except urllib.error.HTTPError as exc:
        body = exc.read(80_000).decode("utf-8", errors="replace")
        response = {
            "status": exc.code,
            "final_url": exc.url,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "set_cookies": exc.headers.get_all("Set-Cookie", []) if exc.headers else [],
            "body": body,
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
        }
    except urllib.error.URLError as exc:
        if verify_tls and _looks_like_tls_verify_error(exc):
            fallback = post_json(url, payload, headers=headers, verify_tls=False)
            fallback["tls_verification_bypassed"] = True
            fallback["verify_error"] = str(exc)
            return fallback
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}

    body = response.get("body", "")
    try:
        response["json"] = json.loads(body)
    except json.JSONDecodeError:
        response["json"] = None
    return response


def _open_request(req: urllib.request.Request, read_limit: int, verify_tls: bool = True) -> dict[str, Any]:
    context = None if verify_tls else ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT, context=context) as response:
        raw = response.read(read_limit)
        charset = response.headers.get_content_charset() or "utf-8"
        body = raw.decode(charset, errors="replace")
        return {
            "status": response.status,
            "final_url": response.url,
            "headers": dict(response.headers.items()),
            "set_cookies": response.headers.get_all("Set-Cookie", []),
            "body": body,
            "content_type": response.headers.get("Content-Type", ""),
        }


def _looks_like_tls_verify_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "certificate_verify_failed" in text or "self-signed certificate" in text or "certificate verify failed" in text


def dig_records(name: str, record_type: str) -> list[str]:
    dig = shutil.which("dig")
    if dig:
        cmd = [dig, "+time=2", "+tries=1", "+short", name, record_type]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            values = [line.strip().strip('"') for line in result.stdout.splitlines() if line.strip()]
            if values or record_type not in {"A", "AAAA"}:
                return values
        except Exception:
            pass
    if record_type in {"A", "AAAA"}:
        try:
            infos = socket.getaddrinfo(name, None)
            return sorted({item[4][0] for item in infos})
        except socket.gaierror:
            return []
    return []


def analyze_transport_and_session(ctx: ScanContext, response: dict[str, Any], http_info: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    final_url = response.get("final_url") or ctx.target_url
    parsed = urlparse(final_url)
    headers = {key.lower(): value for key, value in response.get("headers", {}).items()}

    if parsed.scheme == "https":
        mixed = http_info.get("mixed_content", {})
        active = mixed.get("active", [])
        passive = mixed.get("passive", [])
        if active:
            findings.append(
                Finding(
                    "Обнаружен активный mixed content",
                    "Средний",
                    "Transport security",
                    "Built-in HTTP",
                    "HTTPS-страница загружает активный ресурс по HTTP. Такой ресурс может быть подменён при атаке man-in-the-middle.",
                    evidence=json.dumps(active[:8], ensure_ascii=False),
                    remediation="Переведите scripts/styles/iframes/forms на HTTPS и включите CSP upgrade-insecure-requests или block-all-mixed-content.",
                    cwe=["CWE-319", "CWE-829"],
                )
            )
        if passive:
            findings.append(
                Finding(
                    "Обнаружен пассивный mixed content",
                    "Низкий",
                    "Transport security",
                    "Built-in HTTP",
                    "HTTPS-страница содержит изображения или медиа по HTTP. Это слабее активного mixed content, но всё равно ухудшает целостность страницы.",
                    evidence=json.dumps(passive[:8], ensure_ascii=False),
                    remediation="Переведите все media/assets на HTTPS.",
                    cwe=["CWE-319"],
                )
            )

    insecure_forms = [
        form for form in http_info.get("forms", [])
        if urlparse(form.get("action", "")).scheme == "http"
    ]
    if insecure_forms:
        severity = "Высокий" if any(form.get("has_password") for form in insecure_forms) else "Средний"
        findings.append(
            Finding(
                "Форма отправляет данные по HTTP",
                severity,
                "Transport security",
                "Built-in HTTP",
                "На странице найдена форма, action которой указывает на незашифрованный HTTP endpoint.",
                evidence=json.dumps(insecure_forms[:5], ensure_ascii=False),
                remediation="Переведите обработчики форм на HTTPS и проверьте редиректы, чтобы данные не уходили в открытом виде.",
                cwe=["CWE-319"],
            )
        )

    tokens = http_info.get("session_tokens_in_urls", [])
    if tokens:
        findings.append(
            Finding(
                "Похожие на сессионные токены параметры встречаются в URL",
                "Средний",
                "Session security",
                "Built-in HTTP",
                "Сессионные или авторизационные значения в URL могут попадать в историю браузера, access-логи, Referer и сторонние системы аналитики.",
                evidence=json.dumps(tokens[:8], ensure_ascii=False),
                remediation="Не передавайте session/token/auth значения через URL. Используйте Secure+HttpOnly cookie или Authorization header.",
                cwe=["CWE-598", "CWE-200"],
            )
        )

    if ctx.auth_cookie or ctx.auth_header:
        cache_control = headers.get("cache-control", "").lower()
        pragma = headers.get("pragma", "").lower()
        if not any(marker in cache_control for marker in ["no-store", "private", "no-cache"]) and "no-cache" not in pragma:
            findings.append(
                Finding(
                    "Авторизованная страница может кэшироваться",
                    "Низкий",
                    "Session security",
                    "Built-in HTTP",
                    "При проверке с авторизационными данными в ответе не найдено явного запрета кэширования чувствительного содержимого.",
                    evidence=f"Cache-Control: {headers.get('cache-control', '') or '<нет>'}",
                    remediation="Для личных кабинетов и страниц с персональными данными используйте Cache-Control: no-store или private, no-cache.",
                    cwe=["CWE-525"],
                )
            )

    return findings


def analyze_cookie_prefixes(cookie: str, response: dict[str, Any]) -> list[Finding]:
    name = cookie_name(cookie)
    lower = cookie.lower()
    findings: list[Finding] = []
    if name.startswith("__Host-") and ("secure" not in lower or "path=/" not in lower or "domain=" in lower):
        findings.append(
            Finding(
                "Cookie __Host- нарушает требования префикса",
                "Средний",
                "Session security",
                "Built-in HTTP",
                "Cookie с префиксом __Host- должна быть Secure, Path=/ и без Domain. Иначе защита от подмены cookie ослабевает.",
                evidence=name,
                remediation="Установите __Host-cookie с Secure; Path=/ и без атрибута Domain.",
                cwe=["CWE-565", "CWE-614"],
            )
        )
    if name.startswith("__Secure-") and "secure" not in lower:
        findings.append(
            Finding(
                "Cookie __Secure- установлена без Secure",
                "Средний",
                "Session security",
                "Built-in HTTP",
                "Cookie с префиксом __Secure- должна передаваться только с атрибутом Secure.",
                evidence=name,
                remediation="Добавьте атрибут Secure или уберите префикс __Secure-.",
                cwe=["CWE-614"],
            )
        )
    return findings


def parse_set_cookies(response_or_headers: dict[str, Any]) -> list[str]:
    if "set_cookies" in response_or_headers:
        return [value for value in response_or_headers.get("set_cookies", []) if value]
    cookies = []
    for key, value in response_or_headers.items():
        if key.lower() == "set-cookie":
            cookies.append(value)
    return cookies


def cookie_name(cookie: str) -> str:
    return cookie.split("=", 1)[0].strip()


def find_mixed_content(html_text: str, final_url: str) -> dict[str, list[dict[str, str]]]:
    if not final_url.startswith("https://"):
        return {"active": [], "passive": []}
    active_tags = {"script", "iframe", "frame", "object", "embed", "link", "form"}
    passive_tags = {"img", "audio", "video", "source", "track"}
    result = {"active": [], "passive": []}
    pattern = re.compile(r"<(?P<tag>[a-z0-9:-]+)\b[^>]*(?P<attr>src|href|action)\s*=\s*(['\"])(?P<url>http://[^'\"]+)\3", re.I)
    for match in pattern.finditer(html_text):
        tag = match.group("tag").lower()
        item = {"tag": tag, "attribute": match.group("attr").lower(), "url": match.group("url")[:260]}
        if tag in active_tags:
            result["active"].append(item)
        elif tag in passive_tags:
            result["passive"].append(item)
    return result


def find_session_tokens_in_urls(html_text: str, final_url: str, host: str) -> list[dict[str, str]]:
    candidates = {final_url}
    for attr in ["href", "src", "action"]:
        for match in re.finditer(rf"{attr}\s*=\s*(['\"])(.*?)\1", html_text, re.I | re.S):
            value = match.group(2).strip()
            if value and not value.startswith(("javascript:", "mailto:", "tel:", "#")):
                candidates.add(urljoin(final_url, value))
    token_names = {"sid", "sessid", "session", "sessionid", "phpsessid", "jsessionid", "token", "auth", "access_token", "refresh_token"}
    result: list[dict[str, str]] = []
    for url in candidates:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname != host:
            continue
        query = parsed.query.lower()
        if not query:
            continue
        names = []
        for pair in query.split("&"):
            name = pair.split("=", 1)[0].lower()
            if name in token_names or any(marker in name for marker in ["session", "token", "auth"]):
                names.append(name)
        if names:
            result.append({"url": redact_url_query_values(url), "parameters": ", ".join(sorted(set(names)))})
    return result[:20]


def redact_url_query_values(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.query:
        return url
    redacted_query = "&".join(
        f"{part.split('=', 1)[0]}=[redacted]" if "=" in part else part
        for part in parsed.query.split("&")
    )
    return parsed._replace(query=redacted_query).geturl()


def collect_unverified_tls_info(host: str, port: int) -> dict[str, Any]:
    try:
        ssl_ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=REQUEST_TIMEOUT) as sock:
            with ssl_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                }
    except Exception:
        return {}


def analyze_tls_configuration(tls_info: dict[str, Any], unverified: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    protocol = str(tls_info.get("protocol") or "")
    cipher = tls_info.get("cipher") or ()
    cipher_name = cipher[0] if isinstance(cipher, tuple) and cipher else str(cipher)
    cipher_bits = cipher[2] if isinstance(cipher, tuple) and len(cipher) > 2 else 0
    evidence_prefix = "unverified TLS probe: " if unverified else ""

    if protocol in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                "Используется устаревшая версия TLS/SSL",
                "Высокий",
                "TLS",
                "Built-in TLS",
                "Соединение согласовало устаревший протокол, который не подходит для защищённой передачи сессий и персональных данных.",
                evidence=f"{evidence_prefix}{protocol}",
                remediation="Отключите SSLv2/SSLv3/TLS 1.0/TLS 1.1, оставьте TLS 1.2+ и предпочтительно TLS 1.3.",
                cwe=["CWE-326", "CWE-327"],
            )
        )

    weak_markers = ["RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ANON"]
    if cipher_name and any(marker in cipher_name.upper() for marker in weak_markers):
        findings.append(
            Finding(
                "TLS использует слабый cipher suite",
                "Высокий",
                "TLS",
                "Built-in TLS",
                "Согласованный cipher suite содержит устаревшие или слабые алгоритмы.",
                evidence=f"{evidence_prefix}{cipher_name}",
                remediation="Отключите слабые cipher suites, используйте современные AEAD-наборы TLS 1.2/1.3.",
                cwe=["CWE-326", "CWE-327"],
            )
        )
    elif cipher_bits and cipher_bits < 128:
        findings.append(
            Finding(
                "TLS использует недостаточную длину ключа",
                "Высокий",
                "TLS",
                "Built-in TLS",
                "Согласованный cipher suite сообщает длину ключа меньше 128 бит.",
                evidence=f"{evidence_prefix}{cipher_name}, {cipher_bits} bits",
                remediation="Отключите слабые наборы шифрования и оставьте cipher suites с 128 битами и выше.",
                cwe=["CWE-326"],
            )
        )
    return findings


def is_soft_404_response(response: dict[str, Any], missing_response: dict[str, Any]) -> bool:
    if response.get("status") != 200 or missing_response.get("status") != 200:
        return False
    body = response.get("body", "")
    missing_body = missing_response.get("body", "")
    if not body or not missing_body:
        return False
    title = extract_title(body)
    missing_title = extract_title(missing_body)
    if title and missing_title and title == missing_title:
        body_len = len(body)
        missing_len = len(missing_body)
        if max(body_len, missing_len) and abs(body_len - missing_len) / max(body_len, missing_len) <= 0.05:
            return True
    return body_signature(body) == body_signature(missing_body)


def body_signature(body: str) -> str:
    normalized = re.sub(r"\s+", "", body.lower())
    normalized = re.sub(r"\b\d{10,}\b", "", normalized)
    return normalized[:5000]


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:180]


def extract_forms(html: str, final_url: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for form_match in re.finditer(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", html, re.I | re.S):
        attrs = form_match.group("attrs")
        body = form_match.group("body")
        method = _attr(attrs, "method") or "GET"
        action = _attr(attrs, "action") or final_url
        inputs = re.findall(r"<input\b[^>]*>", body, re.I)
        forms.append(
            {
                "method": method.upper(),
                "action": urljoin(final_url, action),
                "input_count": len(inputs),
                "has_password": any('type="password"' in item.lower() or "type='password'" in item.lower() for item in inputs),
            }
        )
    return forms[:20]


def _attr(attrs: str, name: str) -> str:
    match = re.search(rf"{name}\s*=\s*(['\"])(.*?)\1", attrs, re.I | re.S)
    return match.group(2).strip() if match else ""


def _name_tuple(parts: Any) -> str:
    flattened = []
    for group in parts:
        for key, value in group:
            if key in {"organizationName", "commonName"}:
                flattened.append(value)
    return ", ".join(flattened)


def run_command(cmd: list[str], timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": 124, "stdout": exc.stdout or "", "stderr": f"Timeout after {timeout}s"}
    except Exception as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc)}


def parse_nmap_xml(xml_text: str) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    assets: dict[str, Any] = {"ports": []}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings, assets
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        service_name = service.get("name", "") if service is not None else ""
        product = service.get("product", "") if service is not None else ""
        version = service.get("version", "") if service is not None else ""
        port_item = {
            "port": port.get("portid"),
            "protocol": port.get("protocol"),
            "service": service_name,
            "product": product,
            "version": version,
        }
        assets["ports"].append(port_item)
        if service_name in {"ftp", "telnet", "rlogin", "vnc"}:
            findings.append(
                Finding(
                    f"Открыт потенциально рискованный сервис {service_name}",
                    "Средний",
                    "Network exposure",
                    "Nmap",
                    "Сервис часто требует дополнительной защиты, шифрования или ограничения доступа.",
                    evidence=json.dumps(port_item, ensure_ascii=False),
                    remediation="Ограничьте доступ по ACL/VPN, включите шифрование или отключите сервис, если он не нужен.",
                    cwe=["CWE-284"],
                )
            )
        banner = " ".join([service_name, product, version])
        cves = extract_cves(banner)
        if cves:
            findings.append(
                Finding(
                    f"Nmap обнаружил CVE в баннере {service_name}",
                    "Высокий",
                    "Known vulnerabilities",
                    "Nmap",
                    "В выводе Nmap найден CVE-идентификатор.",
                    evidence=banner,
                    remediation="Проверьте версию сервиса и примените обновления производителя.",
                    cwe=["CWE-1104"],
                    cve=cves,
                )
            )
    return findings, assets


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    normalized = [normalize_single_finding(item) for item in findings]
    merged: dict[tuple[str, str, str], Finding] = {}

    for item in normalized:
        key = finding_key(item)
        existing = merged.get(key)
        if not existing:
            merged[key] = item
            continue

        if severity_rank(item.severity) > severity_rank(existing.severity):
            existing.severity = item.severity
        existing.scanner = merge_csvish(existing.scanner, item.scanner)
        existing.confidence = merge_confidence(existing.confidence, item.confidence)
        existing.cwe = sorted(set(existing.cwe + item.cwe))
        existing.cve = sorted(set(existing.cve + item.cve))
        existing.references = sorted(set(existing.references + item.references))
        if item.evidence and item.evidence not in existing.evidence:
            existing.evidence = (existing.evidence + "\n" + item.evidence).strip()
        if item.description and item.description not in existing.description:
            existing.description = existing.description or item.description
        if item.remediation and item.remediation not in existing.remediation:
            existing.remediation = existing.remediation or item.remediation

    return list(merged.values())


def normalize_single_finding(item: Finding) -> Finding:
    title_lower = item.title.lower()
    desc_lower = item.description.lower()

    if item.scanner == "Wapiti":
        informational_markers = [
            "fingerprint",
            "review webserver metafiles",
            "information leakage",
            "this is only for informational purposes",
        ]
        if any(marker in title_lower or marker in desc_lower or marker in item.remediation.lower() for marker in informational_markers):
            item.severity = "Инфо"
            item.category = "Informational"
            item.cwe = []
        elif item.title in {
            "MIME Type Confusion",
            "HTTP Strict Transport Security (HSTS)",
            "Content Security Policy Configuration",
            "Clickjacking Protection",
        }:
            item.severity = "Низкий"
            item.category = "HTTP headers"
        elif item.title == "Potentially dangerous file":
            item.severity = "Средний"
            item.confidence = "Низкая"
            item.category = "Potentially dangerous file"
            if not item.remediation or item.remediation == "This is only for informational purposes.":
                item.remediation = "Проверьте найденный файл вручную: актуальность, доступность извне и необходимость публикации. Если файл не нужен публично, закройте доступ."

    if "открыт потенциально рискованный порт" in title_lower:
        item.category = "Network exposure"
    if item.category == "Network exposure" and "Socket port scan" in item.scanner:
        item.title = "Обнаружены TCP-ответы на потенциально рискованных портах"
        item.severity = "Низкий"
        item.confidence = "Низкая"
        item.description = "Встроенный socket fallback получил TCP-ответы на портах, которые часто относятся к административным или серверным сервисам. Это эвристика: она не подтверждает протокол и должна проверяться Nmap/OpenVAS."
        item.remediation = "Подтвердите сервисы инструментом Nmap/OpenVAS. Если эти сервисы действительно опубликованы наружу, ограничьте доступ по ACL/VPN или закройте публикацию."
    if "nikto-like endpoint" in title_lower and item.severity == "Инфо":
        item.confidence = "Низкая"
    if "найден путь /.env" in title_lower and "status\": 200" not in item.evidence:
        item.severity = "Инфо"
        item.confidence = "Низкая"

    return item


def finding_key(item: Finding) -> tuple[str, str, str]:
    title = canonical_title(item.title)
    evidence = canonical_evidence(item.evidence)
    if item.category == "Network exposure":
        if "Socket port scan" in item.scanner:
            return (item.category, "socket-fallback", canonical_title(item.title))
        raw = item.evidence + " " + item.title
        port_match = re.search(r'"port"\s*:\s*"?(\d+)"?', raw) or re.search(r"порт\s+(\d+)", raw, re.I)
        port = port_match.group(1) if port_match else ""
        return (item.category, port, title)
    if item.category in {"HTTP headers", "TLS", "DNS email security"}:
        return (item.category, title, "")
    return (item.category, title, evidence[:180])


def canonical_title(title: str) -> str:
    lower = re.sub(r"\s+", " ", title.strip().lower())
    replacements = {
        "mime type confusion": "не запрещён mime sniffing",
        "http strict transport security (hsts)": "отсутствует hsts",
        "content security policy configuration": "отсутствует content-security-policy",
        "clickjacking protection": "не задана защита от clickjacking",
        "review webserver metafiles for information leakage": "информационные metafiles",
        "определены веб-технологии": "fingerprint web technology",
    }
    return replacements.get(lower, lower)


def canonical_evidence(evidence: str) -> str:
    text = evidence.strip()
    text = re.sub(r"https?://[^/\s]+", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def merge_csvish(left: str, right: str) -> str:
    values = []
    for part in (left + "," + right).split(","):
        clean = part.strip()
        if clean and clean not in values:
            values.append(clean)
    return ", ".join(values)


def merge_confidence(left: str, right: str) -> str:
    order = {"Низкая": 1, "Средняя": 2, "Высокая": 3}
    return left if order.get(left, 2) >= order.get(right, 2) else right


def socket_port_scan(host: str) -> tuple[list[Finding], dict[str, Any]]:
    assets: dict[str, Any] = {"ports": [], "scanner": "socket-fallback"}
    risky: list[dict[str, Any]] = []
    for port, service in COMMON_TCP_PORTS.items():
        try:
            with socket.create_connection((host, port), timeout=1.2):
                item = {"port": port, "protocol": "tcp", "service": service}
                assets["ports"].append(item)
                if service in {"ftp", "telnet", "smb", "rdp", "vnc", "redis", "mongodb", "elasticsearch", "mysql", "postgresql"}:
                    risky.append(item)
        except OSError:
            continue
    findings: list[Finding] = []
    if risky:
        ports = ", ".join(f"{item['port']}/{item['service']}" for item in risky)
        findings.append(
            Finding(
                "Обнаружены TCP-ответы на потенциально рискованных портах",
                "Низкий",
                "Network exposure",
                "Socket port scan",
                "Встроенный socket fallback получил TCP-ответы на портах, которые часто относятся к административным или серверным сервисам. Это эвристика: она не подтверждает протокол и должна проверяться Nmap/OpenVAS.",
                evidence=json.dumps(risky, ensure_ascii=False),
                remediation=f"Подтвердите сервисы инструментом Nmap/OpenVAS. Если действительно открыты {ports}, ограничьте доступ по ACL/VPN или закройте публикацию.",
                cwe=["CWE-284"],
                confidence="Низкая",
            )
        )
    return findings, assets


def builtin_content_discovery(ctx: ScanContext, wordlist: Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    assets: dict[str, Any] = {"paths": []}
    words = []
    try:
        words = [line.strip() for line in wordlist.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        words = ["admin", "login", "backup", ".env", ".git", "phpinfo.php", "server-status"]

    root = base_url(ctx.target_url)
    headers = scan_headers(ctx)
    missing_response = fetch(urljoin(root + "/", f"__wfuzz_lite_missing_{ctx.scan_id or int(time.time())}"), "GET", read_limit=30_000, headers=headers)
    for word in words[:80]:
        url = urljoin(root + "/", word.lstrip("/"))
        response = fetch(url, "GET", read_limit=30_000, headers=headers)
        status = response.get("status")
        if status not in {200, 204, 301, 302, 307, 308, 401, 403, 429}:
            continue
        body = response.get("body", "")
        soft_404_like = is_soft_404_response(response, missing_response)
        item = {
            "path": "/" + word.lstrip("/"),
            "url": url,
            "status": status,
            "length": len(body),
            "soft_404_like": soft_404_like,
        }
        assets["paths"].append(item)
        if status == 200 and soft_404_like:
            continue
        severity = "Инфо" if status in {301, 302, 307, 308, 401, 403, 429} else "Низкий"
        confidence = "Низкая" if status == 200 else "Средняя"
        if word in {".env", ".git", "backup", "backups", "db", "database"} and status == 200:
            severity = "Средний"
            confidence = "Низкая"
            if word == ".env" and re.search(r"(PASSWORD|SECRET|TOKEN|KEY)=", body, re.I):
                severity = "Высокий"
                confidence = "Средняя"
        findings.append(
            Finding(
                f"Найден путь /{word.lstrip('/')}",
                severity,
                "Content discovery",
                "Wfuzz-lite",
                "Встроенный словарный поиск обнаружил доступный путь или служебный endpoint.",
                evidence=json.dumps(item, ensure_ascii=False),
                remediation="Проверьте назначение пути и убедитесь, что служебные разделы не раскрывают данные.",
                cwe=["CWE-200"],
                confidence=confidence,
            )
        )
    return findings, assets


def builtin_technology_fingerprint(ctx: ScanContext) -> tuple[list[Finding], dict[str, Any]]:
    response = fetch(ctx.target_url, "GET", headers=scan_headers(ctx))
    headers = response.get("headers", {})
    body = response.get("body", "")
    haystack = (json.dumps(headers, ensure_ascii=False) + "\n" + body[:200_000]).lower()
    technologies: list[str] = []
    for name, patterns in TECH_SIGNATURES.items():
        if any(re.search(pattern, haystack, re.I) for pattern in patterns):
            technologies.append(name)
    server = headers.get("Server") or headers.get("server") or ""
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
    if server:
        technologies.append(f"Server: {server}")
    if powered:
        technologies.append(f"X-Powered-By: {powered}")
    assets = {
        "status": response.get("status"),
        "final_url": response.get("final_url"),
        "technologies": sorted(set(technologies)),
    }
    findings: list[Finding] = []
    if technologies:
        findings.append(
            Finding(
                "Определены веб-технологии",
                "Инфо",
                "Technology fingerprint",
                "WhatWeb-lite",
                "Fingerprint помогает понять стек и точнее выбирать дальнейшие проверки.",
                evidence=", ".join(sorted(set(technologies))),
                remediation="Сверьте обнаруженные версии с политикой обновлений и публичными CVE только при наличии точной версии.",
                cwe=["CWE-200"],
            )
        )
    return findings, assets


def builtin_nikto_lite(ctx: ScanContext) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    assets: dict[str, Any] = {"checks": []}
    root = base_url(ctx.target_url)
    headers = scan_headers(ctx)
    missing_response = fetch(urljoin(root + "/", f"__nikto_lite_missing_{ctx.scan_id or int(time.time())}"), "GET", read_limit=40_000, headers=headers)
    for path in NIKTO_LITE_PATHS:
        url = urljoin(root + "/", path.lstrip("/"))
        response = fetch(url, "GET", read_limit=40_000, headers=headers)
        status = response.get("status")
        if status not in {200, 401, 403}:
            continue
        body = response.get("body", "")
        soft_404_like = is_soft_404_response(response, missing_response)
        item = {
            "path": path,
            "url": url,
            "status": status,
            "length": len(body),
            "soft_404_like": soft_404_like,
        }
        assets["checks"].append(item)
        if status == 200 and soft_404_like:
            continue
        severity = "Инфо" if status in {401, 403} else "Средний"
        confidence = "Низкая" if status == 200 else "Средняя"
        if path in {"/actuator/env", "/actuator/heapdump", "/debug/default/view", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"} and status == 200:
            severity = "Высокий"
            confidence = "Средняя"
        findings.append(
            Finding(
                f"Nikto-like endpoint доступен: {path}",
                severity,
                "Web server exposure",
                "Nikto-lite",
                "Встроенная проверка обнаружила известный служебный или потенциально опасный endpoint.",
                evidence=json.dumps(item, ensure_ascii=False),
                remediation="Ограничьте endpoint по IP/VPN, отключите его на публичном контуре или добавьте аутентификацию.",
                cwe=["CWE-200", "CWE-284"],
                confidence=confidence,
            )
        )
    return findings, assets


def builtin_burp_lite(ctx: ScanContext) -> tuple[list[Finding], dict[str, Any]]:
    response = fetch(ctx.target_url, "GET", headers=scan_headers(ctx))
    body = response.get("body", "")
    final_url = response.get("final_url") or ctx.target_url
    links = extract_in_scope_links(body, final_url, ctx.host)
    forms = extract_form_security_details(body, final_url)
    assets = {
        "status": response.get("status"),
        "final_url": final_url,
        "title": extract_title(body),
        "links": links[:80],
        "forms": forms,
    }
    findings: list[Finding] = []
    for form in forms:
        if form["method"] == "POST" and not form["has_csrf_token"]:
            findings.append(
                Finding(
                    "POST-форма без явного CSRF-токена",
                    "Средний",
                    "Web forms",
                    "Burp-lite",
                    "На странице найдена POST-форма, в которой не видно поля с CSRF/token-признаком. Это эвристика, требующая ручной проверки.",
                    evidence=json.dumps(form, ensure_ascii=False),
                    remediation="Проверьте наличие server-side CSRF-защиты. Для state-changing форм используйте CSRF-токены и SameSite cookie.",
                    cwe=["CWE-352"],
                    confidence="Низкая",
                )
            )
        if form["has_password"] and not final_url.startswith("https://"):
            findings.append(
                Finding(
                    "Форма пароля на странице без HTTPS",
                    "Высокий",
                    "Web forms",
                    "Burp-lite",
                    "Пассивный анализ обнаружил password input на незащищённой HTTP-странице.",
                    evidence=json.dumps(form, ensure_ascii=False),
                    remediation="Перенесите форму аутентификации на HTTPS и включите Secure cookie.",
                    cwe=["CWE-319"],
                )
            )
    if len(links) > 40:
        findings.append(
            Finding(
                "Большая поверхность URL на стартовой странице",
                "Инфо",
                "Site map",
                "Burp-lite",
                "На стартовой странице найдено много in-scope ссылок. Это полезная карта поверхности для дальнейшего тестирования.",
                evidence=f"{len(links)} ссылок",
                remediation="Проверьте, что административные и служебные разделы не попали в публичную навигацию.",
                cwe=["CWE-200"],
            )
        )
    return findings, assets


def builtin_skipfish_lite(ctx: ScanContext) -> tuple[list[Finding], dict[str, Any]]:
    queue = [ctx.target_url]
    seen: set[str] = set()
    pages: list[dict[str, Any]] = []
    findings: list[Finding] = []
    while queue and len(seen) < 35:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        response = fetch(url, "GET", read_limit=120_000, headers=scan_headers(ctx))
        status = response.get("status")
        body = response.get("body", "")
        page = {
            "url": response.get("final_url") or url,
            "status": status,
            "title": extract_title(body),
            "length": len(body),
            "content_type": response.get("content_type", ""),
        }
        pages.append(page)
        if status and status >= 500:
            findings.append(
                Finding(
                    f"Страница отвечает ошибкой HTTP {status}",
                    "Средний",
                    "Web crawl",
                    "SkipFish-lite",
                    "Во время crawl обнаружен серверный код ошибки. Это может указывать на нестабильность или обработчик, который стоит проверить.",
                    evidence=json.dumps(page, ensure_ascii=False),
                    remediation="Проверьте логи приложения для указанного URL и обработку ошибок.",
                    cwe=["CWE-209"],
                )
            )
        if re.search(r"<title>\s*index of\s*/", body, re.I) or "parent directory" in body.lower():
            findings.append(
                Finding(
                    "Похоже на листинг каталога",
                    "Средний",
                    "Directory listing",
                    "SkipFish-lite",
                    "Страница похожа на автоматический индекс каталога.",
                    evidence=page["url"],
                    remediation="Отключите directory listing на веб-сервере.",
                    cwe=["CWE-548"],
                )
            )
        for link in extract_in_scope_links(body, page["url"], ctx.host)[:20]:
            if link not in seen and len(queue) < 60:
                queue.append(link)
    return findings, {"pages": pages, "visited": len(seen)}


def extract_in_scope_links(html_text: str, final_url: str, host: str) -> list[str]:
    urls: set[str] = set()
    for attr in ["href", "src", "action"]:
        for match in re.finditer(rf"{attr}\s*=\s*(['\"])(.*?)\1", html_text, re.I | re.S):
            value = match.group(2).strip()
            if not value or value.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(final_url, value)
            parsed = urlparse(absolute)
            if parsed.hostname == host:
                clean = parsed._replace(fragment="").geturl()
                urls.add(clean)
    return sorted(urls)


def extract_form_security_details(html_text: str, final_url: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for form_match in re.finditer(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", html_text, re.I | re.S):
        attrs = form_match.group("attrs")
        body = form_match.group("body")
        method = (_attr(attrs, "method") or "GET").upper()
        action = urljoin(final_url, _attr(attrs, "action") or final_url)
        input_names = [
            _attr(input_tag, "name")
            for input_tag in re.findall(r"<input\b[^>]*>", body, re.I | re.S)
        ]
        joined_names = " ".join(name.lower() for name in input_names if name)
        forms.append(
            {
                "method": method,
                "action": action,
                "input_names": [name for name in input_names if name][:30],
                "has_password": "type=\"password\"" in body.lower() or "type='password'" in body.lower(),
                "has_csrf_token": any(token in joined_names for token in ["csrf", "_token", "authenticity", "xsrf"]),
            }
        )
    return forms[:30]


def parse_wapiti_json(path: Path) -> list[Finding]:
    data = read_json_file(path)
    findings: list[Finding] = []
    classifications = data.get("classifications", {}) if isinstance(data, dict) else {}
    for section in ["vulnerabilities", "anomalies", "additionals"]:
        values = data.get(section, {}) if isinstance(data, dict) else {}
        if not isinstance(values, dict):
            continue
        for category, items in values.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                cls = classifications.get(category, {}) if isinstance(classifications, dict) else {}
                desc = item.get("info") or item.get("description") or cls.get("desc", "")
                remediation = cls.get("sol", "")
                severity = wapiti_severity(category)
                findings.append(
                    Finding(
                        item.get("name") or category,
                        severity,
                        category,
                        "Wapiti",
                        desc or f"Wapiti сообщил категорию {category}.",
                        evidence=" ".join(str(item.get(key, "")) for key in ["method", "path", "parameter"]).strip(),
                        remediation=remediation or "Проверьте найденный endpoint и примените защиту для указанного класса уязвимости.",
                        url=item.get("path", ""),
                        cwe=category_to_cwe(category),
                        cve=extract_cves(json.dumps(item, ensure_ascii=False)),
                    )
                )
    return findings


def parse_wfuzz_json(path: Path) -> list[Finding]:
    data = read_json_file(path)
    findings: list[Finding] = []
    results = data.get("results", []) if isinstance(data, dict) else data if isinstance(data, list) else []
    for item in results[:50]:
        if not isinstance(item, dict):
            continue
        status = item.get("code") or item.get("status")
        url = item.get("url") or item.get("request", {}).get("url", "")
        if status:
            findings.append(
                Finding(
                    f"Wfuzz нашёл доступный путь HTTP {status}",
                    "Инфо" if int(status) in {301, 302, 307, 308, 401, 403} else "Низкий",
                    "Content discovery",
                    "Wfuzz",
                    "Словарный фаззинг обнаружил доступный путь.",
                    evidence=url,
                    remediation="Проверьте назначение найденного пути и убедитесь, что служебные разделы закрыты.",
                    cwe=["CWE-200"],
                )
            )
    return findings


def parse_nikto_json(path: Path) -> list[Finding]:
    data = read_json_file(path)
    findings: list[Finding] = []
    vulnerabilities = []
    if isinstance(data, dict):
        vulnerabilities = data.get("vulnerabilities") or data.get("items") or []
    for item in vulnerabilities[:100]:
        if not isinstance(item, dict):
            continue
        text = json.dumps(item, ensure_ascii=False)
        findings.append(
            Finding(
                item.get("msg") or item.get("description") or "Nikto finding",
                "Средний",
                "Web server",
                "Nikto",
                item.get("msg") or item.get("description") or "Nikto сообщил потенциальную проблему веб-сервера.",
                evidence=text[:800],
                remediation="Проверьте вывод Nikto, обновите веб-сервер и закройте ненужные endpoints.",
                cwe=["CWE-16"],
                cve=extract_cves(text),
            )
        )
    return findings


def read_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def wapiti_severity(category: str) -> str:
    lower = category.lower()
    if "sql" in lower or "command" in lower or "ssrf" in lower or "file" in lower:
        return "Высокий"
    if "xss" in lower or "csrf" in lower or "redirect" in lower:
        return "Средний"
    if "fingerprint" in lower:
        return "Инфо"
    return "Низкий"


def category_to_cwe(category: str) -> list[str]:
    lower = category.lower()
    mapping = {
        "sql": "CWE-89",
        "xss": "CWE-79",
        "csrf": "CWE-352",
        "redirect": "CWE-601",
        "ssrf": "CWE-918",
        "backup": "CWE-530",
        "header": "CWE-693",
        "file": "CWE-22",
        "command": "CWE-78",
    }
    return [cwe for key, cwe in mapping.items() if key in lower]


def find_wapiti() -> str:
    path = shutil.which("wapiti")
    if path:
        return path
    if LEGACY_WAPITI_BIN.exists():
        return str(LEGACY_WAPITI_BIN)
    return ""


def _tool(name: str, key: str, mode: str, note: str, selected: set[str]) -> ToolStatus:
    path = find_wapiti() if key == "wapiti" else shutil.which(key) or ""
    return ToolStatus(name.upper() if key == "nmap" else name.capitalize(), key, bool(path), path, mode, note, key in selected)


def _tool_with_fallback(name: str, key: str, note: str, fallback: str, selected: set[str]) -> ToolStatus:
    path = shutil.which(key) or ""
    if path:
        return ToolStatus(name, key, True, path, "optional", note, key in selected)
    return ToolStatus(name, key, True, fallback, "fallback", f"{note} CLI не найден, будет использован Python fallback.", key in selected)


def _platform_with_fallback(
    name: str,
    key: str,
    candidates: list[str],
    note: str,
    fallback: str,
    selected: set[str],
) -> ToolStatus:
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return ToolStatus(name, key, True, path, "optional", note, key in selected)
    return ToolStatus(name, key, True, fallback, "fallback", f"{note} Платформа не найдена, будет использован Python fallback.", key in selected)


def severity_rank(value: str) -> int:
    return {"Критический": 5, "Высокий": 4, "Средний": 3, "Низкий": 2, "Инфо": 1}.get(value, 0)


def _deep_merge(current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(current)
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        elif isinstance(value, list) and isinstance(merged.get(key), list):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged
