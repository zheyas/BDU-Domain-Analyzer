# -*- coding: utf-8 -*-

import ipaddress
import hashlib
import json
import os
import re
import signal
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from .bdu import BDUHandler, extract_cves
from .config import (
    EXTERNAL_TIMEOUTS,
    FULL_COMPLETION_TIMEOUTS,
    MAX_HTML_BYTES,
    REPORTS_DIR,
    REQUEST_TIMEOUT,
    RULES_DIR,
    SCANNER_SOURCE_DIRS,
    WORDLIST_DIR,
)
from .models import Finding, ScanContext, ScanReport, ToolStatus
from .installer import (
    find_tool_binary,
    install_missing_tools,
    scanner_runtime_details,
    scanner_source_inventory,
    source_available,
    tool_environment,
)
from .progress import LOGGER, PROGRESS, configure_logging, emit
from .source_integrations import legion_device_profile
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
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    6379: "redis",
    6443: "kubernetes-api",
    8080: "http-alt",
    8291: "mikrotik-winbox",
    8443: "https-alt",
    9200: "elasticsearch",
    9100: "jetdirect",
    10250: "kubelet",
    27017: "mongodb",
}

DISCOVERY_TCP_PORTS = (22, 53, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443, 9100)
WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 27017}
WEB_PORTS = {80, 443, 8080, 8443}
FULL_TCP_PORT_MIN = 1
FULL_TCP_PORT_MAX = 65535
FULL_TCP_SCAN_WORKERS = 256
FULL_TCP_SCAN_TIMEOUT = 0.08
FILE_SERVICE_PORTS = {
    21: "FTP",
    139: "NetBIOS/SMB",
    445: "SMB",
    111: "RPC/NFS",
    2049: "NFS",
    873: "rsync",
    990: "FTPS",
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

FS_MAX_FILES = 20_000
FS_MAX_READ_BYTES = 1_000_000
FS_MAX_ASSET_ITEMS = 120
FS_LARGE_FILE_BYTES = 50 * 1024 * 1024
FS_SKIP_DIR_NAMES = {
    "__pycache__",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
}
FS_SKIP_ABSOLUTE_PREFIXES = ("/proc", "/sys", "/dev", "/run")
FS_TEXT_SUFFIXES = {
    ".asp", ".asax", ".aspx", ".bash", ".bat", ".cgi", ".conf", ".config",
    ".env", ".htaccess", ".ini", ".java", ".js", ".jsp", ".jspx", ".json",
    ".lua", ".php", ".php3", ".php4", ".php5", ".phtml", ".pl", ".ps1",
    ".py", ".rb", ".sh", ".sql", ".txt", ".xml", ".yaml", ".yml",
}
FS_WEB_EXEC_SUFFIXES = {
    ".asp", ".aspx", ".cgi", ".jsp", ".jspx", ".php", ".php3", ".php4",
    ".php5", ".phtml", ".phar", ".pl", ".py",
}
FS_UPLOAD_MARKERS = {"upload", "uploads", "tmp", "temp", "cache", "files", "media", "static"}
FS_AUTOSTART_MARKERS = (
    "/cron.", "/cron/", "/systemd/", "/init.d/", "/rc.local",
    "/launchagents/", "/launchdaemons/", "/startup/", "/authorized_keys",
)
FS_SECRET_PATTERNS = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("JWT token", re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Password/secret assignment", re.compile(r"(?i)\b(password|passwd|secret|secret[_-]?key|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]
FS_WEBSHELL_PATTERNS = [
    ("PHP eval from request", re.compile(r"(?is)\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)")),
    ("PHP command execution from request", re.compile(r"(?is)\b(?:system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)")),
    ("PHP eval/base64 obfuscation", re.compile(r"(?is)\beval\s*\(.{0,120}\bbase64_decode\s*\(")),
    ("Known PHP shell marker", re.compile(r"(?is)\b(?:WSO|c99shell|r57shell|FilesMan|b374k)\b")),
    ("JSP command shell", re.compile(r"(?is)Runtime\.getRuntime\(\)\.exec\s*\(.{0,120}request\.getParameter")),
    ("ASP command shell", re.compile(r"(?is)(?:WScript\.Shell|Server\.CreateObject\(['\"]WScript\.Shell['\"]\)|Request\.(?:QueryString|Form).{0,80}(?:cmd|command))")),
    ("Python reverse shell pattern", re.compile(r"(?is)socket\.socket\s*\(.{0,200}\.connect\s*\(.{0,200}(?:/bin/sh|cmd\.exe)")),
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

RECOMMENDED_ACTIVE_TOOLS = {
    "domain": {"nmap", "whatweb", "wfuzz", "nikto", "burp_lite", "skipfish", "legion", "theharvester", "dnsrecon", "knockpy", "altdns"},
    "ip": {"nmap", "whatweb", "wfuzz", "nikto", "burp_lite", "skipfish", "legion"},
    "network": {"nmap"},
    "filesystem": set(),
}


def recommended_tools_for_target(target_kind: str) -> set[str]:
    return set(RECOMMENDED_ACTIVE_TOOLS.get(target_kind, set()))


def discover_tools(selected: set[str] | None = None) -> list[ToolStatus]:
    selected = selected or set()
    tools = [
        ToolStatus("Инвентаризация узлов и ОС", "system-inventory", True, "встроенный Python-анализатор", "built-in", "IP/CIDR, сервисы, роли узлов, MAC/hostname и эвристика ОС."),
        ToolStatus("Обнаружение локальной сети", "network-discovery", True, "встроенный Python-анализатор", "built-in", "Безопасный TCP-discovery подсетей до 256 адресов."),
        ToolStatus("Аудит файловой системы", "filesystem-audit", True, "встроенный Python-анализатор", "built-in", "Проверка локального/смонтированного пути на web-shell, секреты, автозапуск и подозрительные файлы."),
        ToolStatus("ClamAV", "clamscan", bool(find_tool_binary("clamscan")), find_tool_binary("clamscan"), "optional", "Антивирусная проверка файловой цели, если clamscan установлен."),
        ToolStatus("YARA", "yara", bool(find_tool_binary("yara")), find_tool_binary("yara"), "optional", "Сигнатурная проверка файловой цели по локальным правилам rules/*.yar, если yara установлен."),
        _tool("nmap", "nmap", "optional", "Сетевые порты и версии сервисов. Если Nmap зависнет, включится socket fallback.", selected),
        _tool(
            "wapiti",
            "wapiti",
            "optional",
            "DAST веб-приложений; Wapiti 3.3.0 устанавливается в изолированное окружение проекта.",
            selected,
        ),
        _tool_with_fallback("Wfuzz", "wfuzz", "Фаззинг каталогов и URL через словарь.", "встроенный Wfuzz-lite", selected),
        _tool_with_fallback("WhatWeb", "whatweb", "Фингерпринт технологий веб-сайта.", "встроенный WhatWeb-lite", selected),
        _tool_with_fallback("Nikto", "nikto", "Проверка веб-сервера на известные misconfiguration.", "встроенный Nikto-lite", selected),
        _tool("sqlmap", "sqlmap", "active", "SQL-инъекции; запускается только при активном профиле.", selected),
        ToolStatus("Burp-lite", "burp_lite", True, "встроенный Python-анализатор", "built-in", "Собственный модуль проекта: пассивная карта сайта, формы и CSRF-эвристики.", "burp_lite" in selected),
        _platform_with_fallback("SkipFish", "skipfish", ["skipfish"], "Активная карта сайта и web-crawl.", "встроенный SkipFish-lite", selected),
        _platform_with_fallback("Legion", "legion", ["legion"], "Оркестрация сетевых и web-проверок.", "встроенный Legion-lite", selected),
        _tool("theHarvester", "theharvester", "passive", "Пассивный OSINT-сбор поддоменов и email из открытых источников.", selected),
        _tool_with_fallback("DNSRecon", "dnsrecon", "Глубокий DNS-аудит, AXFR, SRV и wildcard.", "встроенный DNS-аудит", selected),
        _tool_with_fallback("Knockpy", "knockpy", "Пассивный поиск и словарный перебор поддоменов с wildcard-контролем.", "встроенный DNS-перебор", selected),
        _tool_with_fallback("Altdns", "altdns", "Мутации уже найденных поддоменов.", "встроенные ограниченные мутации", selected),
    ]
    return tools


# Параллелизм движков. Встроенные проверки и внешние сканеры запускаются пулами
# потоков; результаты (каждый самодостаточный) сливаются в общий assets в главном
# потоке в детерминированном порядке, поэтому отчёт стабилен.
BUILTIN_MAX_WORKERS = 6
EXTERNAL_MAX_WORKERS = 4


def _run_component(label: str, fn: Callable[[], dict[str, Any]], progress_id: str) -> tuple[dict[str, Any], float]:
    """Выполнить один компонент, поймав исключение, и вернуть (результат, длительность)."""
    step_start = time.time()
    try:
        result = fn()
    except Exception as exc:
        log_component_exception(label, exc)
        message = f"{label}: ошибка {type(exc).__name__}: {exc}. Остальные проверки продолжены."
        emit(progress_id, message, "warning")
        result = {"assets": {}, "findings": [], "notes": [message]}
    return result, time.time() - step_start


def _run_components_parallel(
    jobs: list[tuple[str, Callable[[], dict[str, Any]]]],
    progress_id: str,
    max_workers: int,
) -> dict[str, tuple[dict[str, Any], float]]:
    """Запустить компоненты пулом потоков; ключ результата — уникальная метка задания.

    Компоненты читают только ctx и возвращают свой результат, поэтому безопасны
    для параллельного исполнения; слияние общего состояния делает вызывающий код.
    """
    collected: dict[str, tuple[dict[str, Any], float]] = {}
    if not jobs:
        return collected
    workers = max(1, min(max_workers, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_run_component, label, fn, progress_id): label for label, fn in jobs}
        for future in as_completed(futures):
            label = futures[future]
            collected[label] = future.result()
    return collected


def run_assessment(ctx: ScanContext, bdu: BDUHandler) -> ScanReport:
    start = time.time()
    progress_id = ctx.progress_id or ctx.scan_id
    emit(progress_id, "Подготавливаю контекст и структуру отчёта")
    notes: list[str] = []
    runtime_inventory = [scanner_runtime_details(key) for key in sorted(ctx.selected_tools)]
    assets: dict[str, Any] = {
        "dns": {},
        "subdomains": [],
        "http": {},
        "tls": {},
        "paths": [],
        "external_reports": [],
        "scanner_runs": [],
        "scanner_sources": scanner_source_inventory(),
        "scanner_runtimes": runtime_inventory,
        "source_integration": {
            "selected": len(runtime_inventory),
            "source_used": sum(1 for item in runtime_inventory if item.get("source_used")),
            "not_source_runtime": [item.get("key") for item in runtime_inventory if not item.get("source_used")],
        },
        "scan_context": {
            "target_kind": ctx.target_kind,
            "network": ctx.network,
            "filesystem_path": ctx.filesystem_path,
            "active_mode": ctx.active_mode,
            "injection_profile": ctx.injection_profile,
            "auth_cookie_provided": bool(ctx.auth_cookie),
            "auth_header_provided": bool(ctx.auth_header),
            "raw_request_provided": bool(ctx.raw_request),
            "auto_install": ctx.auto_install,
            "wait_for_completion": ctx.wait_for_completion,
        },
    }
    findings: list[Finding] = []
    if ctx.injection_profile:
        notes.append("Включён профиль XSS/SQLi: Wapiti и SQLMap запускаются с расширенными параметрами проверки.")
    if ctx.auth_cookie or ctx.auth_header:
        notes.append("Авторизационные данные переданы сканерам и встроенным HTTP-проверкам; секреты не сохраняются в отчёт.")
    if ctx.raw_request:
        notes.append("SQLMap использует raw HTTP-запрос как основную цель проверки параметров.")

    if ctx.auto_install:
        emit(progress_id, "Проверяю недостающие выбранные компоненты")
        compatible_tools = {key for key in ctx.selected_tools if not incompatible_tool_note(key, ctx.target_kind)}
        installed = install_missing_tools(compatible_tools, lambda message, level="info": emit(progress_id, message, level))
        if installed:
            notes.append("Автоустановка: добавлены компоненты " + ", ".join(installed) + ".")

    if ctx.target_kind == "filesystem":
        builtins = [FileSystemAnalyzer()]
        notes.append("Для файловой цели выполняется локальный аудит указанного пути; web/DNS/network-проверки пропущены.")
    elif ctx.target_kind == "network":
        builtins = [NetworkSystemAnalyzer()]
        notes.append("Для CIDR-цели выполняется сетевая инвентаризация; DNS- и web-проверки домена пропущены.")
    elif ctx.target_kind == "ip":
        builtins = [NetworkSystemAnalyzer(), HTTPAnalyzer(), TokenExposureAnalyzer(), TLSAnalyzer(), DirectoryProbeAnalyzer(), WebScenarioAnalyzer()]
        notes.append("Для IP-цели включена инвентаризация системы; доменные DNS/OSINT-проверки пропущены.")
    else:
        builtins = [DNSAnalyzer(), HTTPAnalyzer(), TokenExposureAnalyzer(), TLSAnalyzer(), DirectoryProbeAnalyzer(), WebScenarioAnalyzer()]
    builtin_jobs = [(analyzer.__class__.__name__, analyzer) for analyzer in builtins]
    emit(progress_id, f"Параллельно выполняю встроенные проверки: {len(builtin_jobs)}")
    builtin_results = _run_components_parallel(
        [(label, (lambda analyzer=analyzer: analyzer.run(ctx))) for label, analyzer in builtin_jobs],
        progress_id,
        BUILTIN_MAX_WORKERS,
    )
    for label, _analyzer in builtin_jobs:
        result, duration = builtin_results[label]
        assets.update(_deep_merge(assets, result.get("assets", {})))
        findings.extend(result.get("findings", []))
        notes.extend(result.get("notes", []))
        assets["scanner_runs"].append(scanner_run_record(label, "built-in", result, duration))
        emit(
            progress_id,
            f"{label}: готово за {duration:.1f} с, находок {len(result.get('findings', []))}",
        )

    external_map = {
        "nmap": NmapAdapter(),
        "wapiti": WapitiAdapter(),
        "wfuzz": WfuzzAdapter(),
        "whatweb": WhatWebAdapter(),
        "nikto": NiktoAdapter(),
        "sqlmap": SQLMapAdapter(),
        "burp_lite": BurpLiteAdapter(),
        "skipfish": SkipFishAdapter(),
        "legion": LegionAdapter(),
        "theharvester": TheHarvesterAdapter(),
        "dnsrecon": DNSReconAdapter(),
        "knockpy": KnockpyAdapter(),
        "altdns": AltdnsAdapter(),
    }
    if "theharvester" in ctx.selected_tools and ctx.target_kind == "domain":
        adapter = external_map["theharvester"]
        emit(progress_id, f"Пассивный сканер: {adapter.label}")
        step_start = time.time()
        try:
            result = adapter.run(ctx)
        except Exception as exc:
            log_component_exception(adapter.label, exc)
            message = f"{adapter.label}: ошибка адаптера {type(exc).__name__}: {exc}. Остальные проверки продолжены."
            emit(progress_id, message, "warning")
            result = {"assets": {}, "findings": [], "notes": [message]}
        assets.update(_deep_merge(assets, result.get("assets", {})))
        findings.extend(result.get("findings", []))
        notes.extend(result.get("notes", []))
        assets["scanner_runs"].append(scanner_run_record(adapter.label, "theharvester", result, time.time() - step_start))
        emit(
            progress_id,
            f"{adapter.label}: готово за {time.time() - step_start:.1f} с, находок {len(result.get('findings', []))}",
        )
    elif "theharvester" in ctx.selected_tools:
        compatibility_note = incompatible_tool_note("theharvester", ctx.target_kind)
        notes.append(compatibility_note)
        assets["scanner_runs"].append(scanner_run_record("theHarvester", "theharvester", {"status": "skipped", "notes": [compatibility_note]}, 0.0))
    if ctx.active_mode:
        preferred_order = [
            "dnsrecon", "knockpy", "altdns", "nmap", "whatweb", "wfuzz", "nikto",
            "burp_lite", "skipfish", "legion", "wapiti", "sqlmap",
        ]
        selected_external = [key for key in preferred_order if key in ctx.selected_tools]
        selected_external.extend(sorted(ctx.selected_tools - set(preferred_order) - {"theharvester"}))
        runnable: list[tuple[str, Any]] = []
        for key in selected_external:
            adapter = external_map.get(key)
            compatibility_note = incompatible_tool_note(key, ctx.target_kind)
            if compatibility_note:
                notes.append(compatibility_note)
                assets["scanner_runs"].append(scanner_run_record(adapter.label if adapter else key, key, {"status": "skipped", "notes": [compatibility_note]}, 0.0))
            elif adapter:
                runnable.append((key, adapter))
        if runnable:
            if ctx.wait_for_completion:
                total_limit = int(sum(full_completion_timeout(key, EXTERNAL_TIMEOUTS.get(key, 180)) for key, _adapter in runnable))
                emit(
                    progress_id,
                    f"Очередь внешних сканеров: {len(runnable)}; полный режим с предельным бюджетом {total_limit // 60} мин {total_limit % 60} с",
                )
            else:
                total_limit = sum(EXTERNAL_TIMEOUTS.get(key, 180) for key, _adapter in runnable)
                emit(
                    progress_id,
                    f"Очередь внешних сканеров: {len(runnable)}, оценочный бюджет по таймаутам {total_limit // 60} мин {total_limit % 60} с",
                )
        def merge_external(key: str, label: str, result: dict[str, Any], duration: float) -> None:
            assets.update(_deep_merge(assets, result.get("assets", {})))
            findings.extend(result.get("findings", []))
            result_notes = result.get("notes", [])
            notes.extend(result_notes)
            assets["scanner_runs"].append(scanner_run_record(label, key, result, duration))
            if not result_notes and not result.get("findings", []):
                notes.append(f"{label}: выполнен, новых находок не добавил.")
            emit(progress_id, f"{label}: готово за {duration:.1f} с, находок {len(result.get('findings', []))}")

        # altdns зависит от собранных поддоменов, поэтому выполняется отдельной
        # фазой после остальных внешних сканеров; всё остальное идёт параллельно.
        parallel_runnable = [(key, adapter) for key, adapter in runnable if key != "altdns"]
        altdns_runnable = [(key, adapter) for key, adapter in runnable if key == "altdns"]
        if parallel_runnable:
            workers = max(1, min(len(parallel_runnable), EXTERNAL_MAX_WORKERS))
            emit(progress_id, f"Параллельный запуск внешних сканеров: {len(parallel_runnable)} (воркеров {workers})")
            external_results = _run_components_parallel(
                [(key, (lambda adapter=adapter: adapter.run(ctx))) for key, adapter in parallel_runnable],
                progress_id,
                EXTERNAL_MAX_WORKERS,
            )
            for key, adapter in parallel_runnable:
                result, duration = external_results[key]
                merge_external(key, adapter.label, result, duration)
        for key, adapter in altdns_runnable:
            emit(progress_id, f"Внешний сканер (после сбора поддоменов): {adapter.label}")
            result, duration = _run_component(
                adapter.label,
                (lambda adapter=adapter: adapter.run(ctx, assets.get("subdomains", []))),
                progress_id,
            )
            merge_external(key, adapter.label, result, duration)
    elif ctx.target_kind == "filesystem" and ctx.selected_tools - {"theharvester"}:
        for key in sorted(ctx.selected_tools - {"theharvester"}):
            compatibility_note = incompatible_tool_note(key, ctx.target_kind)
            if compatibility_note:
                notes.append(compatibility_note)
                adapter = external_map.get(key)
                assets["scanner_runs"].append(scanner_run_record(adapter.label if adapter else key, key, {"status": "skipped", "notes": [compatibility_note]}, 0.0))
    elif ctx.selected_tools - {"theharvester"}:
        inactive_note = "Внешние активные сканеры не запускались: включите активный профиль проверки."
        notes.append(inactive_note)
        for key in sorted(ctx.selected_tools - {"theharvester"}):
            adapter = external_map.get(key)
            if adapter:
                assets["scanner_runs"].append(scanner_run_record(adapter.label, key, {"status": "skipped", "notes": [inactive_note]}, 0.0))

    finalize_filesystem_step(ctx, assets, findings, notes)
    emit(progress_id, "Нормализую находки и сопоставляю их с локальной БДУ")
    findings = normalize_findings(findings)
    enriched = [bdu.enrich(item) for item in findings]
    enriched.sort(key=lambda item: (severity_rank(item.severity), item.title), reverse=True)
    incomplete_runs = [
        item for item in assets["scanner_runs"]
        if item.get("selected") and item.get("status") not in {"completed", "completed-with-fallback"}
    ]
    assets["scan_completion"] = {
        "wait_for_completion": ctx.wait_for_completion,
        "all_selected_stages_finished": not incomplete_runs,
        "incomplete": incomplete_runs,
        "run_count": len(assets["scanner_runs"]),
    }
    if incomplete_runs:
        notes.append("Не все выбранные движки завершились штатно: " + ", ".join(str(item["label"]) for item in incomplete_runs) + ".")
    report = ScanReport(
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
    emit(progress_id, f"Отчёт собран: {len(enriched)} находок, длительность {time.time() - start:.1f} с")
    assets["scan_log"] = PROGRESS.snapshot(progress_id).get("events", [])
    return report


class NetworkSystemAnalyzer:
    """Small built-in inventory engine for one IP or a bounded CIDR target."""

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        network_text = ctx.network or ctx.host
        try:
            network = ipaddress.ip_network(network_text, strict=False)
        except ValueError:
            return {"assets": {}, "findings": [], "notes": ["Не удалось разобрать IP-сеть для системного анализа."]}

        addresses = [str(address) for address in network.hosts()]
        if not addresses and network.num_addresses == 1:
            addresses = [str(network.network_address)]
        single_target = ctx.target_kind == "ip" or len(addresses) == 1
        explicit_port = target_url_port(ctx.target_url) if ctx.target_kind == "ip" else None
        workers = min(32, max(1, len(addresses)))
        records: list[dict[str, Any]] = []
        progress_id = ctx.progress_id or ctx.scan_id
        if progress_id:
            emit(progress_id, f"Сетевая инвентаризация: проверяю {len(addresses)} адресов, потоков {workers}")

        def inspect(address: str) -> dict[str, Any] | None:
            initial_ports = list(COMMON_TCP_PORTS) if single_target else list(DISCOVERY_TCP_PORTS)
            if explicit_port and explicit_port not in initial_ports:
                initial_ports.append(explicit_port)
            open_ports = scan_host_ports(address, initial_ports, timeout=0.22 if not single_target else 0.45)
            if explicit_port:
                for item in open_ports:
                    if item.get("port") == explicit_port and item.get("service") == "unknown":
                        item["service"] = "https-target" if ctx.target_url.startswith("https://") else "http-target"
            if single_target:
                already_checked = set(initial_ports)
                if progress_id:
                    emit(progress_id, f"Порт-скан {address}: ищу открытые TCP-порты 1-65535")
                open_ports.extend(
                    discover_tcp_ports(
                        address,
                        exclude=already_checked,
                        timeout=FULL_TCP_SCAN_TIMEOUT,
                        workers=FULL_TCP_SCAN_WORKERS,
                    )
                )
                open_ports = dedupe_port_records(open_ports)
                if progress_id:
                    emit(progress_id, f"Порт-скан {address}: найдено открытых TCP-портов {len(open_ports)}")
            if not open_ports and not single_target:
                return None
            if open_ports and not single_target:
                already_checked = {int(item["port"]) for item in open_ports}
                remaining = [port for port in COMMON_TCP_PORTS if port not in already_checked]
                open_ports.extend(scan_host_ports(address, remaining, timeout=0.28))
                open_ports.sort(key=lambda item: int(item["port"]))
            hostname = reverse_hostname(address) if open_ports else ""
            os_guess, roles, confidence = infer_system_profile(open_ports)
            legion_profile = legion_device_profile(open_ports, hostname=hostname, os_match=os_guess)
            mac = local_arp_entry(address) if open_ports else {}
            return {
                "ip": address,
                "status": "online" if open_ports else "no_response",
                "hostname": hostname,
                "mac": mac.get("mac", ""),
                "interface": mac.get("interface", ""),
                "os_guess": os_guess,
                "os_confidence": confidence,
                "roles": roles,
                "device_categories": legion_profile.get("device_categories", []),
                "legion_classification": legion_profile.get("classification", []),
                "open_ports": open_ports,
            }

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(inspect, address): address for address in addresses}
            progress_step = max(1, len(futures) // 4)
            for completed, future in enumerate(as_completed(futures), 1):
                try:
                    record = future.result()
                except Exception:
                    record = None
                if record:
                    records.append(record)
                    if progress_id and record.get("status") == "online":
                        emit(progress_id, f"Найден узел {record['ip']}: открытых TCP-портов {len(record['open_ports'])}")
                if progress_id and completed % progress_step == 0 and len(futures) > 1:
                    emit(progress_id, f"Сетевая инвентаризация: обработано {completed}/{len(futures)} адресов")
        records.sort(key=lambda item: ipaddress.ip_address(item["ip"]))

        findings: list[Finding] = []
        for record in records:
            findings.extend(system_exposure_findings(record))
        responsive = sum(1 for item in records if item["status"] == "online")
        summary = {
            "network": network.with_prefixlen,
            "address_count": len(addresses),
            "responsive_hosts": responsive,
            "discovery_method": "TCP connect",
            "discovery_ports": "1-65535" if single_target else list(DISCOVERY_TCP_PORTS),
            "port_scan_mode": "full_tcp_single_host" if single_target else "cidr_discovery_then_common_ports",
            "limit": 256,
        }
        notes = []
        if ctx.target_kind == "network":
            notes.append(
                "Встроенный discovery считает узел доступным при ответе на один из контрольных TCP-портов; "
                "узлы с полностью фильтруемыми портами может дополнительно обнаружить Nmap."
            )
        return {
            "assets": {"network_inventory": summary, "systems": records},
            "findings": findings,
            "notes": notes,
        }


class FileSystemAnalyzer:
    """Read-only audit for a local or mounted server filesystem path."""

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        root_text = ctx.filesystem_path or ctx.network or ctx.original_target
        root = Path(root_text).expanduser()
        progress_id = ctx.progress_id or ctx.scan_id
        assets: dict[str, Any] = {
            "filesystem": {
                "root": str(root),
                "mode": "read-only",
                "limits": {
                    "max_files": FS_MAX_FILES,
                    "max_read_bytes_per_file": FS_MAX_READ_BYTES,
                    "max_asset_items_per_section": FS_MAX_ASSET_ITEMS,
                },
                "statistics": {
                    "files_seen": 0,
                    "files_analyzed": 0,
                    "directories_seen": 0,
                    "bytes_seen": 0,
                    "unreadable_files": 0,
                    "skipped_directories": 0,
                    "large_files": 0,
                },
                "webshell_candidates": [],
                "secret_candidates": [],
                "suspicious_files": [],
                "autostart_files": [],
                "executable_candidates": [],
                "tool_checks": {},
            }
        }
        notes: list[str] = []
        findings: list[Finding] = []
        fs = assets["filesystem"]
        stats = fs["statistics"]

        if not root.exists():
            return {
                "assets": assets,
                "findings": [
                    Finding(
                        "Файловый путь недоступен",
                        "Средний",
                        "Filesystem audit",
                        "Built-in filesystem",
                        "Указанный путь не существует или не смонтирован на машине, где запущен анализатор.",
                        evidence=str(root),
                        remediation="Смонтируйте каталог сервера по SSHFS/NFS/SMB или укажите корректный локальный путь.",
                        cwe=["CWE-668"],
                    )
                ],
                "notes": ["Файловый аудит не выполнен: путь не найден."],
            }

        if progress_id:
            emit(progress_id, f"Файловый аудит: обхожу {root}")

        for path in iter_filesystem_targets(root, stats):
            if stats["files_seen"] >= FS_MAX_FILES:
                notes.append(f"Файловый аудит остановлен на лимите {FS_MAX_FILES} файлов; укажите более узкий каталог для полной проверки.")
                break
            stats["files_seen"] += 1
            try:
                stat_result = path.lstat()
            except OSError:
                stats["unreadable_files"] += 1
                continue
            if not path.is_file():
                continue
            size = int(stat_result.st_size)
            stats["bytes_seen"] += size
            if size > FS_LARGE_FILE_BYTES:
                stats["large_files"] += 1
            record = filesystem_file_record(path, root, stat_result)
            stats["files_analyzed"] += 1

            reasons = suspicious_filename_reasons(path, root)
            if reasons:
                append_limited(fs["suspicious_files"], {**record, "reasons": reasons})

            if is_autostart_artifact(path, root):
                append_limited(fs["autostart_files"], {**record, "reason": "autostart/persistence location"})

            if is_executable_candidate(path, root, stat_result):
                append_limited(fs["executable_candidates"], {**record, "reason": "executable in upload/tmp/web content location"})

            if size <= FS_MAX_READ_BYTES and looks_textual(path):
                text = read_text_sample(path)
                if text:
                    webshell_matches = pattern_matches(text, FS_WEBSHELL_PATTERNS)
                    if webshell_matches:
                        append_limited(
                            fs["webshell_candidates"],
                            {**record, "matches": webshell_matches, "sha256": sha256_file(path)},
                        )
                    secret_matches = pattern_matches(text, FS_SECRET_PATTERNS)
                    if secret_matches:
                        append_limited(fs["secret_candidates"], {**record, "matches": secret_matches})
                    obfuscation = obfuscation_reasons(text, path)
                    if obfuscation:
                        append_limited(
                            fs["suspicious_files"],
                            {**record, "reasons": obfuscation, "sha256": sha256_file(path)},
                        )
            elif size > FS_MAX_READ_BYTES:
                reasons = suspicious_binary_reasons(path, root, stat_result)
                if reasons:
                    append_limited(
                        fs["suspicious_files"],
                        {**record, "reasons": reasons, "sha256": sha256_file(path)},
                    )

            if progress_id and stats["files_seen"] in {1000, 5000, 10000, 15000}:
                emit(progress_id, f"Файловый аудит: просмотрено {stats['files_seen']} файлов")

        findings.extend(filesystem_findings(fs))
        findings.extend(run_clamav_if_available(ctx, root, fs, notes))
        findings.extend(run_yara_if_available(ctx, root, fs, notes))
        notes.extend(filesystem_notes(fs))
        return {"assets": assets, "findings": findings, "notes": notes}


def iter_filesystem_targets(root: Path, stats: dict[str, Any]):
    if root.is_file():
        yield root
        return

    def onerror(_error: OSError) -> None:
        stats["skipped_directories"] += 1

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=onerror, followlinks=False):
        current = Path(dirpath)
        stats["directories_seen"] += 1
        kept: list[str] = []
        for dirname in dirnames:
            child = current / dirname
            if should_skip_filesystem_dir(child):
                stats["skipped_directories"] += 1
            else:
                kept.append(dirname)
        dirnames[:] = kept
        for filename in filenames:
            yield current / filename


def should_skip_filesystem_dir(path: Path) -> bool:
    name = path.name.lower()
    if name in FS_SKIP_DIR_NAMES:
        return True
    if name == "objects" and path.parent.name == ".git":
        return True
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    full = str(path)
    return any(full == prefix or full.startswith(prefix + os.sep) for prefix in FS_SKIP_ABSOLUTE_PREFIXES)


def filesystem_file_record(path: Path, root: Path, stat_result: os.stat_result) -> dict[str, Any]:
    try:
        relative = str(path.relative_to(root))
    except ValueError:
        relative = str(path)
    return {
        "path": str(path),
        "relative_path": relative,
        "size": int(stat_result.st_size),
        "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat_result.st_mtime)),
        "mode": oct(stat_result.st_mode & 0o777),
    }


def append_limited(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if len(items) < FS_MAX_ASSET_ITEMS:
        items.append(item)


def relative_path_text(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace(os.sep, "/").lower()
    except ValueError:
        return str(path).replace(os.sep, "/").lower()


def path_parts_lower(path: Path, root: Path) -> set[str]:
    rel = relative_path_text(path, root)
    return {part for part in rel.split("/") if part}


def is_upload_location(path: Path, root: Path) -> bool:
    return bool(path_parts_lower(path, root) & FS_UPLOAD_MARKERS)


def suspicious_filename_reasons(path: Path, root: Path) -> list[str]:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    reasons: list[str] = []
    if has_embedded_web_exec_extension(path):
        reasons.append("double extension that can mask executable web code")
    if suffix in {".phtml", ".phar", ".jspx", ".asax"}:
        reasons.append("rare executable web extension")
    if is_upload_location(path, root) and suffix in FS_WEB_EXEC_SUFFIXES:
        reasons.append("web-executable extension inside upload/tmp/media path")
    if lower_name.endswith(("~", ".bak", ".old", ".save", ".orig")) and re.search(r"(?i)(config|settings|secret|password|backup|dump|db)", lower_name):
        reasons.append("backup copy of sensitive-looking configuration/data file")
    return reasons


def is_autostart_artifact(path: Path, root: Path) -> bool:
    rel = "/" + relative_path_text(path, root)
    name = path.name.lower()
    return (
        any(marker in rel for marker in FS_AUTOSTART_MARKERS)
        or name in {"crontab", "rc.local", "authorized_keys", ".bashrc", ".zshrc", ".profile"}
        or name.endswith((".service", ".timer", ".plist"))
    )


def is_executable_candidate(path: Path, root: Path, stat_result: os.stat_result) -> bool:
    executable_bit = bool(stat_result.st_mode & 0o111)
    suffix = path.suffix.lower()
    return is_upload_location(path, root) and (executable_bit or suffix in FS_WEB_EXEC_SUFFIXES or has_embedded_web_exec_extension(path))


def looks_textual(path: Path) -> bool:
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in FS_TEXT_SUFFIXES:
        return True
    if has_embedded_web_exec_extension(path):
        return True
    return (
        lower_name.startswith(".env")
        or lower_name in {"authorized_keys", "id_rsa", "id_ed25519", "credentials", "settings", "config"}
        or lower_name.endswith((".service", ".timer", ".plist", ".conf", ".config", ".ini"))
    )


def has_embedded_web_exec_extension(path: Path) -> bool:
    return bool(re.search(r"\.(?:php|phtml|phar|jsp|jspx|asp|aspx)\.(?:jpg|jpeg|png|gif|txt|bak|old|zip)$", path.name.lower()))


def read_text_sample(path: Path) -> str:
    try:
        data = path.read_bytes()[:FS_MAX_READ_BYTES]
    except OSError:
        return ""
    if b"\x00" in data[:4096]:
        return ""
    return data.decode("utf-8", errors="ignore")


def pattern_matches(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    lines = text.splitlines()
    for label, pattern in patterns:
        match = pattern.search(text)
        if not match:
            continue
        line_numbers = [index for index, line in enumerate(lines, 1) if pattern.search(line)][:5]
        if not line_numbers:
            line_numbers = [text[: match.start()].count("\n") + 1]
        matches.append({"pattern": label, "lines": line_numbers})
        if len(matches) >= 12:
            break
    return matches


def obfuscation_reasons(text: str, path: Path) -> list[str]:
    suffix = path.suffix.lower()
    reasons: list[str] = []
    if suffix in FS_WEB_EXEC_SUFFIXES and re.search(r"[A-Za-z0-9+/]{220,}={0,2}", text):
        reasons.append("long base64-like blob in executable web file")
    if suffix in {".php", ".phtml", ".phar"} and re.search(r"(?is)(gzinflate|str_rot13|base64_decode).{0,160}(eval|assert)\s*\(", text):
        reasons.append("PHP obfuscation chain with dynamic execution")
    if suffix == ".js" and re.search(r"(?is)(eval\s*\(\s*atob|new Function\s*\()", text):
        reasons.append("JavaScript dynamic execution/obfuscation")
    return reasons


def suspicious_binary_reasons(path: Path, root: Path, stat_result: os.stat_result) -> list[str]:
    if is_executable_candidate(path, root, stat_result):
        return ["large executable or web-executable file in upload/tmp/media path"]
    return []


def sha256_file(path: Path, max_bytes: int = FS_LARGE_FILE_BYTES) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def filesystem_findings(fs: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    webshells = fs.get("webshell_candidates", [])
    secrets = fs.get("secret_candidates", [])
    suspicious = fs.get("suspicious_files", [])
    autostart = fs.get("autostart_files", [])
    executables = fs.get("executable_candidates", [])
    if webshells:
        findings.append(
            Finding(
                "Обнаружены признаки web-shell/backdoor в файлах",
                "Критический",
                "Malware / Web shell",
                "Built-in filesystem",
                "В файловой системе найдены файлы с паттернами удалённого выполнения кода, web-shell или обфускации. Это требует ручной верификации и срочного реагирования.",
                evidence=json.dumps(webshells[:8], ensure_ascii=False),
                remediation="Изолируйте копию файлов, проверьте журнал доступа, восстановите файлы из доверенного источника, смените секреты и закройте исходный вектор загрузки/выполнения.",
                cwe=["CWE-94", "CWE-78", "CWE-434"],
                confidence="Высокая",
            )
        )
    if secrets:
        findings.append(
            Finding(
                "Найдены потенциальные секреты в файлах",
                "Высокий",
                "Secrets exposure",
                "Built-in filesystem",
                "Файлы похожи на содержащие приватные ключи, токены или пароли. Значения секретов в отчёт намеренно не выводятся.",
                evidence=json.dumps(secrets[:10], ensure_ascii=False),
                remediation="Проверьте указанные файлы, уберите секреты из web-root/репозитория, ротируйте ключи и настройте secret scanning в CI.",
                cwe=["CWE-200", "CWE-522", "CWE-798"],
                confidence="Средняя",
            )
        )
    if executables:
        findings.append(
            Finding(
                "Исполняемые файлы или web-скрипты находятся в upload/tmp-зоне",
                "Высокий",
                "Unsafe file upload",
                "Built-in filesystem",
                "В каталогах загрузок, временных файлов или media найдены исполняемые файлы/web-скрипты. Это типичный признак риска RCE через загрузку файла.",
                evidence=json.dumps(executables[:10], ensure_ascii=False),
                remediation="Запретите выполнение скриптов в upload/tmp/media, храните загрузки вне web-root, проверяйте MIME/расширения и используйте случайные имена.",
                cwe=["CWE-434"],
                confidence="Средняя",
            )
        )
    if suspicious:
        findings.append(
            Finding(
                "Найдены подозрительные имена, расширения или обфускация файлов",
                "Средний",
                "Suspicious files",
                "Built-in filesystem",
                "Часть файлов похожа на замаскированные скрипты, резервные копии чувствительных файлов или обфусцированный код.",
                evidence=json.dumps(suspicious[:12], ensure_ascii=False),
                remediation="Проверьте происхождение файлов, сравните с эталонной поставкой приложения и удаляйте только после подтверждения владельцем системы.",
                cwe=["CWE-200", "CWE-434"],
                confidence="Низкая",
            )
        )
    if autostart:
        findings.append(
            Finding(
                "Найдены файлы автозапуска или persistence-точки",
                "Средний",
                "Persistence",
                "Built-in filesystem",
                "Обнаружены cron/systemd/LaunchAgent/authorized_keys или похожие точки закрепления. Это не всегда вредоносно, но требует контроля.",
                evidence=json.dumps(autostart[:12], ensure_ascii=False),
                remediation="Сверьте задания автозапуска и SSH-ключи с утверждённой конфигурацией, удалите неизвестные записи и проверьте историю изменений.",
                cwe=["CWE-284"],
                confidence="Низкая",
            )
        )
    return findings


def filesystem_notes(fs: dict[str, Any]) -> list[str]:
    stats = fs.get("statistics", {})
    notes = ["Файловый аудит выполнен в read-only режиме: файлы не удалялись, не лечились и не помещались в карантин."]
    if stats.get("skipped_directories"):
        notes.append(f"Файловый аудит пропустил служебные/тяжёлые каталоги: {stats['skipped_directories']}.")
    if stats.get("unreadable_files"):
        notes.append(f"Часть файлов недоступна для чтения текущему пользователю: {stats['unreadable_files']}.")
    return notes


def run_clamav_if_available(ctx: ScanContext, root: Path, fs: dict[str, Any], notes: list[str]) -> list[Finding]:
    path = find_tool_binary("clamscan")
    check: dict[str, Any] = {"available": bool(path), "path": path or "", "status": "not_available"}
    fs.setdefault("tool_checks", {})["clamscan"] = check
    if not path:
        notes.append("ClamAV не найден: антивирусный слой пропущен, встроенные сигнатуры уже применены.")
        return []
    progress_id = ctx.progress_id or ctx.scan_id
    if progress_id:
        emit(progress_id, "ClamAV: проверяю файловую цель")
    timeout = full_completion_timeout("clamscan", 300) if ctx.wait_for_completion else 300
    result = run_command(
        [path, "-r", "--infected", "--no-summary", "--max-filesize=25M", "--max-scansize=200M", str(root)],
        timeout=timeout,
        progress=(lambda message: emit(progress_id, f"ClamAV: {message}")) if progress_id else None,
    )
    stdout = result.get("stdout", "")
    infected = [line.strip() for line in stdout.splitlines() if " FOUND" in line]
    check.update(
        {
            "status": "timeout" if result.get("timed_out") else "completed",
            "returncode": result.get("returncode"),
            "timed_out": bool(result.get("timed_out")),
            "infected_count": len(infected),
            "infected": infected[:50],
            "stderr_tail": result.get("stderr", "")[-1200:],
        }
    )
    if result.get("timed_out"):
        notes.append("ClamAV остановлен предохранителем; используйте более узкий каталог или запустите clamscan отдельно.")
    if infected:
        return [
            Finding(
                "ClamAV обнаружил вредоносные файлы",
                "Критический",
                "Malware",
                "ClamAV",
                "Антивирусный движок сообщил совпадения по известным сигнатурам вредоносного ПО.",
                evidence=json.dumps(infected[:20], ensure_ascii=False),
                remediation="Изолируйте систему/копию файлов, подтвердите срабатывания, восстановите из доверенного бэкапа и выполните расследование точки входа.",
                cwe=["CWE-506"],
                confidence="Высокая",
            )
        ]
    if result.get("returncode") not in {0, 1, 124}:
        notes.append(f"ClamAV завершился с кодом {result.get('returncode')}: {result.get('stderr', '')[-300:]}")
    return []


def run_yara_if_available(ctx: ScanContext, root: Path, fs: dict[str, Any], notes: list[str]) -> list[Finding]:
    yara = find_tool_binary("yara")
    rule_files = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara")) if RULES_DIR.exists() else []
    check: dict[str, Any] = {
        "available": bool(yara),
        "path": yara or "",
        "rules": [str(path) for path in rule_files],
        "status": "not_available" if not yara else "no_rules",
    }
    fs.setdefault("tool_checks", {})["yara"] = check
    if not yara:
        notes.append("YARA не найдена: сигнатурный слой YARA пропущен.")
        return []
    if not rule_files:
        notes.append("YARA найдена, но локальные правила rules/*.yar отсутствуют.")
        return []
    progress_id = ctx.progress_id or ctx.scan_id
    if progress_id:
        emit(progress_id, "YARA: проверяю файловую цель по локальным правилам")
    timeout = full_completion_timeout("yara", 240) if ctx.wait_for_completion else 240
    result = run_command(
        [yara, "-r", str(rule_files[0]), str(root)],
        timeout=timeout,
        progress=(lambda message: emit(progress_id, f"YARA: {message}")) if progress_id else None,
    )
    matches = [line.strip() for line in result.get("stdout", "").splitlines() if line.strip()]
    check.update(
        {
            "status": "timeout" if result.get("timed_out") else "completed",
            "returncode": result.get("returncode"),
            "timed_out": bool(result.get("timed_out")),
            "match_count": len(matches),
            "matches": matches[:80],
            "stderr_tail": result.get("stderr", "")[-1200:],
        }
    )
    if result.get("timed_out"):
        notes.append("YARA остановлена предохранителем; используйте более узкий каталог или запустите yara отдельно.")
    if matches:
        return [
            Finding(
                "YARA обнаружила подозрительные файлы",
                "Высокий",
                "Malware / Suspicious code",
                "YARA",
                "Локальные YARA-правила нашли совпадения с web-shell, обфускацией или подозрительным кодом.",
                evidence=json.dumps(matches[:30], ensure_ascii=False),
                remediation="Проверьте совпавшие файлы вручную, сопоставьте с журналами доступа и восстановите изменённые компоненты из доверенного источника.",
                cwe=["CWE-94", "CWE-506"],
                confidence="Средняя",
            )
        ]
    if result.get("returncode") not in {0, 1, 124}:
        notes.append(f"YARA завершилась с кодом {result.get('returncode')}: {result.get('stderr', '')[-300:]}")
    return []


def finalize_filesystem_step(ctx: ScanContext, assets: dict[str, Any], findings: list[Finding], notes: list[str]) -> None:
    if ctx.target_kind == "filesystem":
        return
    if assets.get("filesystem"):
        return

    file_services = collect_file_service_ports(assets)
    if file_services:
        reason = (
            "Файловая система сервера не смонтирована в анализаторе, поэтому содержимое файлов не читалось. "
            "При этом найдены сетевые файловые сервисы — проверьте, должны ли они быть доступны."
        )
        status = "skipped-file-services-detected"
        findings.append(
            Finding(
                "Доступны сетевые файловые сервисы",
                "Средний",
                "File service exposure",
                "Built-in filesystem gate",
                "Сканирование портов обнаружило сервисы, через которые потенциально может быть доступна файловая система или передача файлов. Содержимое не проверялось без смонтированного/разрешённого доступа.",
                evidence=json.dumps(file_services[:20], ensure_ascii=False),
                remediation="Если сервис нужен — ограничьте доступ VPN/ACL, проверьте аутентификацию и права шар. Для анализа содержимого смонтируйте разрешённый каталог и запустите проверку повторно.",
                cwe=["CWE-284", "CWE-200"],
                confidence="Средняя",
            )
        )
    else:
        reason = (
            "Файловая система цели не открыта как локальный/смонтированный путь и явные сетевые файловые сервисы не найдены; "
            "файловый аудит безопасно пропущен."
        )
        status = "skipped-not-accessible"

    assets["filesystem"] = {
        "status": status,
        "checked": False,
        "mode": "not-mounted",
        "reason": reason,
        "file_service_ports": file_services,
        "how_to_enable": "Если есть права на сервер, смонтируйте нужный каталог через SSHFS/SMB/NFS и укажите его как file:///путь.",
    }
    notes.append(reason)
    progress_id = ctx.progress_id or ctx.scan_id
    if progress_id:
        emit(progress_id, f"Файловый аудит: {reason}", "warning")


def collect_file_service_ports(assets: dict[str, Any]) -> list[dict[str, Any]]:
    observed: dict[tuple[str, int, str], dict[str, Any]] = {}

    def add_port(item: dict[str, Any], default_host: str = "") -> None:
        try:
            port = int(item.get("port", 0) or 0)
        except (TypeError, ValueError):
            return
        service_text = " ".join(str(item.get(key, "")) for key in ("service", "product", "version")).lower()
        if port not in FILE_SERVICE_PORTS and not any(token in service_text for token in ["ftp", "smb", "netbios", "nfs", "rsync", "sftp"]):
            return
        host = str(item.get("host") or item.get("ip") or default_host or "")
        protocol = str(item.get("protocol") or "tcp")
        record = {
            "host": host,
            "port": port,
            "protocol": protocol,
            "service": item.get("service") or FILE_SERVICE_PORTS.get(port, "file-service"),
            "product": item.get("product", ""),
            "version": item.get("version", ""),
        }
        observed[(host, port, protocol)] = record

    for system in assets.get("systems", []):
        host = str(system.get("ip", ""))
        for port_item in system.get("open_ports", []):
            add_port(port_item, host)

    for section in ("nmap", "nmap_fallback"):
        data = assets.get(section, {})
        for port_item in data.get("ports", []) if isinstance(data, dict) else []:
            add_port(port_item)

    return sorted(observed.values(), key=lambda item: (item.get("host", ""), int(item.get("port", 0))))


class DNSAnalyzer:
    def run(self, ctx: ScanContext) -> dict[str, Any]:
        records = {
            "A": dig_records(ctx.host, "A"),
            "AAAA": dig_records(ctx.host, "AAAA"),
            "MX": dig_records(ctx.host, "MX"),
            "NS": dig_records(ctx.host, "NS"),
            "SOA": dig_records(ctx.host, "SOA"),
            "CAA": dig_records(ctx.host, "CAA"),
            "TXT": dig_records(ctx.host, "TXT"),
            "DMARC": dig_records(f"_dmarc.{ctx.host}", "TXT"),
            "DNSKEY": dig_records(ctx.host, "DNSKEY"),
        }
        findings: list[Finding] = []

        srv_names = [
            "_ldap._tcp",
            "_kerberos._tcp",
            "_sip._tcp",
            "_sip._udp",
            "_sips._tcp",
            "_xmpp-server._tcp",
            "_autodiscover._tcp",
        ]
        srv_records = {
            prefix: values
            for prefix in srv_names
            if (values := dig_records(f"{prefix}.{ctx.host}", "SRV"))
        }
        wildcard_host = f"bdu-wildcard-{uuid.uuid4().hex[:12]}.{ctx.host}"
        wildcard = {
            "test_host": wildcard_host,
            "A": dig_records(wildcard_host, "A"),
            "AAAA": dig_records(wildcard_host, "AAAA"),
            "CNAME": dig_records(wildcard_host, "CNAME"),
        }
        wildcard["detected"] = bool(wildcard["A"] or wildcard["AAAA"] or wildcard["CNAME"])
        zone_transfers = check_zone_transfers(ctx.host, records["NS"])
        if any(item.get("allowed") for item in zone_transfers):
            exposed = [item.get("nameserver", "") for item in zone_transfers if item.get("allowed")]
            findings.append(
                Finding(
                    "DNS-зона допускает полный перенос AXFR",
                    "Высокий",
                    "DNS zone transfer",
                    "Built-in DNS",
                    "Авторитетный DNS-сервер вернул содержимое зоны на AXFR-запрос. Это раскрывает внутренние имена и структуру инфраструктуры.",
                    evidence=", ".join(exposed),
                    remediation="Запретите AXFR для произвольных клиентов и разрешите перенос зоны только доверенным secondary DNS по ACL/TSIG.",
                    cwe=["CWE-200"],
                    confidence="Высокая",
                )
            )

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
        wildcard_values = set(wildcard["A"] + wildcard["AAAA"] + wildcard["CNAME"])
        for label in COMMON_SUBDOMAINS:
            name = f"{label}.{ctx.host}"
            a = dig_records(name, "A")
            cname = dig_records(name, "CNAME")
            values = set(a + cname)
            if values and (not wildcard["detected"] or values != wildcard_values):
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

        records["SRV"] = srv_records
        records["DNSSEC"] = {"enabled": bool(records["DNSKEY"]), "dnskey_count": len(records["DNSKEY"])}
        records["wildcard"] = wildcard
        records["zone_transfers"] = zone_transfers
        notes = []
        if wildcard["detected"]:
            notes.append("Built-in DNS обнаружил wildcard-запись; совпадающие ответы исключены из списка поддоменов.")
        if not shutil.which("dig"):
            notes.append("Утилита dig не найдена: расширенные NS/MX/SRV/DNSSEC/AXFR-проверки ограничены.")
        return {"assets": {"dns": records, "subdomains": subdomains}, "findings": findings, "notes": notes}


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


# Бюджеты прикладного анализатора: держат проверку быстрой и вежливой даже на
# большом приложении. Активные пробы шлются только в активном режиме.
WEB_SCENARIO_MAX_PAGES = 40
WEB_SCENARIO_MAX_POINTS = 30
WEB_SCENARIO_MAX_PARAMS = 5
WEB_SCENARIO_REQUEST_BUDGET = 600

SECRET_RESPONSE_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe-подобный live-секрет", re.compile(r"\bsk_live_[0-9A-Za-z]{6,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}")),
    ("Приватный ключ", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Секрет в JSON-поле", re.compile(r"\"(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|password)\"\s*:\s*\"[^\"]{6,}\"", re.I)),
]

PASSWD_RE = re.compile(r"root:.*?:0:0:", re.S)
UID_RE = re.compile(r"uid=\d+\(")

# Статические ресурсы не являются страницами приложения: их исходник (особенно
# JS фронтенда) может содержать строки `<form>` и литералы маркеров, что давало
# бы ложные срабатывания. Такие ссылки не краулятся и не парсятся как формы.
STATIC_ASSET_EXT = (
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
    ".gz", ".mp4", ".webm", ".mp3", ".wasm",
)

DEBUG_TRACEBACK_MARKERS = ("Werkzeug Debugger", "Traceback (most recent call last)", "class=\"traceback\"")


def is_static_asset(url: str) -> bool:
    return urlparse(url).path.lower().rsplit("?", 1)[0].endswith(STATIC_ASSET_EXT)


_ROUTE_ID_SEGMENT = re.compile(r"^(\d+|[A-Za-z]+[-_]?\d+)$")


def route_template(action: str) -> str:
    """Свернуть идентификаторы в пути к шаблону маршрута.

    /product/chair-01/review и /product/lamp-02/review -> /product/{id}/review,
    чтобы один маршрут не порождал дубли находок и лишние пробы.
    """
    parsed = urlparse(action)
    segments = ["{id}" if _ROUTE_ID_SEGMENT.match(seg) else seg for seg in parsed.path.split("/")]
    return f"{parsed.scheme}://{parsed.netloc}{'/'.join(segments)}"


def mask_secret(value: str) -> str:
    value = (value or "").strip()
    if len(value) <= 8:
        return (value[:2] + "***") if value else "***"
    return value[:4] + "***" + value[-2:]


class WebScenarioAnalyzer:
    """Безопасные прикладные проверки веб-приложения.

    Краулит страницы того же origin, собирает формы и GET-точки с параметрами и
    проверяет их по классам уязвимостей. Детект — по маркерам в ответе приложения
    и по наблюдаемому поведению, без реальной эксплуатации. Пассивные проверки
    (CORS, доверие к X-Forwarded-For, раскрытие debug/секретов) безопасны и
    выполняются всегда; пробы атакующей формы (SQLi/XSS/инъекции/IDOR/оплата/
    перебор входа) — только в активном режиме.
    """

    label = "Прикладные проверки веб-приложения"

    # (заголовок находки, список CWE, полезная нагрузка, детектор по телу ответа)
    MARKER_PROBES: list[tuple[str, list[str], str, Callable[[str], bool]]] = [
        ("Внедрение команд ОС (OS command injection)", ["CWE-78"], "127.0.0.1;id",
         lambda body: "INJECTION_MARKER" in body or bool(UID_RE.search(body))),
        ("Server-Side Template Injection (SSTI)", ["CWE-1336", "CWE-94"], "{{7*7}}",
         lambda body: "SSTI_MARKER" in body or ("{{7*7}}" not in body and re.search(r"(^|[^0-9])49([^0-9]|$)", body) is not None and "TEMPLATE_MARKER" in body)),
        ("Обработка внешних сущностей XML (XXE)", ["CWE-611"], "<!DOCTYPE bdu [<!ENTITY x \"bdu\">]><root>&x;</root>",
         lambda body: "XXE_MARKER" in body),
        ("Небезопасная десериализация", ["CWE-502"], "bdu-deserialize-probe",
         lambda body: "SERIALIZATION_MARKER" in body),
    ]

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        self.ctx = ctx
        self.host = ctx.host
        self.headers = scan_headers(ctx)
        self.active = ctx.active_mode
        self._budget = WEB_SCENARIO_REQUEST_BUDGET
        self._reported: set[tuple[str, str]] = set()
        self._debug_evidence: str = ""

        findings: list[Finding] = []
        notes: list[str] = []
        root = base_url(ctx.target_url)

        pages = self._crawl(ctx, root)
        if not pages:
            return {"assets": {"web_scenarios": {"status": "target-unreachable"}}, "findings": [], "notes": []}

        points = self._collect_points(pages)

        # Пассивные проверки — всегда.
        findings += self._check_cors(root)
        findings += self._check_xff_trust(root, pages)
        findings += self._check_debug_and_secrets(pages)

        if self.active:
            for point in points:
                findings += self._probe_point(point)
            findings += self._probe_idor(points, pages)
            findings += self._probe_sensitive_forms(points)
            findings += self._probe_ssrf(points)
        else:
            notes.append(
                "Прикладные активные пробы (SQLi/XSS/инъекции/IDOR/оплата/вход/SSRF) пропущены: "
                "включите активный профиль проверки."
            )

        if self._debug_evidence:
            findings.append(
                Finding(
                    "Раскрытие отладочной трассировки (debug-режим)",
                    "Высокий",
                    "Security misconfiguration",
                    self.label,
                    "При ошибке приложение возвращает подробную трассировку стека (framework debug): исходный код, пути на сервере и, у Werkzeug, интерактивную консоль. Это раскрывает внутреннее устройство и может приводить к выполнению кода.",
                    evidence=f"{self._debug_evidence}: ответ содержит отладочную трассировку/консоль.",
                    remediation="Отключите debug в продакшене (debug=False, FLASK_DEBUG=0); отдавайте обобщённые страницы ошибок и логируйте детали на сервере.",
                    cwe=["CWE-489", "CWE-215"],
                    confidence="Высокая",
                )
            )

        assets = {
            "web_scenarios": {
                "status": "completed",
                "pages_crawled": len(pages),
                "injection_points": len(points),
                "active_mode": self.active,
                "requests_used": WEB_SCENARIO_REQUEST_BUDGET - self._budget,
            }
        }
        return {"assets": assets, "findings": findings, "notes": notes}

    # --- транспорт -------------------------------------------------------

    def _spend(self) -> bool:
        if self._budget <= 0:
            return False
        self._budget -= 1
        return True

    def _wrap(self, resp: dict[str, Any], url: str) -> dict[str, Any]:
        body = resp.get("body", "") or ""
        data = resp.get("json")
        if data is None and body:
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                data = None
        headers = resp.get("headers", {}) or {}
        ctype = ""
        for key, value in headers.items():
            if key.lower() == "content-type":
                ctype = value or ""
                break
        if not self._debug_evidence and body and any(marker in body for marker in DEBUG_TRACEBACK_MARKERS):
            self._debug_evidence = url
        return {
            "url": url,
            "status": resp.get("status"),
            "body": body,
            "json": data,
            "headers": headers,
            "content_type": ctype,
            "error": resp.get("error"),
        }

    @staticmethod
    def _is_error_page(resp: dict[str, Any]) -> bool:
        status = resp.get("status") or 0
        body = resp.get("body") or ""
        return status >= 500 or any(marker in body for marker in DEBUG_TRACEBACK_MARKERS)

    def _get(self, url: str, params: dict[str, Any] | None = None, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        if not self._spend():
            return {"url": url, "status": None, "body": "", "json": None, "headers": {}, "content_type": "", "error": "request budget exhausted"}
        target = url
        if params:
            query = urlencode({key: ("" if value is None else str(value)) for key, value in params.items()})
            target = url + ("&" if "?" in url else "?") + query
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        return self._wrap(fetch(target, "GET", read_limit=80_000, headers=headers), target)

    def _post(self, url: str, payload: dict[str, Any], extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        if not self._spend():
            return {"url": url, "status": None, "body": "", "json": None, "headers": {}, "content_type": "", "error": "request budget exhausted"}
        headers = dict(self.headers)
        if extra_headers:
            headers.update(extra_headers)
        return self._wrap(post_form(url, payload, headers=headers), url)

    def _request(self, point: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
        values = dict(point["values"])
        values.update(overrides)
        if point["method"] == "POST":
            return self._post(point["action"], values)
        return self._get(point["action"], values)

    def _emit_once(self, vuln_class: str, action: str) -> bool:
        key = (vuln_class, route_template(action.split("?")[0]))
        if key in self._reported:
            return False
        self._reported.add(key)
        return True

    # --- крауль и сбор точек --------------------------------------------

    def _crawl(self, ctx: ScanContext, root: str) -> dict[str, dict[str, Any]]:
        pages: dict[str, dict[str, Any]] = {}
        queue: list[str] = []
        seen: set[str] = set()
        seen_routes: set[str] = set()

        def enqueue(candidate: str) -> None:
            # По одному представителю на шаблон маршрута: /product/{id} краулится
            # один раз, а не по разу на каждый товар — бюджет идёт на новые пути.
            if candidate in seen or is_static_asset(candidate):
                return
            route = route_template(candidate.split("?")[0])
            if route in seen_routes:
                return
            seen.add(candidate)
            seen_routes.add(route)
            queue.append(candidate)

        for seed in (ctx.target_url, root + "/"):
            enqueue(seed)
        while queue and len(pages) < WEB_SCENARIO_MAX_PAGES and self._budget > 0:
            url = queue.pop(0)
            resp = self._get(url)
            if resp.get("error") or not resp.get("status"):
                continue
            pages[url] = resp
            body = resp["body"]
            # Ссылки и формы берём только со страниц, отдающих HTML, — не со
            # случайно связанного JSON/текста и тем более не со статики.
            if "html" not in resp["content_type"].lower() and "<html" not in body.lower():
                continue
            for link in extract_in_scope_links(body, url, ctx.host):
                enqueue(link)
        return pages

    def _collect_points(self, pages: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        points: list[dict[str, Any]] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()

        def add(method: str, action: str, names: list[str], values: dict[str, Any], has_password: bool = False) -> None:
            names = [name for name in names if name][:WEB_SCENARIO_MAX_PARAMS]
            if not names:
                return
            key = (method, route_template(action.split("?")[0]), tuple(sorted(names)))
            if key in seen:
                return
            seen.add(key)
            points.append({"method": method, "action": action, "params": names, "values": values, "has_password": has_password})

        for url, resp in pages.items():
            body = resp["body"]
            is_html = "html" in (resp["content_type"] or "").lower() or "<html" in body.lower()
            if is_html and "<form" in body.lower():
                for form in extract_form_security_details(body, url):
                    names = list(form["input_names"])
                    add(form["method"], form["action"], names, {name: "bdu" for name in names}, bool(form.get("has_password")))
            parsed = urlparse(url)
            if parsed.query:
                parsed_qs = parse_qs(parsed.query)
                base = url.split("?")[0]
                add("GET", base, list(parsed_qs), {key: (vals[0] if vals else "bdu") for key, vals in parsed_qs.items()})

        return points[:WEB_SCENARIO_MAX_POINTS]

    # --- пассивные проверки ---------------------------------------------

    def _check_cors(self, root: str) -> list[Finding]:
        probe_origin = "https://bdu-cors-probe.example"
        resp = self._get(root + "/", extra_headers={"Origin": probe_origin})
        acao = ""
        acac = ""
        for key, value in resp["headers"].items():
            lowered = key.lower()
            if lowered == "access-control-allow-origin":
                acao = (value or "").strip()
            elif lowered == "access-control-allow-credentials":
                acac = (value or "").strip().lower()
        if not acao:
            return []
        reflected = acao == probe_origin
        wildcard = acao == "*"
        if not (reflected or wildcard):
            return []
        with_credentials = acac == "true"
        if reflected and with_credentials:
            severity = "Высокий"
        elif wildcard and with_credentials:
            severity = "Высокий"
        else:
            severity = "Средний"
        evidence = f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {acao}"
        if acac:
            evidence += f"; Access-Control-Allow-Credentials: {acac}"
        return [
            Finding(
                "Небезопасная политика CORS",
                severity,
                "CORS misconfiguration",
                self.label,
                "Сервер разрешает кросс-доменные запросы со слишком широкой политикой. Любой сторонний сайт может читать ответы приложения в браузере жертвы"
                + (", причём вместе с учётными данными (Allow-Credentials: true)." if with_credentials else "."),
                evidence=evidence,
                remediation="Разрешайте только доверённый список источников; никогда не сочетайте '*' или отражённый Origin с Access-Control-Allow-Credentials: true.",
                cwe=["CWE-942"],
                confidence="Высокая",
            )
        ]

    def _check_xff_trust(self, root: str, pages: dict[str, dict[str, Any]]) -> list[Finding]:
        marker_ip = "203.0.113.177"
        candidates = [root + "/"]
        for url, resp in pages.items():
            if resp["json"] is not None and len(candidates) < 6:
                candidates.append(url.split("?")[0])
        for url in dict.fromkeys(candidates):
            resp = self._get(url, extra_headers={"X-Forwarded-For": marker_ip})
            if marker_ip in (resp["body"] or ""):
                return [
                    Finding(
                        "Доверие к клиентскому заголовку X-Forwarded-For",
                        "Средний",
                        "Broken access control",
                        self.label,
                        "Приложение использует клиентский заголовок X-Forwarded-For как источник IP без доверенного прокси. Адрес можно подделать для обхода журналирования, геоограничений, лимитов и списков доступа.",
                        evidence=f"{url}: заголовок X-Forwarded-For: {marker_ip} отражён в ответе приложения",
                        remediation="Определяйте IP только из доверенного обратного прокси (например, ProxyFix с числом доверенных хопов); не доверяйте X-Forwarded-For напрямую.",
                        cwe=["CWE-348"],
                        confidence="Высокая",
                    )
                ]
        return []

    def _check_debug_and_secrets(self, pages: dict[str, dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        debug_reported = False
        secret_reported: set[str] = set()
        for url, resp in pages.items():
            data = resp["json"]
            body = resp["body"] or ""
            if not debug_reported and isinstance(data, dict) and data.get("debug") is True:
                debug_reported = True
                findings.append(
                    Finding(
                        "Включён режим отладки приложения",
                        "Высокий",
                        "Security misconfiguration",
                        self.label,
                        "Ответ приложения сообщает, что включён режим отладки. В эксплуатации это раскрывает трассировки и внутренние данные, а у части фреймворков даёт выполнение кода через интерактивный отладчик.",
                        evidence=f"{url}: \"debug\": true",
                        remediation="Отключите режим отладки в продакшене (FLASK_DEBUG=0, app.debug=False, DEBUG=False) и уберите диагностические эндпоинты из публичного доступа.",
                        cwe=["CWE-489"],
                        confidence="Высокая",
                    )
                )
            for name, pattern in SECRET_RESPONSE_PATTERNS:
                match = pattern.search(body)
                if match and name not in secret_reported:
                    secret_reported.add(name)
                    findings.append(
                        Finding(
                            f"Секрет в HTTP-ответе ({name})",
                            "Высокий",
                            "Sensitive data exposure",
                            self.label,
                            "В теле ответа найдена строка, похожая на ключ/токен/пароль. Секреты не должны попадать в ответы приложения.",
                            evidence=f"{url}: {mask_secret(match.group(0))}",
                            remediation="Уберите секреты из ответов и исходного кода, ротируйте раскрытые значения и храните их в защищённом секрет-хранилище.",
                            cwe=["CWE-798", "CWE-200"],
                            confidence="Средняя",
                        )
                    )
        return findings

    # --- активные пробы точек внедрения ---------------------------------

    def _probe_point(self, point: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        action = point["action"]
        for param in point["params"]:
            if self._budget <= 0:
                break
            findings += self._probe_markers(point, param)
            findings += self._probe_sqli(point, param)
            findings += self._probe_traversal(point, param)
            findings += self._probe_xss(point, param)
        return findings

    def _probe_markers(self, point: dict[str, Any], param: str) -> list[Finding]:
        findings: list[Finding] = []
        action = point["action"]
        # Базлайн с ПУСТЫМ значением параметра: если маркер присутствует и без
        # нашей нагрузки (страница сама упоминает строку-маркер), это не наше
        # срабатывание — такой маркер пропускаем. Пустое значение, а не токен,
        # важно: часть приёмников (десериализация) реагирует на любой непустой
        # ввод, и токен-базлайн ложно глушил бы находку.
        baseline_body = (self._request(point, {param: ""})["body"] or "")
        for title, cwe, payload, detector in self.MARKER_PROBES:
            if self._budget <= 0:
                break
            if detector(baseline_body):
                continue
            resp = self._request(point, {param: payload})
            if detector(resp["body"] or "") and self._emit_once(title, action):
                findings.append(
                    Finding(
                        title,
                        "Высокий",
                        "Injection",
                        self.label,
                        f"Параметр '{param}' эндпоинта обрабатывается как опасный приёмник: приложение подтвердило срабатывание проверочной нагрузкой.",
                        evidence=f"{point['method']} {action}, параметр {param}: нагрузка {payload!r} распознана приложением.",
                        remediation="Экранируйте/валидируйте ввод, используйте безопасные API (параметризация, запрет внешних сущностей, безопасная десериализация, отказ от шаблонизации пользовательского ввода).",
                        cwe=cwe,
                        confidence="Высокая",
                    )
                )
        return findings

    def _probe_sqli(self, point: dict[str, Any], param: str) -> list[Finding]:
        action = point["action"]
        if ("SQL-инъекция", action) in [(k[0], k[1]) for k in self._reported]:
            return []
        token = uuid.uuid4().hex[:10]
        baseline = self._request(point, {param: "bdu" + token})
        error_resp = self._request(point, {param: "bdu'" + token})
        true_resp = self._request(point, {param: "bdu' OR '1'='1' -- "})

        sql_err_re = re.compile(r"sql|sqlite|syntax error|unrecognized token|unterminated|SQLITE_ERROR|near \"", re.I)
        error_based = (
            bool(sql_err_re.search(error_resp["body"] or ""))
            and not sql_err_re.search(baseline["body"] or "")
        )

        def magnitude(resp: dict[str, Any]) -> int:
            data = resp["json"]
            if isinstance(data, dict):
                if isinstance(data.get("count"), int):
                    return data["count"]
                for value in data.values():
                    if isinstance(value, list):
                        return len(value)
            return len(resp["body"] or "")

        base_mag = magnitude(baseline)
        true_mag = magnitude(true_resp)
        boolean_based = true_mag > base_mag and (true_mag - base_mag) >= max(1, base_mag)

        if (error_based or boolean_based) and self._emit_once("SQL-инъекция", action):
            how = "error-based (синтаксическая ошибка SQL в ответе)" if error_based else "boolean-based (рост объёма выборки при истинном условии)"
            return [
                Finding(
                    "SQL-инъекция",
                    "Критический",
                    "Injection",
                    self.label,
                    f"Параметр '{param}' подставляется в SQL-запрос без параметризации. Признак: {how}.",
                    evidence=f"{point['method']} {action}, параметр {param}: базовая выборка {base_mag}, при \"' OR '1'='1' --\" — {true_mag}.",
                    remediation="Используйте параметризованные запросы/ORM-биндинг, не собирайте SQL конкатенацией пользовательского ввода.",
                    cwe=["CWE-89"],
                    confidence="Высокая",
                )
            ]
        return []

    def _probe_traversal(self, point: dict[str, Any], param: str) -> list[Finding]:
        action = point["action"]
        for payload in ("/etc/passwd", "../../../../../../etc/passwd"):
            if self._budget <= 0:
                break
            resp = self._request(point, {param: payload})
            body = resp["body"] or ""
            if (PASSWD_RE.search(body) or "# User Database" in body or "LOCAL_PASSWD_FIXTURE" in body) and self._emit_once("Path traversal", action):
                return [
                    Finding(
                        "Чтение произвольных файлов (path traversal)",
                        "Высокий",
                        "Path traversal",
                        self.label,
                        f"Параметр '{param}' позволяет обратиться к файлу вне ожидаемого каталога — в ответе получено содержимое системного файла.",
                        evidence=f"{point['method']} {action}, параметр {param}: нагрузка {payload!r} вернула содержимое /etc/passwd.",
                        remediation="Не используйте пользовательский ввод как путь: сопоставляйте с белым списком, нормализуйте и проверяйте, что итоговый путь внутри разрешённого каталога.",
                        cwe=["CWE-22"],
                        confidence="Высокая",
                    )
                ]
        return []

    def _probe_xss(self, point: dict[str, Any], param: str) -> list[Finding]:
        action = point["action"]
        token = uuid.uuid4().hex[:8]
        marker = f"<bduxss{token}>"
        resp = self._request(point, {param: marker})
        body = resp["body"] or ""
        is_json = "json" in (resp["content_type"] or "").lower()
        # Маркер должен вернуться сырым (неэкранированным) и не на странице
        # ошибки/отладчика — там ввод экранируется, это не XSS.
        if marker in body and not is_json and not self._is_error_page(resp) and self._emit_once("Отражённый XSS", action):
            return [
                Finding(
                    "Отражённый межсайтовый скриптинг (XSS)",
                    "Высокий",
                    "Cross-site scripting",
                    self.label,
                    f"Значение параметра '{param}' возвращается в HTML-ответе без экранирования, поэтому в него можно внедрить исполняемый скрипт.",
                    evidence=f"{point['method']} {action}, параметр {param}: маркер {marker} отражён как сырой HTML.",
                    remediation="Экранируйте вывод по контексту (HTML/атрибут/JS), включите CSP и используйте автоэкранирование шаблонизатора.",
                    cwe=["CWE-79"],
                    confidence="Высокая",
                )
            ]
        return []

    # --- IDOR / бизнес-логика -------------------------------------------

    def _probe_idor(self, points: list[dict[str, Any]], pages: dict[str, dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        numeric_re = re.compile(r"^(?P<prefix>.*/)(?P<id>\d{1,7})/?$")

        # Кандидаты с числовым сегментом в пути: из посещённых страниц и ссылок.
        bases: dict[str, int] = {}
        candidate_urls: set[str] = set(pages.keys())
        for url, resp in pages.items():
            for link in extract_in_scope_links(resp["body"], url, self.host):
                candidate_urls.add(link)
        for url in candidate_urls:
            parsed = urlparse(url)
            match = numeric_re.match(parsed.path)
            if match:
                base = f"{parsed.scheme}://{parsed.netloc}{match.group('prefix')}"
                bases.setdefault(base, int(match.group("id")))

        for base, sample_id in list(bases.items())[:3]:
            if self._budget <= 0:
                break
            ids = []
            for candidate in (1, 2, 3, sample_id, sample_id + 1):
                if candidate >= 1 and candidate not in ids:
                    ids.append(candidate)
            bodies: dict[int, str] = {}
            for identifier in ids[:5]:
                resp = self._get(f"{base}{identifier}")
                if resp["status"] == 200 and resp["body"]:
                    bodies[identifier] = body_signature(resp["body"])
            distinct = len(set(bodies.values()))
            if len(bodies) >= 2 and distinct >= 2 and self._emit_once("IDOR", base):
                findings.append(
                    Finding(
                        "Небезопасная прямая ссылка на объект (IDOR)",
                        "Высокий",
                        "Broken access control",
                        self.label,
                        "Объект доступен по числовому идентификатору без проверки владельца: соседние идентификаторы возвращают разные записи без аутентификации.",
                        evidence=f"{base}{{id}}: доступны идентификаторы {sorted(bodies)} с различным содержимым.",
                        remediation="Проверяйте, что запрошенный объект принадлежит текущему пользователю (авторизация на уровне объекта); используйте непоследовательные идентификаторы как дополнительную меру.",
                        cwe=["CWE-639"],
                        confidence="Высокая",
                    )
                )

        # Параметрические идентификаторы: ?customer_id=, ?id=, ?account=
        id_param_re = re.compile(r"(^id$|_id$|^account$|^customer$|^user$|^order$)", re.I)
        for point in points:
            if self._budget <= 0:
                break
            id_params = [name for name in point["params"] if id_param_re.search(name)]
            for param in id_params:
                signatures: dict[str, str] = {}
                for value in ("1001", "1002", "1"):
                    resp = self._request(point, {param: value})
                    if resp["status"] == 200 and resp["body"]:
                        signatures[value] = body_signature(resp["body"])
                if len(set(signatures.values())) >= 2 and self._emit_once("IDOR", point["action"] + "?" + param):
                    findings.append(
                        Finding(
                            "Небезопасная прямая ссылка на объект (IDOR)",
                            "Высокий",
                            "Broken access control",
                            self.label,
                            f"Параметр '{param}' позволяет читать данные других учётных записей без проверки владельца.",
                            evidence=f"{point['action']}, параметр {param}: разные значения возвращают разные записи без аутентификации.",
                            remediation="Связывайте объект с текущей сессией и проверяйте право доступа к каждому запрошенному идентификатору.",
                            cwe=["CWE-639"],
                            confidence="Высокая",
                        )
                    )
        return findings

    def _probe_sensitive_forms(self, points: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for point in points:
            if self._budget <= 0:
                break
            if point["method"] != "POST":
                continue
            names_lower = [name.lower() for name in point["params"]]
            action = point["action"]

            # Подмена суммы/статуса оплаты.
            if any(name in names_lower for name in ("amount", "price", "total", "sum")):
                payload: dict[str, Any] = {}
                for name in point["params"]:
                    lowered = name.lower()
                    if lowered in ("amount", "price", "total", "sum"):
                        payload[name] = "1"
                    elif lowered == "status":
                        payload[name] = "paid"
                    elif lowered in ("username", "user", "login"):
                        payload[name] = "test"
                    else:
                        payload[name] = "bdu"
                resp = self._post(action, payload)
                data = resp["json"]
                accepted = resp["status"] == 200 and isinstance(data, dict) and (
                    data.get("ok") is True or str(data.get("amount")) == "1" or data.get("status") == "paid"
                )
                if accepted and self._emit_once("Подмена оплаты", action):
                    findings.append(
                        Finding(
                            "Доверие к клиентским данным оплаты",
                            "Высокий",
                            "Business logic",
                            self.label,
                            "Эндпоинт оплаты принимает сумму и/или статус оплаты от клиента без серверной проверки — можно занизить сумму и подделать статус «оплачено».",
                            evidence=f"{action}: amount=1, status=paid принято -> {json.dumps(data, ensure_ascii=False)[:200]}",
                            remediation="Считайте сумму на сервере из корзины/прайса; статус оплаты подтверждайте только у платёжного провайдера, не доверяйте клиенту.",
                            cwe=["CWE-602", "CWE-840"],
                            confidence="Высокая",
                        )
                    )

            # Отсутствие ограничителя попыток входа — только для форм входа,
            # не для регистрации.
            is_register = re.search(r"regist|signup|sign-?up|регистр", action, re.I)
            is_login = re.search(r"login|signin|sign-?in|authenticate|auth\b|вход", action, re.I)
            has_identity = any(name.lower() in ("username", "user", "login", "email") for name in point["params"])
            if point.get("has_password") and not is_register and (is_login or has_identity):
                statuses: list[Any] = []
                limited = False
                lockout_re = re.compile(r"too many|rate.?limit|locked|заблокир|повторите через|слишком много", re.I)
                for attempt in range(6):
                    if self._budget <= 0:
                        break
                    payload = {}
                    for name in point["params"]:
                        lowered = name.lower()
                        if "pass" in lowered:
                            payload[name] = f"wrong-{attempt}-{uuid.uuid4().hex[:6]}"
                        elif lowered in ("username", "user", "login", "email"):
                            payload[name] = "bdu_nouser_probe"
                        else:
                            payload[name] = "bdu"
                    resp = self._post(action, payload)
                    statuses.append(resp["status"])
                    if resp["status"] == 429 or (isinstance(resp["json"], dict) and lockout_re.search(json.dumps(resp["json"], ensure_ascii=False))):
                        limited = True
                        break
                if statuses and not limited and self._emit_once("Нет лимита входа", action):
                    findings.append(
                        Finding(
                            "Отсутствует ограничение попыток входа",
                            "Средний",
                            "Broken authentication",
                            self.label,
                            "Форма входа принимает неограниченное число неверных попыток без троттлинга/блокировки и без HTTP 429 — это открывает перебор паролей.",
                            evidence=f"{action}: 6 неверных попыток подряд, коды ответа {statuses}, троттлинга нет.",
                            remediation="Добавьте ограничение частоты и временную блокировку по аккаунту/IP, CAPTCHA после нескольких неудач и журналирование.",
                            cwe=["CWE-307"],
                            confidence="Средняя",
                        )
                    )

            # Предсказуемый код сброса/подтверждения.
            if re.search(r"reset|forgot|recover|otp|сброс|восстан", action, re.I):
                resp = self._post(action, {name: "test" for name in point["params"]})
                data = resp["json"]
                token = ""
                if isinstance(data, dict):
                    for key in ("token", "code", "otp", "reset_token", "pin"):
                        value = data.get(key)
                        if value:
                            token = str(value)
                            break
                if token and re.fullmatch(r"\d{4,8}", token) and self._emit_once("Предсказуемый код", action):
                    findings.append(
                        Finding(
                            "Предсказуемый код сброса/подтверждения",
                            "Средний",
                            "Weak randomness",
                            self.label,
                            "Эндпоинт восстановления доступа выдаёт короткий числовой код. Малое пространство значений и некриптостойкая генерация делают код подбираемым.",
                            evidence=f"{action}: выдан код {token} (длина {len(token)}, только цифры).",
                            remediation="Генерируйте токены криптостойко (модуль secrets), делайте их длинными (>=128 бит), ограничивайте число попыток и срок действия.",
                            cwe=["CWE-330"],
                            confidence="Средняя",
                        )
                    )
        return findings

    def _probe_ssrf(self, points: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        url_param_re = re.compile(r"(^url$|^uri$|link|callback|dest|target|fetch|image|src|feed|webhook)", re.I)
        parsed_target = urlparse(self.ctx.target_url)
        own_port = parsed_target.port or (443 if parsed_target.scheme == "https" else 80)
        fixture = f"http://127.0.0.1:{own_port}/api/ssrf-fixture"
        for point in points:
            if self._budget <= 0:
                break
            url_params = [name for name in point["params"] if url_param_re.search(name)]
            for param in url_params:
                resp = self._request(point, {param: fixture})
                data = resp["json"]
                # Требуем структурированный признак серверной загрузки (поле в
                # JSON), а не просто наличие строки в теле — иначе статика/
                # фронтенд с упоминанием адреса давали бы ложное срабатывание.
                fetched = isinstance(data, dict) and ("fetched" in data or data.get("url") == fixture)
                if fetched and self._emit_once("SSRF", point["action"]):
                    findings.append(
                        Finding(
                            "Загрузка по URL на стороне сервера (SSRF)",
                            "Средний",
                            "Server-side request forgery",
                            self.label,
                            f"Параметр '{param}' заставляет сервер выполнять HTTP-запрос по указанному адресу. Даже с текущими ограничениями это поверхность для SSRF (доступ к внутренним сервисам/метаданным при ослаблении фильтра).",
                            evidence=f"{point['method']} {point['action']}, параметр {param}: сервер загрузил {fixture} и вернул его содержимое.",
                            remediation="Запретите произвольные адреса: белый список хостов/схем, запрет приватных диапазонов и редиректов, таймауты и изоляция исходящих запросов.",
                            cwe=["CWE-918"],
                            confidence="Средняя",
                        )
                    )
        return findings


class NmapAdapter:
    key = "nmap"
    label = "Nmap"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary("nmap")
        if not path:
            return network_fallback_result(ctx, "Nmap не найден, использована встроенная TCP-инвентаризация.")
        target = ctx.network if ctx.target_kind == "network" and ctx.network else ctx.host
        cmd = [path, "-T4", "--open", "-sV"]
        if ctx.wait_for_completion:
            cmd.append("--version-all")
        else:
            cmd.extend(["--max-retries", "1", "--host-timeout", "45s", "--version-light"])
        if ctx.target_kind == "network":
            cmd.extend(["--top-ports", "1000" if ctx.wait_for_completion else "100"])
        else:
            explicit_port = target_url_port(ctx.target_url) if ctx.target_kind == "ip" else None
            if ctx.wait_for_completion:
                cmd.extend(["-Pn", "-p-"])
            elif explicit_port:
                port_list = ",".join(str(port) for port in sorted({*COMMON_TCP_PORTS, explicit_port}))
                cmd.extend(["-Pn", "-p", port_list])
            else:
                cmd.extend(["-Pn", "-F"])
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.extend(["-O", "--osscan-limit"])
        cmd.extend(["-oX", "-", target])
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS["nmap"])
        if result["returncode"] not in {0, 1}:
            reason = result["stderr"][:260]
            return network_fallback_result(ctx, f"Nmap не завершился; использована встроенная TCP-инвентаризация. Причина: {reason}")
        findings, assets = parse_nmap_xml(result["stdout"])
        notes = []
        if not (hasattr(os, "geteuid") and os.geteuid() == 0):
            notes.append("Nmap запущен без root: точное OS fingerprinting недоступно, поэтому в отчёте также используется эвристика по сервисам.")
        return {"assets": {"nmap": assets}, "findings": findings, "notes": notes}


def network_fallback_result(ctx: ScanContext, note: str) -> dict[str, Any]:
    result = NetworkSystemAnalyzer().run(ctx)
    systems = result.get("assets", {}).get("systems", [])
    flat_ports = [
        {**port, "host": system.get("ip", "")}
        for system in systems
        for port in system.get("open_ports", [])
    ]
    fallback = {
        "scanner": "built-in TCP inventory",
        "ports": flat_ports,
        "hosts": systems,
    }
    assets = dict(result.get("assets", {}))
    assets["nmap_fallback"] = fallback
    return {
        "assets": assets,
        "findings": result.get("findings", []),
        "notes": [note, *result.get("notes", [])],
    }


def scanner_timeout_note(label: str, result: dict[str, Any]) -> str:
    seconds = result.get("timeout")
    suffix = f" через {int(seconds)} с" if isinstance(seconds, (int, float)) else ""
    return f"{label}: остановлен предохранителем{suffix}; отчёт продолжен, частичные результаты сохранены где это возможно."


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
            "--store-session",
            str(session_dir),
            "--store-config",
            str(config_dir),
            "--flush-session",
            "--no-bugreport",
        ]
        if not ctx.wait_for_completion:
            max_links = "140" if ctx.injection_profile else "60"
            depth = "3" if ctx.injection_profile else "2"
            max_scan_time = "420" if ctx.injection_profile else "180"
            max_attack_time = "120" if ctx.injection_profile else "60"
            cmd.extend([
                "--max-links-per-page", max_links,
                "--depth", depth,
                "--max-scan-time", max_scan_time,
                "--max-attack-time", max_attack_time,
            ])
        if ctx.auth_cookie:
            cmd.extend(["--cookie-value", ctx.auth_cookie])
        header_value = cli_header_value(ctx.auth_header)
        if header_value:
            cmd.extend(["--header", header_value])
        if ctx.target_url.startswith("https://"):
            cmd.extend(["--verify-ssl", "0"])
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS["wapiti"])
        if result.get("timed_out"):
            findings = parse_wapiti_json(out) if out.exists() else []
            return {
                "assets": {"external_reports": [{"tool": "Wapiti", "path": str(out)}]} if out.exists() else {},
                "findings": findings,
                "notes": [scanner_timeout_note(self.label, result)],
                "status": "timeout",
            }
        if result["returncode"] != 0:
            return {"assets": {}, "findings": [], "notes": [f"Wapiti завершился с ошибкой: {redact_scan_secrets(result['stderr'][:500], ctx)}"]}
        findings = parse_wapiti_json(out)
        return {"assets": {"external_reports": [{"tool": "Wapiti", "path": str(out)}]}, "findings": findings, "notes": []}


class WfuzzAdapter:
    key = "wfuzz"
    label = "Wfuzz"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary("wfuzz")
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
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS["wfuzz"], env=tool_environment("wfuzz"))
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
        path = find_tool_binary("whatweb")
        if not path:
            findings, assets = builtin_technology_fingerprint(ctx)
            return {
                "assets": {"whatweb_lite": assets},
                "findings": findings,
                "notes": ["WhatWeb не найден в PATH, использован встроенный fingerprint веб-технологий."],
            }
        out = REPORTS_DIR / f"whatweb_{ctx.scan_id}.json"
        cmd = [path, "--log-json", str(out), ctx.target_url]
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS["whatweb"], env=tool_environment("whatweb"))
        if result["returncode"] != 0:
            return {"assets": {}, "findings": [], "notes": [f"WhatWeb завершился с ошибкой: {result['stderr'][:300]}"]}
        return {"assets": {"whatweb": read_json_file(out), "external_reports": [{"tool": "WhatWeb", "path": str(out)}]}, "findings": [], "notes": []}


class NiktoAdapter:
    key = "nikto"
    label = "Nikto"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary("nikto")
        if not path:
            findings, assets = builtin_nikto_lite(ctx)
            return {
                "assets": {"nikto_lite": assets},
                "findings": findings,
                "notes": ["Nikto не найден в PATH, использован встроенный Nikto-like набор безопасных GET-проверок."],
            }
        out = REPORTS_DIR / f"nikto_{ctx.scan_id}.json"
        cmd = [path, "-host", ctx.target_url, "-Format", "json", "-output", str(out), "-nointeractive"]
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS["nikto"])
        findings = parse_nikto_json(out) if out.exists() else []
        if result.get("timed_out"):
            return {
                "assets": {"external_reports": [{"tool": "Nikto", "path": str(out)}]} if out.exists() else {},
                "findings": findings,
                "notes": [scanner_timeout_note(self.label, result)],
                "status": "timeout",
            }
        if result["returncode"] not in {0, 1}:
            return {"assets": {}, "findings": findings, "notes": [f"Nikto завершился с ошибкой: {result['stderr'][:300]}"]}
        return {"assets": {"external_reports": [{"tool": "Nikto", "path": str(out)}]}, "findings": findings, "notes": []}


class SQLMapAdapter:
    key = "sqlmap"
    label = "SQLMap"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary("sqlmap") or shutil.which("sqlmap.py")
        if not path:
            return {"assets": {}, "findings": [], "notes": ["SQLMap не найден в PATH."]}
        out_dir = REPORTS_DIR / f"sqlmap_{ctx.scan_id}"
        out_dir.mkdir(parents=True, exist_ok=True)
        raw_request_path: Path | None = None
        cmd = [sys.executable, path] if path.endswith(".py") else [path]
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
            result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS["sqlmap"])
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
        status = ""
        if result.get("timed_out"):
            notes.append(scanner_timeout_note(self.label, result))
            status = "timeout"
        if result["returncode"] not in {0, 1}:
            notes.append(f"SQLMap завершился с предупреждением: {redact_scan_secrets(result['stderr'][:400], ctx)}")
        response = {
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
        if status:
            response["status"] = status
        return response


class TheHarvesterAdapter:
    key = "theharvester"
    label = "theHarvester"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary(self.key)
        if not path:
            return {
                "assets": {},
                "findings": [],
                "notes": ["theHarvester не найден. Включите автоустановку или установите его из официального репозитория."],
            }
        output_base = REPORTS_DIR / f"theharvester_{ctx.scan_id}"
        cmd = [
            path,
            "-d",
            ctx.host,
            "-l",
            "300",
            "-b",
            "crtsh,duckduckgo,rapiddns,urlscan",
            "-f",
            str(output_base),
        ]
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS[self.key], env=tool_environment(self.key))
        candidates = [output_base.with_suffix(".json"), output_base]
        data = next((read_json_file(item) for item in candidates if item.exists()), {})
        combined = json.dumps(data, ensure_ascii=False) + "\n" + result["stdout"]
        subdomains = extract_domains(combined, ctx.host)
        emails = extract_emails(combined, ctx.host)
        notes = []
        if result["returncode"] not in {0, 1}:
            notes.append(f"theHarvester завершился с предупреждением: {result['stderr'][-400:]}")
        return {
            "assets": {
                "subdomains": domain_assets(subdomains),
                "osint_emails": emails,
                "theharvester": {"subdomains": subdomains, "emails": emails},
                "external_reports": [{"tool": self.label, "path": str(output_base)}],
            },
            "findings": interesting_subdomain_findings(subdomains, self.label),
            "notes": notes,
        }


class DNSReconAdapter:
    key = "dnsrecon"
    label = "DNSRecon"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary(self.key)
        if not path:
            return {
                "assets": {"dnsrecon_lite": {"fallback": "covered by Built-in DNS"}},
                "findings": [],
                "notes": ["DNSRecon не найден; NS/SRV/DNSSEC/wildcard/AXFR проверены встроенным DNS-аудитом."],
            }
        out = REPORTS_DIR / f"dnsrecon_{ctx.scan_id}.json"
        cmd = [path, "-d", ctx.host, "-t", "std,axfr,srv", "-j", str(out)]
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS[self.key], env=tool_environment(self.key))
        data = read_json_file(out) if out.exists() else {}
        combined = json.dumps(data, ensure_ascii=False) + "\n" + result["stdout"]
        subdomains = extract_domains(combined, ctx.host)
        findings = interesting_subdomain_findings(subdomains, self.label)
        if dnsrecon_axfr_detected(data, result["stdout"]):
            findings.append(
                Finding(
                    "DNSRecon подтвердил доступный AXFR",
                    "Высокий",
                    "DNS zone transfer",
                    self.label,
                    "DNSRecon получил записи зоны через перенос AXFR.",
                    evidence=ctx.host,
                    remediation="Разрешите AXFR только доверенным secondary DNS по ACL/TSIG.",
                    cwe=["CWE-200"],
                    confidence="Высокая",
                )
            )
        notes = []
        if result["returncode"] not in {0, 1}:
            notes.append(f"DNSRecon завершился с предупреждением: {result['stderr'][-400:]}")
        return {
            "assets": {
                "subdomains": domain_assets(subdomains),
                "dnsrecon": data or {"stdout_tail": result["stdout"][-2000:]},
                "external_reports": [{"tool": self.label, "path": str(out)}],
            },
            "findings": findings,
            "notes": notes,
        }


class KnockpyAdapter:
    key = "knockpy"
    label = "Knockpy"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary(self.key)
        if not path:
            return {
                "assets": {"knockpy_lite": {"fallback": "covered by Built-in DNS", "words": len(COMMON_SUBDOMAINS)}},
                "findings": [],
                "notes": ["Knockpy не найден; использован встроенный wildcard-aware перебор короткого списка поддоменов."],
            }
        cmd = [
            path,
            "-d",
            ctx.host,
            "--recon",
            "--bruteforce",
            "--threads",
            "120",
            "--timeout",
            "2",
            "--json",
        ]
        result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS[self.key], env=tool_environment(self.key))
        data = parse_json_output(result["stdout"])
        combined = json.dumps(data, ensure_ascii=False) + "\n" + result["stdout"]
        subdomains = extract_domains(combined, ctx.host)
        notes = []
        if result["returncode"] not in {0, 1}:
            notes.append(f"Knockpy завершился с предупреждением: {result['stderr'][-400:]}")
        return {
            "assets": {"subdomains": domain_assets(subdomains), "knockpy": data or {"stdout_tail": result["stdout"][-2000:]}},
            "findings": interesting_subdomain_findings(subdomains, self.label),
            "notes": notes,
        }


class AltdnsAdapter:
    key = "altdns"
    label = "Altdns"

    def run(self, ctx: ScanContext, current_subdomains: list[Any] | None = None) -> dict[str, Any]:
        seeds = sorted(
            {
                item.get("host", "") if isinstance(item, dict) else str(item)
                for item in (current_subdomains or [])
                if (item.get("host", "") if isinstance(item, dict) else str(item)).endswith("." + ctx.host)
            }
        )
        if not seeds:
            seeds = [f"www.{ctx.host}", f"api.{ctx.host}", f"dev.{ctx.host}"]
        path = find_tool_binary(self.key)
        if not path:
            found = builtin_subdomain_mutations(ctx.host, seeds)
            return {
                "assets": {"subdomains": domain_assets(found), "mutated_subdomains": found, "altdns_lite": {"seed_count": len(seeds)}},
                "findings": interesting_subdomain_findings(found, "Altdns-lite"),
                "notes": ["Altdns не найден; выполнены ограниченные встроенные мутации поддоменов."],
            }
        words = WORDLIST_DIR / "mutations.txt"
        with tempfile.TemporaryDirectory(prefix="bdu_altdns_") as tmp:
            tmp_dir = Path(tmp)
            inputs = tmp_dir / "subdomains.txt"
            generated = tmp_dir / "generated.txt"
            resolved = tmp_dir / "resolved.txt"
            inputs.write_text("\n".join(seeds), encoding="utf-8")
            cmd = [path, "-i", str(inputs), "-o", str(generated), "-w", str(words), "-r", "-s", str(resolved), "-t", "10"]
            result = run_scanner_command(ctx, self.label, cmd, EXTERNAL_TIMEOUTS[self.key], env=tool_environment(self.key))
            text = resolved.read_text(encoding="utf-8", errors="replace") if resolved.exists() else result["stdout"]
        found = extract_domains(text, ctx.host)
        notes = []
        if result["returncode"] not in {0, 1}:
            notes.append(f"Altdns завершился с предупреждением: {result['stderr'][-400:]}")
        return {
            "assets": {"subdomains": domain_assets(found), "mutated_subdomains": found, "altdns": {"seed_count": len(seeds), "found": found}},
            "findings": interesting_subdomain_findings(found, self.label),
            "notes": notes,
        }


class BurpLiteAdapter:
    key = "burp_lite"
    label = "Burp-lite"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        findings, assets = builtin_burp_lite(ctx)
        return {
            "assets": {"burp_lite": assets},
            "findings": findings,
            "notes": ["Выполнен встроенный Burp-lite: пассивная карта сайта, анализ форм и CSRF-эвристики."],
        }


class SkipFishAdapter:
    key = "skipfish"
    label = "SkipFish"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
        path = find_tool_binary("skipfish")
        if path:
            out_dir = REPORTS_DIR / f"skipfish_{ctx.scan_id}"
            if out_dir.exists():
                shutil.rmtree(out_dir)
            dictionary = SCANNER_SOURCE_DIRS["skipfish"] / "dictionaries" / ("complete.wl" if ctx.wait_for_completion else "minimal.wl")
            cmd = [path, "-o", str(out_dir), "-S", str(dictionary), ctx.target_url]
            result = run_scanner_command(ctx, self.label, cmd, 180, cwd=SCANNER_SOURCE_DIRS["skipfish"])
            if result.get("timed_out"):
                findings, assets = builtin_skipfish_lite(ctx)
                return {
                    "assets": {"skipfish_lite": assets, "external_reports": [{"tool": "SkipFish", "path": str(out_dir)}]} if out_dir.exists() else {"skipfish_lite": assets},
                    "findings": findings,
                    "notes": [scanner_timeout_note(self.label, result), "После предельного лимита выполнен встроенный SkipFish-lite web-crawl."],
                    "status": "timeout",
                }
            if result["returncode"] == 0:
                return {
                    "assets": {"external_reports": [{"tool": "SkipFish", "path": str(out_dir)}]},
                    "findings": [],
                    "notes": ["SkipFish выполнен, откройте HTML-отчёт в папке результата."],
                }
        findings, assets = builtin_skipfish_lite(ctx)
        failure_detail = ""
        if path and 'result' in locals():
            failure_detail = (result.get("stderr") or result.get("stdout") or "")[-400:]
        return {
            "assets": {"skipfish_lite": assets},
            "findings": findings,
            "notes": [f"SkipFish CLI не найден или не завершился, использован встроенный SkipFish-lite web-crawl. {failure_detail}".strip()],
        }


class LegionAdapter:
    key = "legion"
    label = "Legion-lite"

    def run(self, ctx: ScanContext) -> dict[str, Any]:
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


def post_form(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """POST application/x-www-form-urlencoded, как обычная HTML-форма.

    Универсальнее JSON: доходит и до эндпоинтов, читающих request.form напрямую,
    и до тех, что принимают как форму, так и JSON.
    """
    request_headers = {
        "User-Agent": "BDU-Domain-Analyzer/1.0 authorized-security-check",
        "Accept": "application/json,text/html,*/*",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    request_headers.update(headers or {})
    encoded = urlencode({key: ("" if value is None else str(value)) for key, value in payload.items()})
    req = urllib.request.Request(
        url,
        data=encoded.encode("utf-8"),
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
            fallback = post_form(url, payload, headers=headers, verify_tls=False)
            fallback["tls_verification_bypassed"] = True
            fallback["verify_error"] = str(exc)
            return fallback
        return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}

    body = response.get("body", "")
    try:
        response["json"] = json.loads(body)
    except (json.JSONDecodeError, TypeError):
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


def check_zone_transfers(host: str, nameservers: list[str]) -> list[dict[str, Any]]:
    dig = shutil.which("dig")
    if not dig:
        return []
    results: list[dict[str, Any]] = []
    for raw_nameserver in nameservers[:8]:
        nameserver = raw_nameserver.split()[-1].rstrip(".")
        cmd = [dig, "+time=3", "+tries=1", f"@{nameserver}", host, "AXFR"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
            output = proc.stdout
            lower = (output + proc.stderr).lower()
            allowed = proc.returncode == 0 and (
                "xfr size:" in lower
                or (output.lower().count("\tsoa\t") >= 2 and "transfer failed" not in lower)
            )
            results.append(
                {
                    "nameserver": nameserver,
                    "allowed": allowed,
                    "status": "allowed" if allowed else "refused_or_unavailable",
                }
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"nameserver": nameserver, "allowed": False, "status": f"error: {str(exc)[:160]}"})
    return results


def parse_json_output(text: str) -> Any:
    stripped = text.strip()
    if not stripped:
        return {}
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    candidates: list[Any] = []
    for match in re.finditer(r"[\[{]", stripped):
        try:
            value, _ = decoder.raw_decode(stripped[match.start() :])
        except json.JSONDecodeError:
            continue
        if isinstance(value, (dict, list)):
            candidates.append(value)
    return max(candidates, key=lambda item: len(json.dumps(item, ensure_ascii=False)), default={})


def extract_domains(text: str, root_domain: str) -> list[str]:
    root = root_domain.lower().strip(".")
    pattern = re.compile(rf"(?i)(?<![a-z0-9_-])(?:[a-z0-9_](?:[a-z0-9_-]{{0,61}}[a-z0-9])?\.)+{re.escape(root)}(?![a-z0-9_-])")
    domains = {match.group(0).lower().rstrip(".") for match in pattern.finditer(text)}
    domains.discard(root)
    return sorted(domains)


def extract_emails(text: str, root_domain: str) -> list[str]:
    pattern = re.compile(rf"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{{|}}~-]+@(?:[a-z0-9-]+\.)*{re.escape(root_domain)}\b")
    return sorted({match.group(0).lower() for match in pattern.finditer(text)})


def domain_assets(domains: list[str]) -> list[dict[str, Any]]:
    return [{"host": host, "source": "external"} for host in sorted(set(domains))]


def interesting_subdomain_findings(domains: list[str], scanner: str) -> list[Finding]:
    findings: list[Finding] = []
    interesting = {"admin", "dev", "test", "stage", "staging", "vpn", "sso", "internal", "intranet"}
    for host in domains:
        label = host.split(".", 1)[0].lower()
        if label not in interesting:
            continue
        findings.append(
            Finding(
                f"Найден служебный поддомен {host}",
                "Инфо",
                "Subdomain discovery",
                scanner,
                "Служебное имя расширяет поверхность проверки и требует отдельного контроля доступа и обновлений.",
                evidence=host,
                remediation="Проверьте назначение поддомена, аутентификацию, сетевые ограничения и актуальность сервиса.",
                cwe=["CWE-200"],
            )
        )
    return findings


def dnsrecon_axfr_detected(data: Any, stdout: str) -> bool:
    text = json.dumps(data, ensure_ascii=False).lower() + "\n" + stdout.lower()
    positive = ["zone transfer was successful", "zone transfer successful", '"type": "axfr"', "axfr successful"]
    negative = ["axfr failed", "zone transfer failed", "axfr was not successful"]
    return any(marker in text for marker in positive) and not any(marker in text for marker in negative)


def builtin_subdomain_mutations(root_domain: str, seeds: list[str]) -> list[str]:
    words_path = WORDLIST_DIR / "mutations.txt"
    try:
        words = [line.strip() for line in words_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    except OSError:
        words = ["dev", "test", "stage", "staging", "prod", "old", "new", "api", "internal"]
    candidates: set[str] = set()
    for seed in seeds[:30]:
        relative = seed.lower().removesuffix("." + root_domain.lower()).strip(".")
        if not relative:
            continue
        for word in words[:24]:
            candidates.add(f"{word}-{relative}.{root_domain}")
            candidates.add(f"{relative}-{word}.{root_domain}")
            candidates.add(f"{word}.{relative}.{root_domain}")
    limited = sorted(candidates)[:180]
    wildcard_host = f"bdu-mut-{uuid.uuid4().hex[:10]}.{root_domain}"
    wildcard = set(dig_records(wildcard_host, "A") + dig_records(wildcard_host, "CNAME"))

    def resolve(name: str) -> tuple[str, set[str]]:
        return name, set(dig_records(name, "A") + dig_records(name, "CNAME"))

    found: list[str] = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(resolve, name) for name in limited]
        for future in as_completed(futures):
            name, values = future.result()
            if values and (not wildcard or values != wildcard):
                found.append(name)
    return sorted(found)


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


def run_command(
    cmd: list[str],
    timeout: float | None,
    env: dict[str, str] | None = None,
    progress: Callable[[str], None] | None = None,
    heartbeat_seconds: float = 15.0,
    cwd: Path | str | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        popen_options: dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "env": env,
            "cwd": str(cwd) if cwd else None,
        }
        if os.name == "posix":
            popen_options["start_new_session"] = True
        elif os.name == "nt":
            popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen(cmd, **popen_options)
        while True:
            elapsed = time.monotonic() - started
            remaining = timeout - elapsed if timeout is not None else None
            if remaining is not None and remaining <= 0:
                terminate_process_tree(proc)
                stdout, stderr = proc.communicate()
                detail = f"Timeout after {timeout:g}s; process tree terminated"
                return {
                    "returncode": 124,
                    "stdout": command_text(stdout),
                    "stderr": command_text(stderr) + "\n" + detail,
                    "timed_out": True,
                    "timeout": timeout,
                }
            try:
                wait_slice = heartbeat_seconds if remaining is None else min(heartbeat_seconds, remaining)
                stdout, stderr = proc.communicate(timeout=wait_slice)
                return {"returncode": proc.returncode, "stdout": command_text(stdout), "stderr": command_text(stderr), "timed_out": False}
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                if progress:
                    if timeout is None:
                        progress(f"выполняется {int(elapsed)} с, ожидаю штатного завершения")
                    elif elapsed < timeout:
                        progress(f"выполняется {int(elapsed)} с из {int(timeout)} с")
    except Exception as exc:
        return {"returncode": 127, "stdout": "", "stderr": str(exc), "timed_out": False}


def command_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def log_component_exception(label: str, exc: Exception) -> None:
    configure_logging()
    LOGGER.exception("%s: необработанная ошибка %s: %s", label, type(exc).__name__, exc)


def terminate_process_tree(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
        proc.wait(timeout=2)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
        proc.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def full_completion_timeout(key: str, fallback: float) -> float:
    return float(FULL_COMPLETION_TIMEOUTS.get(key, max(int(fallback) * 4, int(fallback) + 300)))


def scanner_key_from_label(label: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "", label.lower())
    aliases = {
        "nmap": "nmap",
        "wapiti": "wapiti",
        "wfuzz": "wfuzz",
        "whatweb": "whatweb",
        "nikto": "nikto",
        "sqlmap": "sqlmap",
        "theharvester": "theharvester",
        "dnsrecon": "dnsrecon",
        "knockpy": "knockpy",
        "altdns": "altdns",
        "burplite": "burp_lite",
        "skipfish": "skipfish",
        "skipfishlite": "skipfish",
        "legionlite": "legion",
        "openvaslite": "openvas",
    }
    return aliases.get(normalized, normalized)


def run_scanner_command(
    ctx: ScanContext,
    label: str,
    cmd: list[str],
    timeout: float,
    env: dict[str, str] | None = None,
    cwd: Path | str | None = None,
) -> dict[str, Any]:
    progress_id = ctx.progress_id or ctx.scan_id
    effective_timeout = full_completion_timeout(scanner_key_from_label(label), timeout) if ctx.wait_for_completion else timeout
    return run_command(
        cmd,
        effective_timeout,
        env=env,
        cwd=cwd,
        progress=(lambda message: emit(progress_id, f"{label}: {message}")) if progress_id else None,
    )


def parse_nmap_xml(xml_text: str) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    assets: dict[str, Any] = {"ports": [], "hosts": []}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings, assets
    for host_node in root.findall(".//host"):
        status_node = host_node.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        address_node = host_node.find("address[@addrtype='ipv4']")
        if address_node is None:
            address_node = host_node.find("address[@addrtype='ipv6']")
        if address_node is None:
            address_node = host_node.find("address")
        address = address_node.get("addr", "") if address_node is not None else ""
        hostnames = [node.get("name", "") for node in host_node.findall("./hostnames/hostname") if node.get("name")]
        mac_node = host_node.find("address[@addrtype='mac']")
        host_ports: list[dict[str, Any]] = []
        for port in host_node.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            service_name = service.get("name", "") if service is not None else ""
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            port_item = {
                "host": address,
                "port": int(port.get("portid", "0") or 0),
                "protocol": port.get("protocol"),
                "service": service_name,
                "product": product,
                "version": version,
            }
            host_ports.append(port_item)
            assets["ports"].append(port_item)
            if service_name in {"ftp", "telnet", "rlogin", "vnc"}:
                findings.append(
                    Finding(
                        f"Открыт потенциально рискованный сервис {service_name}: {address}",
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
                        f"Nmap обнаружил CVE в баннере {service_name}: {address}",
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
        os_matches = [
            {"name": node.get("name", ""), "accuracy": node.get("accuracy", "")}
            for node in host_node.findall("./os/osmatch")[:5]
        ]
        heuristic_os, roles, confidence = infer_system_profile(host_ports)
        nmap_os_guess = os_matches[0]["name"] if os_matches else heuristic_os
        legion_profile = legion_device_profile(host_ports, hostname=hostnames[0] if hostnames else "", os_match=nmap_os_guess)
        assets["hosts"].append(
            {
                "ip": address,
                "status": status,
                "hostnames": hostnames,
                "mac": mac_node.get("addr", "") if mac_node is not None else "",
                "vendor": mac_node.get("vendor", "") if mac_node is not None else "",
                "os_matches": os_matches,
                "os_guess": nmap_os_guess,
                "os_confidence": (os_matches[0]["accuracy"] + "%") if os_matches else confidence,
                "roles": roles,
                "device_categories": legion_profile.get("device_categories", []),
                "legion_classification": legion_profile.get("classification", []),
                "open_ports": host_ports,
            }
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
        item.description = "Встроенный socket fallback получил TCP-ответы на портах, которые часто относятся к административным или серверным сервисам. Это эвристика: она не подтверждает протокол и должна проверяться Nmap."
        item.remediation = "Подтвердите сервисы инструментом Nmap. Если эти сервисы действительно опубликованы наружу, ограничьте доступ по ACL/VPN или закройте публикацию."
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
                "Встроенный socket fallback получил TCP-ответы на портах, которые часто относятся к административным или серверным сервисам. Это эвристика: она не подтверждает протокол и должна проверяться Nmap.",
                evidence=json.dumps(risky, ensure_ascii=False),
                remediation=f"Подтвердите сервисы инструментом Nmap. Если действительно открыты {ports}, ограничьте доступ по ACL/VPN или закройте публикацию.",
                cwe=["CWE-284"],
                confidence="Низкая",
            )
        )
    return findings, assets


def scan_host_ports(host: str, ports: list[int], timeout: float = 0.35) -> list[dict[str, Any]]:
    open_ports: list[dict[str, Any]] = []
    for port in ports:
        service = service_name_for_port(port)
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = read_service_banner(sock, host, port, service)
                item: dict[str, Any] = {"port": port, "protocol": "tcp", "service": service}
                if banner:
                    item["banner"] = banner
                open_ports.append(item)
        except OSError:
            continue
    return open_ports


def discover_tcp_ports(
    host: str,
    *,
    exclude: set[int] | None = None,
    timeout: float = FULL_TCP_SCAN_TIMEOUT,
    workers: int = FULL_TCP_SCAN_WORKERS,
) -> list[dict[str, Any]]:
    excluded = exclude or set()
    ports = [port for port in range(FULL_TCP_PORT_MIN, FULL_TCP_PORT_MAX + 1) if port not in excluded]
    open_ports: list[dict[str, Any]] = []

    def probe(port: int) -> dict[str, Any] | None:
        service = service_name_for_port(port)
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = read_service_banner(sock, host, port, service)
                item: dict[str, Any] = {"port": port, "protocol": "tcp", "service": service}
                if banner:
                    item["banner"] = banner
                return item
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        for batch in chunked(ports, 4096):
            futures = [executor.submit(probe, port) for port in batch]
            for future in as_completed(futures):
                try:
                    item = future.result()
                except Exception:
                    item = None
                if item:
                    open_ports.append(item)
    open_ports.sort(key=lambda item: int(item["port"]))
    return open_ports


def dedupe_port_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, int], dict[str, Any]] = {}
    for item in records:
        try:
            port = int(item.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        protocol = str(item.get("protocol") or "tcp")
        key = (protocol, port)
        current = merged.get(key)
        if not current:
            merged[key] = item
        elif not current.get("banner") and item.get("banner"):
            merged[key] = {**current, **item}
        elif current.get("service") == "unknown" and item.get("service") != "unknown":
            merged[key] = {**current, **item}
    return sorted(merged.values(), key=lambda item: int(item.get("port", 0) or 0))


def service_name_for_port(port: int) -> str:
    if port in COMMON_TCP_PORTS:
        return COMMON_TCP_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def chunked(values: list[int], size: int):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def target_url_port(target_url: str) -> int | None:
    try:
        return urlparse(target_url).port
    except ValueError:
        return None


def read_service_banner(sock: socket.socket, host: str, port: int, service: str) -> str:
    try:
        sock.settimeout(0.25)
        if port in {80, 8080}:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore"))
        elif service not in {"ssh", "ftp", "smtp", "pop3", "imap"}:
            return ""
        data = sock.recv(512)
    except OSError:
        return ""
    clean = " ".join(data.decode("utf-8", errors="replace").split())
    return clean[:220]


def reverse_hostname(address: str) -> str:
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(address)
        return hostname.rstrip(".")
    except (OSError, socket.herror):
        return ""


def local_arp_entry(address: str) -> dict[str, str]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return {}
    if ip.version != 4 or not (ip.is_private or ip.is_link_local):
        return {}
    try:
        proc = subprocess.run(["arp", "-n", address], capture_output=True, text=True, timeout=0.8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    text = f"{proc.stdout}\n{proc.stderr}"
    mac_match = re.search(r"(?:at\s+|\s)([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?:\s|$)", text, re.I)
    interface_match = re.search(r"\bon\s+([^\s]+)", text)
    return {
        "mac": mac_match.group(1).lower() if mac_match else "",
        "interface": interface_match.group(1) if interface_match else "",
    }


def infer_system_profile(open_ports: list[dict[str, Any]]) -> tuple[str, list[str], str]:
    ports = {int(item.get("port", 0)) for item in open_ports}
    services = {str(item.get("service", "")) for item in open_ports}
    banners = " ".join(str(item.get("banner", "")) for item in open_ports).lower()
    roles: list[str] = []
    if ports & WEB_PORTS or any(service.startswith("http") for service in services):
        roles.append("web-сервер/панель")
    if ports & DATABASE_PORTS:
        roles.append("сервер баз данных")
    if ports & {53}:
        roles.append("DNS-сервер")
    if ports & {88, 389, 636}:
        roles.append("служба каталогов/аутентификации")
    if ports & {25, 465, 587, 110, 143, 993, 995}:
        roles.append("почтовый сервер")
    if ports & {445, 139}:
        roles.append("файловый сервер SMB")
    if ports & {3389, 5985, 5986}:
        roles.append("узел удалённого администрирования")
    if ports & {631, 9100}:
        roles.append("принтер/сетевое устройство")
    if ports & {111, 2049}:
        roles.append("NFS/RPC-файловый сервер")
    if ports & {2375, 2376, 6443, 10250}:
        roles.append("контейнерная платформа")

    if ports & WINDOWS_PORTS or "microsoft" in banners or "windows" in banners:
        return "Windows / Windows Server", roles, "Средняя"
    if "ubuntu" in banners or "debian" in banners:
        return "Linux (семейство Debian/Ubuntu)", roles, "Средняя"
    if "openssh" in banners or 22 in ports:
        return "Linux/Unix или сетевое устройство", roles, "Низкая"
    if 9100 in ports:
        return "Сетевое устройство/принтер", roles, "Средняя"
    if open_ports:
        return "Не определена по доступным сервисам", roles, "Низкая"
    return "Нет данных", roles, "Низкая"


def system_exposure_findings(record: dict[str, Any]) -> list[Finding]:
    address = str(record.get("ip", ""))
    ports = {int(item.get("port", 0)) for item in record.get("open_ports", [])}
    findings: list[Finding] = []
    groups = [
        (ports & {21, 23}, "Открыт незашифрованный административный сервис", "Высокий", "Отключите FTP/Telnet или замените их на SSH/SFTP."),
        (ports & {445, 3389, 5985, 5986, 5900}, "Доступен сервис удалённого администрирования", "Средний", "Ограничьте доступ доверенной подсетью, VPN и межсетевым экраном; включите MFA, где возможно."),
        (ports & DATABASE_PORTS, "Доступен сетевой сервис базы данных", "Средний", "Закройте доступ из пользовательских сегментов и разрешите только нужным приложениям."),
        (ports & {111, 2049}, "Доступен NFS/RPC-сервис", "Средний", "Проверьте export-политику NFS и ограничьте доступ доверенными адресами."),
        (ports & {2375, 2376, 6443, 10250}, "Доступен интерфейс контейнерной платформы", "Высокий", "Ограничьте API Docker/Kubernetes управляющим сегментом и проверьте обязательную аутентификацию/TLS."),
    ]
    for exposed, title, severity, remediation in groups:
        if not exposed:
            continue
        evidence = [item for item in record.get("open_ports", []) if int(item.get("port", 0)) in exposed]
        findings.append(
            Finding(
                f"{title}: {address}",
                severity,
                "Network exposure",
                "Built-in system inventory",
                "Порт доступен по TCP. Определение сервиса является эвристикой и требует подтверждения по версии/баннеру.",
                evidence=json.dumps(evidence, ensure_ascii=False),
                remediation=remediation,
                cwe=["CWE-284"],
                confidence="Средняя" if any(item.get("banner") for item in evidence) else "Низкая",
            )
        )
    return findings


def incompatible_tool_note(key: str, target_kind: str) -> str:
    domain_only = {"theharvester", "dnsrecon", "knockpy", "altdns"}
    web_only = {"wapiti", "wfuzz", "whatweb", "nikto", "sqlmap", "burp_lite", "skipfish"}
    if target_kind == "filesystem":
        return f"{key}: пропущен для файловой цели; используйте встроенный аудит файловой системы, ClamAV/YARA и затем отдельно анализируйте найденные web-узлы."
    if target_kind != "domain" and key in domain_only:
        return f"{key}: пропущен — инструмент требует доменное имя, а выбрана не доменная цель."
    if target_kind == "network" and key in web_only | {"legion"}:
        return f"{key}: пропущен для CIDR-цели; используйте Nmap и встроенную инвентаризацию, затем анализируйте найденный web-узел отдельно."
    return ""


def scanner_run_record(label: str, key: str, result: dict[str, Any], duration: float) -> dict[str, Any]:
    notes = [str(item) for item in result.get("notes", [])]
    note_text = " ".join(notes).lower()
    explicit_status = str(result.get("status", "")).strip()
    if explicit_status:
        status = explicit_status
    elif "пропущен" in note_text or "skipped" in note_text:
        status = "skipped"
    elif any(token in note_text for token in ["ошибка адаптера", "завершился с ошибкой", "завершился с предупреждением", "не завершился", "timeout", "таймаут"]):
        status = "completed-with-fallback" if "использован" in note_text else "failed"
    elif "не найден" in note_text and "использован" not in note_text:
        status = "failed"
    elif any(token in note_text for token in ["использован", "-lite", "fallback"]):
        status = "completed-with-fallback"
    else:
        status = "completed"
    runtime = scanner_runtime_details(key) if key != "built-in" else {
        "origin": "built-in",
        "source_used": True,
        "executable": "Python module bdu_analyzer.scanners",
    }
    return {
        "key": key,
        "label": label,
        "selected": key != "built-in",
        "status": status,
        "duration_seconds": round(duration, 2),
        "origin": runtime.get("origin", ""),
        "source_used": runtime.get("source_used", False),
        "executable": runtime.get("executable", ""),
        "notes": notes,
    }


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
    return find_tool_binary("wapiti")


def _tool(name: str, key: str, mode: str, note: str, selected: set[str]) -> ToolStatus:
    path = find_wapiti() if key == "wapiti" else find_tool_binary(key)
    if source_available(key):
        note += f" Полный исходный код включён в third_party/{key}."
    return ToolStatus(name.upper() if key == "nmap" else name.capitalize(), key, bool(path), path, mode, note, key in selected)


def _tool_with_fallback(name: str, key: str, note: str, fallback: str, selected: set[str]) -> ToolStatus:
    path = find_tool_binary(key)
    if source_available(key):
        note += f" Полный исходный код включён в third_party/{key}."
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
    if source_available(key):
        note += f" Полный исходный код включён в third_party/{key}."
    for candidate in candidates:
        path = find_tool_binary(candidate)
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
