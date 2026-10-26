# -*- coding: utf-8 -*-

import io
import json
import os
import re
import shutil
import threading
import time
import traceback
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .bdu import BDUHandler
from .config import DEFAULT_HOST, DEFAULT_PORT, REPORTS_DIR, STATIC_DIR
from .models import Finding, ScanContext, ScanReport, ToolStatus
from .reporting import render_index, render_static_report, save_report
from .scanners import discover_tools, recommended_tools_for_target, run_assessment
from .progress import PROGRESS, emit
from .target import TargetError, normalize_scan_target, safe_filename
from .updater import check_scanner_updates, ensure_bdu_fresh, update_bdu_database


class AnalyzerApp:
    def __init__(self) -> None:
        self.bdu = BDUHandler()

    def page(self, error: str = "", report=None, saved_paths=None) -> str:
        tool_statuses = report.tool_statuses if report else discover_tools()
        return render_index(
            tool_statuses=tool_statuses,
            bdu_stats=self.bdu.stats(),
            error=error,
            report=report,
            saved_paths=saved_paths,
            recent_reports=recent_reports(),
        )


APP = AnalyzerApp()


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "BDUNetworkAnalyzer/1.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send_html(APP.page())
        elif parsed.path.startswith("/static/"):
            self._send_static(parsed.path.removeprefix("/static/"))
        elif parsed.path == "/api/tools":
            self._send_json([tool.to_dict() for tool in discover_tools()])
        elif parsed.path == "/api/bdu/stats":
            self._send_json(APP.bdu.stats())
        elif parsed.path == "/api/progress":
            progress_id = (parse_qs(parsed.query).get("id") or [""])[0]
            self._send_json(PROGRESS.snapshot(progress_id))
        elif parsed.path.startswith("/reports/package/"):
            self._send_report_package(parsed.path.removeprefix("/reports/package/"))
        elif parsed.path.startswith("/reports/"):
            self._send_report_file(parsed.path.removeprefix("/reports/"))
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/scan":
            self._handle_scan()
        elif parsed.path == "/bdu/import":
            imported = APP.bdu.import_all_xml()
            self._send_json({"imported": imported, "stats": APP.bdu.stats()})
        elif parsed.path == "/bdu/update":
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            source = (parse_qs(body).get("source") or [""])[0].strip() or None
            result = update_bdu_database(source, log=lambda message, level="info": emit("bdu-update", message, level))
            result["stats"] = APP.bdu.stats()
            self._send_json(result)
        elif parsed.path == "/bdu/scanners":
            self._send_json({"scanners": check_scanner_updates(log=lambda message, level="info": None)})
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_scan(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body)
        target = (form.get("target") or [""])[0]
        authorized = (form.get("authorized") or [""])[0] == "1"
        selected_tools = set(form.get("tools") or [])
        active_mode = (form.get("active_mode") or [""])[0] == "1"
        injection_profile = (form.get("injection_profile") or [""])[0] == "1"
        auth_cookie = (form.get("auth_cookie") or [""])[0].strip()
        auth_header = (form.get("auth_header") or [""])[0].strip()
        raw_request = (form.get("raw_request") or [""])[0].strip()
        auto_install = (form.get("auto_install") or [""])[0] == "1"
        wait_for_completion = (form.get("wait_for_completion") or ["1"])[0] != "0"
        requested_progress_id = (form.get("progress_id") or [""])[0].strip()

        if injection_profile or raw_request:
            active_mode = True

        if not authorized:
            self._send_html(APP.page("Подтвердите право на проверку цели."))
            return
        try:
            target_url, host, target_kind, network = normalize_scan_target(target)
        except TargetError as exc:
            self._send_html(APP.page(str(exc)))
            return
        if target_kind == "network" and (injection_profile or raw_request):
            self._send_html(APP.page("Профиль XSS/SQLi и raw HTTP-запрос применимы к одному web-узлу, но не к подсети CIDR."))
            return
        if active_mode and not selected_tools:
            selected_tools.update(recommended_tools_for_target(target_kind))
        if injection_profile or raw_request:
            selected_tools.update({"wapiti", "sqlmap", "burp_lite"})
        filesystem_path = network if target_kind == "filesystem" else ""
        network_value = "" if target_kind == "filesystem" else network

        scan_id = f"{safe_filename(host)}_{time.strftime('%Y%m%d_%H%M%S')}"
        progress_id = requested_progress_id if re.fullmatch(r"[A-Za-z0-9_-]{8,80}", requested_progress_id) else scan_id
        PROGRESS.start(progress_id, target_url)
        ctx = ScanContext(
            original_target=target,
            target_url=target_url,
            host=host,
            target_kind=target_kind,
            network=network_value,
            filesystem_path=filesystem_path,
            selected_tools=selected_tools,
            active_mode=active_mode,
            injection_profile=injection_profile,
            auth_cookie=auth_cookie,
            auth_header=auth_header,
            raw_request=raw_request,
            scan_id=scan_id,
            progress_id=progress_id,
            auto_install=auto_install,
            wait_for_completion=wait_for_completion,
        )
        try:
            report = run_assessment(ctx, APP.bdu)
            saved_paths = save_report(report)
            PROGRESS.finish(progress_id)
            self._send_html(APP.page(report=report, saved_paths=saved_paths))
        except Exception as exc:
            error_name = f"error_{safe_filename(progress_id)}.log"
            error_path = REPORTS_DIR / error_name
            try:
                error_path.write_text(
                    f"target={target_url}\nerror={type(exc).__name__}: {exc}\n\n{traceback.format_exc()}",
                    encoding="utf-8",
                )
            except OSError:
                error_name = "журнал прогресса"
            PROGRESS.fail(progress_id, f"Анализ прерван: {type(exc).__name__}: {exc}; журнал: {error_name}")
            self._send_html(APP.page(f"Анализ прерван ({type(exc).__name__}). Диагностика: {error_name}."))

    def _send_static(self, relative: str) -> None:
        path = (STATIC_DIR / relative).resolve()
        if not str(path).startswith(str(STATIC_DIR.resolve())) or not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        content_type = "text/css" if path.suffix == ".css" else "application/javascript"
        self._send_bytes(path.read_bytes(), content_type)

    def _send_report_file(self, relative: str) -> None:
        path = (REPORTS_DIR / relative).resolve()
        if not str(path).startswith(str(REPORTS_DIR.resolve())) or not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        if path.suffix == ".html":
            report = load_report_for_html(path)
            if report:
                self._send_html(render_static_report(report))
                return
        content_type = "text/html" if path.suffix == ".html" else "application/json"
        self._send_bytes(path.read_bytes(), content_type)

    def _send_report_package(self, relative: str) -> None:
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)\.zip", relative)
        if not match:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        scan_id = match.group(1)
        package = build_report_package(scan_id)
        if package is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        delivered = self._send_bytes(
            package,
            "application/zip",
            {"Content-Disposition": f'attachment; filename="report_{safe_filename(scan_id)}.zip"'},
        )
        if delivered:
            removed = cleanup_scan_artifacts(scan_id)
            print(f"[cleanup] scan {scan_id}: удалено объектов {removed}")

    def _send_html(self, html: str) -> None:
        self._send_bytes(html.encode("utf-8"), "text/html; charset=utf-8")

    def _send_json(self, payload) -> None:
        self._send_bytes(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _send_bytes(self, data: bytes, content_type: str, headers: dict[str, str] | None = None) -> bool:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(data)
            self.wfile.flush()
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False

    def log_message(self, fmt: str, *args) -> None:
        path = getattr(self, "path", "")
        if path.startswith("/api/progress"):
            return
        print(f"[web] {self.address_string()} - {fmt % args}")


def _auto_update_bdu_async() -> None:
    """Фоновое авто-обновление базы БДУ при старте, если включено флагом окружения.

    Не блокирует запуск сервера и не ломает его при сетевом сбое/геоблоке:
    при ошибке работа продолжается на текущей базе.
    """
    def worker() -> None:
        try:
            result = ensure_bdu_fresh(log=lambda message, level="info": emit("bdu-update", message, level))
            emit("bdu-update", f"Авто-обновление БДУ: {result.get('status')}", "info")
        except Exception as exc:  # авто-обновление не должно влиять на работу сервера
            emit("bdu-update", f"Авто-обновление БДУ пропущено: {exc}", "warning")

    threading.Thread(target=worker, name="bdu-auto-update", daemon=True).start()


def run(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    if os.environ.get("BDU_AUTO_UPDATE", "").strip().lower() in {"1", "true", "yes", "on"}:
        _auto_update_bdu_async()
    server = ThreadingHTTPServer((host, port), RequestHandler)
    print(f"BDU Domain & Network Analyzer: http://{host}:{port}")
    server.serve_forever()


def load_report_for_html(html_path: Path) -> ScanReport | None:
    json_path = html_path.with_suffix(".json")
    if not json_path.exists():
        return None
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return ScanReport(
            scan_id=data["scan_id"],
            target_url=data["target_url"],
            host=data["host"],
            generated_at=data["generated_at"],
            duration_seconds=data["duration_seconds"],
            findings=[Finding(**item) for item in data.get("findings", [])],
            assets=data.get("assets", {}),
            tool_statuses=[ToolStatus(**item) for item in data.get("tool_statuses", [])],
            bdu_stats=data.get("bdu_stats", {}),
            notes=data.get("notes", []),
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return None


def cleanup_scan_artifacts(scan_id: str) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", scan_id):
        return 0
    root = REPORTS_DIR.resolve()
    removed = 0
    for candidate in list(REPORTS_DIR.iterdir()) if REPORTS_DIR.exists() else []:
        if scan_id not in candidate.name:
            continue
        resolved = candidate.resolve()
        if resolved.parent != root:
            continue
        try:
            if resolved.is_dir():
                shutil.rmtree(resolved)
            else:
                resolved.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def build_report_package(scan_id: str) -> bytes | None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", scan_id):
        return None
    html_path = REPORTS_DIR / f"scan_{scan_id}.html"
    json_path = REPORTS_DIR / f"scan_{scan_id}.json"
    report = load_report_for_html(html_path)
    if not report or not json_path.exists():
        return None
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(html_path.name, render_static_report(report).encode("utf-8"))
        archive.writestr(json_path.name, json_path.read_bytes())
    return payload.getvalue()


def recent_reports(limit: int = 5) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for json_path in sorted(REPORTS_DIR.glob("scan_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:limit]:
        html_path = json_path.with_suffix(".html")
        if not html_path.exists():
            continue
        title = json_path.stem.removeprefix("scan_")
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            title = f"{data.get('host', title)} · {data.get('generated_at', '')}".strip()
        except (OSError, json.JSONDecodeError):
            pass
        items.append(
            {
                "title": title,
                "html_name": html_path.name,
                "json_name": json_path.name,
                "scan_id": json_path.stem.removeprefix("scan_"),
            }
        )
    return items
