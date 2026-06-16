# -*- coding: utf-8 -*-

import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .bdu import BDUHandler
from .config import DEFAULT_HOST, DEFAULT_PORT, REPORTS_DIR, STATIC_DIR
from .models import Finding, ScanContext, ScanReport, ToolStatus
from .reporting import render_index, render_static_report, save_report
from .scanners import discover_tools, run_assessment
from .target import TargetError, normalize_target, safe_filename


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
    server_version = "BDUDomainAnalyzer/1.0"

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

        if injection_profile or raw_request:
            active_mode = True
            selected_tools.update({"wapiti", "sqlmap", "burp"})

        if not authorized:
            self._send_html(APP.page("Подтвердите право на проверку цели."))
            return
        try:
            target_url, host = normalize_target(target)
        except TargetError as exc:
            self._send_html(APP.page(str(exc)))
            return

        scan_id = f"{safe_filename(host)}_{time.strftime('%Y%m%d_%H%M%S')}"
        ctx = ScanContext(
            original_target=target,
            target_url=target_url,
            host=host,
            selected_tools=selected_tools,
            active_mode=active_mode,
            injection_profile=injection_profile,
            auth_cookie=auth_cookie,
            auth_header=auth_header,
            raw_request=raw_request,
            scan_id=scan_id,
        )
        report = run_assessment(ctx, APP.bdu)
        saved_paths = save_report(report)
        self._send_html(APP.page(report=report, saved_paths=saved_paths))

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

    def _send_html(self, html: str) -> None:
        self._send_bytes(html.encode("utf-8"), "text/html; charset=utf-8")

    def _send_json(self, payload) -> None:
        self._send_bytes(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def _send_bytes(self, data: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        print(f"[web] {self.address_string()} - {fmt % args}")


def run(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    server = ThreadingHTTPServer((host, port), RequestHandler)
    print(f"BDU Domain Analyzer: http://{host}:{port}")
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


def recent_reports(limit: int = 5) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for json_path in sorted(REPORTS_DIR.glob("scan_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)[:limit]:
        html_path = json_path.with_suffix(".html")
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
            }
        )
    return items
