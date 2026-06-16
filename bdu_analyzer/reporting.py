# -*- coding: utf-8 -*-

import html
import json
from pathlib import Path
from typing import Any

from .config import REPORTS_DIR, SEVERITY_ORDER, SEVERITY_WEIGHT, STATIC_DIR
from .knowledge import PRACTICUM_ANALYZERS, PRACTICUM_VULNERABILITIES
from .models import ScanReport


def report_metrics(report: ScanReport | dict[str, Any]) -> dict[str, Any]:
    findings = report.findings if isinstance(report, ScanReport) else report.get("findings", [])
    counts = {name: 0 for name in ["Критический", "Высокий", "Средний", "Низкий", "Инфо"]}
    penalty = 0.0
    for item in findings:
        severity = item.severity if hasattr(item, "severity") else item.get("severity", "Инфо")
        confidence = item.confidence if hasattr(item, "confidence") else item.get("confidence", "Средняя")
        counts[severity] = counts.get(severity, 0) + 1
        penalty += SEVERITY_WEIGHT.get(severity, 0) * confidence_factor(confidence)
    penalty = min(95, penalty)
    score = max(0, int(round(100 - penalty)))
    serious = counts.get("Критический", 0) + counts.get("Высокий", 0)
    if serious == 0:
        score = max(score, 65)
    if serious == 0 and score >= 80:
        grade = "Хорошо"
    elif score >= 60 or serious == 0:
        grade = "Требует внимания"
    elif score >= 35:
        grade = "Рискованно"
    else:
        grade = "Критично"
    return {"counts": counts, "score": score, "grade": grade, "total": sum(counts.values())}


def confidence_factor(confidence: str) -> float:
    return {
        "Низкая": 0.25,
        "Средняя": 0.75,
        "Высокая": 1.0,
    }.get(confidence, 0.75)


def save_report(report: ScanReport) -> tuple[Path, Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORTS_DIR / f"scan_{report.scan_id}.json"
    html_path = REPORTS_DIR / f"scan_{report.scan_id}.html"
    json_path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_static_report(report), encoding="utf-8")
    return json_path, html_path


def render_static_report(report: ScanReport) -> str:
    data = report.to_dict()
    metrics = report_metrics(report)
    findings = data["findings"]
    actionable_findings = [item for item in findings if item.get("severity") != "Инфо"]
    primary_findings = [item for item in actionable_findings if not needs_manual_verification(item)]
    verification_findings = [item for item in actionable_findings if needs_manual_verification(item)]
    info_findings = [item for item in findings if item.get("severity") == "Инфо"]
    rows = (
        render_finding_section("Основные находки", primary_findings, "Подтверждённых значимых находок нет в рамках выбранного профиля.")
        + render_verification_findings(verification_findings)
        + render_info_findings(info_findings)
    )
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Отчёт ИБ: {html.escape(report.host)}</title>
  <style>{load_report_css()}</style>
</head>
<body class="report-body">
  <main class="shell">
    <section class="hero compact">
      <div>
        <p class="eyebrow">Аналитика ИБ домена</p>
        <h1>{html.escape(report.host)}</h1>
        <p class="lead">{html.escape(report.target_url)} · {html.escape(report.generated_at)}</p>
      </div>
      <div class="score-ring">
        <strong>{metrics["score"]}</strong>
        <span>{html.escape(metrics["grade"])}</span>
      </div>
    </section>
    {render_executive_summary(report, metrics)}
    {render_metric_strip(metrics, report)}
    <section class="panel report-section">
      <h2>Сводка проблем</h2>
      {render_report_analytics(report, metrics)}
    </section>
    <section class="panel report-section">
      <h2>План исправления</h2>
      {render_remediation_plan(report)}
    </section>
    <section class="panel">
      <h2>Находки</h2>
      <div class="finding-list">{rows or '<p class="muted">Находок нет.</p>'}</div>
    </section>
  </main>
</body>
</html>"""


def load_report_css() -> str:
    try:
        return (STATIC_DIR / "style.css").read_text(encoding="utf-8")
    except OSError:
        return ""


def render_index(
    *,
    tool_statuses: list[Any],
    bdu_stats: dict[str, Any],
    error: str = "",
    report: ScanReport | None = None,
    saved_paths: tuple[Path, Path] | None = None,
    recent_reports: list[dict[str, str]] | None = None,
) -> str:
    metrics = report_metrics(report) if report else None
    result_html = render_results(report, metrics, saved_paths) if report and metrics else ""
    def checked(key: str) -> str:
        return "checked" if any(getattr(t, "key", "") == key and getattr(t, "selected", False) for t in tool_statuses) else ""

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BDU Domain Analyzer</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="hero-copy">
        <p class="eyebrow">БДУ ФСТЭК · Web · DNS · TLS</p>
        <h1>Аналитика ИБ целевого домена</h1>
        <p class="lead">Единая панель для безопасных базовых проверок, внешних сканеров из практикума и обогащения находок через БДУ ФСТЭК России.</p>
      </div>
      <form class="scan-form" method="post" action="/scan" data-testid="scan-form">
        <label class="field">
          <span>Адрес для проверки</span>
          <input name="target" type="text" placeholder="https://example.ru" value="{html.escape(report.target_url if report else '')}" required>
        </label>
        <div class="switch-grid">
          <label class="checkline">
            <input type="checkbox" name="authorized" value="1" required>
            <span>Права на проверку подтверждены</span>
          </label>
          <label class="checkline">
            <input type="checkbox" name="active_mode" value="1">
            <span>Активный профиль</span>
          </label>
        </div>
        <details class="auth-options">
          <summary>XSS/SQLi и авторизованный режим</summary>
          <label class="checkline">
            <input type="checkbox" name="injection_profile" value="1" data-injection-profile>
            <span>Глубокая проверка XSS/SQL-инъекций</span>
          </label>
          <label class="field">
            <span>Cookie авторизованной сессии</span>
            <textarea name="auth_cookie" rows="2" placeholder="sessionid=...; csrftoken=..."></textarea>
          </label>
          <label class="field">
            <span>Authorization или полный HTTP-заголовок</span>
            <input name="auth_header" type="text" placeholder="Bearer ... или Authorization: Bearer ...">
          </label>
          <label class="field">
            <span>Raw HTTP-запрос для SQLMap</span>
            <textarea name="raw_request" rows="5" placeholder="GET /search?q=test HTTP/1.1&#10;Host: example.ru&#10;Cookie: sessionid=..."></textarea>
          </label>
        </details>
        <div class="tool-picks">
          <label><input type="checkbox" name="tools" value="nmap" {checked('nmap')}> Nmap</label>
          <label><input type="checkbox" name="tools" value="wapiti" {checked('wapiti')}> Wapiti</label>
          <label><input type="checkbox" name="tools" value="wfuzz" {checked('wfuzz')}> Wfuzz</label>
          <label><input type="checkbox" name="tools" value="whatweb" {checked('whatweb')}> WhatWeb</label>
          <label><input type="checkbox" name="tools" value="nikto" {checked('nikto')}> Nikto</label>
          <label><input type="checkbox" name="tools" value="sqlmap" {checked('sqlmap')}> SQLMap</label>
          <label><input type="checkbox" name="tools" value="openvas" {checked('openvas')}> OpenVAS</label>
          <label><input type="checkbox" name="tools" value="burp" {checked('burp')}> Burp-lite</label>
          <label><input type="checkbox" name="tools" value="skipfish" {checked('skipfish')}> SkipFish</label>
          <label><input type="checkbox" name="tools" value="legion" {checked('legion')}> Legion</label>
        </div>
        <button class="primary" type="submit" data-testid="scan-button"><span>Запустить анализ</span></button>
        {f'<p class="form-error">{html.escape(error)}</p>' if error else ''}
      </form>
    </section>

    <section class="status-band">
      <div>
        <strong>{int(bdu_stats.get('total', 0)):,}</strong>
        <span>записей БДУ</span>
      </div>
      <div>
        <strong>{int(bdu_stats.get('with_cve', 0)):,}</strong>
        <span>CVE в базе</span>
      </div>
      <div>
        <strong>{sum(1 for item in tool_statuses if getattr(item, 'available', False))}</strong>
        <span>сканеров доступны</span>
      </div>
    </section>

    {result_html}

    {render_recent_reports(recent_reports or [], collapsed=bool(report))}

    {render_reference_sections(tool_statuses, collapsed=bool(report))}
  </main>
  <script src="/static/app.js"></script>
</body>
</html>"""


def render_recent_reports(reports: list[dict[str, str]], collapsed: bool) -> str:
    if not reports:
        return ""
    rows = "".join(
        f"""<article>
          <strong>{html.escape(item.get('title', 'Отчёт'))}</strong>
          <div>
            <a href="/reports/{html.escape(item.get('html_name', ''))}" download>Скачать HTML</a>
            <a href="/reports/{html.escape(item.get('json_name', ''))}" download>JSON</a>
          </div>
        </article>"""
        for item in reports
    )
    open_attr = "" if collapsed else " open"
    return f"""<details class="recent-reports"{open_attr}>
      <summary>Последние отчёты</summary>
      <div class="recent-report-list">{rows}</div>
    </details>"""


def render_reference_sections(tool_statuses: list[Any], collapsed: bool) -> str:
    if collapsed:
        selected = [item for item in tool_statuses if getattr(item, "selected", False)]
        available = sum(1 for item in selected if getattr(item, "available", False))
        selected_cards = "\n".join(render_tool_card(item) for item in selected[:10])
        return f"""
    <details class="reference-dock">
      <summary>Справка по практикуму и подключённым адаптерам</summary>
      <p class="muted">Выбрано сканеров: {len(selected)}. Доступно с учётом встроенных fallback-проверок: {available}. Полный справочник показывается на стартовом экране до запуска анализа.</p>
      <div class="tool-grid compact">{selected_cards or '<p class="muted">Сканеры не выбраны.</p>'}</div>
    </details>"""
    tool_cards = "\n".join(render_tool_card(item) for item in tool_statuses)
    analyzers = "\n".join(
        f"<tr><td>{html.escape(item['name'])}</td><td>{html.escape(item['kind'])}</td><td>{html.escape(item['studies'])}</td><td>{html.escape(item['domain_scan'])}</td></tr>"
        for item in PRACTICUM_ANALYZERS
    )
    vuln_tags = "\n".join(f"<span>{html.escape(item)}</span>" for item in PRACTICUM_VULNERABILITIES)
    open_attr = ""
    return f"""
    <details class="panel details-panel"{open_attr}>
      <summary>
        <span>
          <small>Практикум 10.05.01</small>
          <strong>Справочник: анализаторы и уязвимости</strong>
        </span>
      </summary>
      <div class="tag-cloud">{vuln_tags}</div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Инструмент</th><th>Тип</th><th>Что исследует</th><th>Домены / поддомены / сайт</th></tr></thead>
          <tbody>{analyzers}</tbody>
        </table>
      </div>
    </details>

    <details class="panel details-panel"{open_attr}>
      <summary>
        <span>
          <small>Адаптеры</small>
          <strong>Подключение внешних сканеров</strong>
        </span>
      </summary>
      <div class="tool-grid">{tool_cards}</div>
    </details>"""


def render_results(report: ScanReport, metrics: dict[str, Any], saved_paths: tuple[Path, Path] | None) -> str:
    findings = report.to_dict()["findings"]
    actionable_findings = [item for item in findings if item.get("severity") != "Инфо"]
    primary_findings = [item for item in actionable_findings if not needs_manual_verification(item)]
    verification_findings = [item for item in actionable_findings if needs_manual_verification(item)]
    info_findings = [item for item in findings if item.get("severity") == "Инфо"]
    grouped = group_recommendations(findings)
    dns = report.assets.get("dns", {})
    subdomains = report.assets.get("subdomains", [])
    ports = report.assets.get("nmap", {}).get("ports", []) or report.assets.get("nmap_fallback", {}).get("ports", [])
    paths = report.assets.get("paths", [])
    tool_assets = {
        key: value
        for key, value in report.assets.items()
        if key.endswith("_lite") or key in {"external_reports", "nmap", "nmap_fallback"}
    }
    saved = ""
    downloads = ""
    if saved_paths:
        downloads = render_download_buttons(saved_paths)
        saved = f"""<details class="report-files">
          <summary>Файлы отчёта</summary>
          <code>{html.escape(str(saved_paths[0]))}</code>
          <code>{html.escape(str(saved_paths[1]))}</code>
        </details>"""
    return f"""
    <section class="result-layout" data-testid="result-layout">
      <aside class="score-panel">
        <div class="score-ring large">
          <strong>{metrics['score']}</strong>
          <span>{html.escape(metrics['grade'])}</span>
        </div>
        <dl class="scan-meta">
          <div><dt>Цель</dt><dd>{html.escape(report.target_url)}</dd></div>
          <div><dt>Скан</dt><dd>{html.escape(report.generated_at)}</dd></div>
          <div><dt>Время</dt><dd>{report.duration_seconds} c</dd></div>
        </dl>
        {downloads}
        {saved}
      </aside>
      <div class="result-main">
        {render_executive_summary(report, metrics)}
        {render_metric_strip(metrics, report)}
        {render_scan_notes(report)}
        <div class="tabs" role="tablist">
          <button class="tab active" data-tab="findings" type="button">Детали</button>
          <button class="tab" data-tab="assets" type="button">Поверхность</button>
          <button class="tab" data-tab="bdu" type="button">БДУ</button>
          <button class="tab" data-tab="actions" type="button">План действий</button>
        </div>
        <section class="tab-panel active" id="tab-findings">
          <div class="finding-list">
            {render_finding_section('Основные находки', primary_findings, 'Подтверждённых значимых находок нет в рамках выбранного профиля.')}
            {render_verification_findings(verification_findings)}
            {render_info_findings(info_findings)}
          </div>
        </section>
        <section class="tab-panel" id="tab-assets">
          <div class="asset-grid">
            {render_asset_block('DNS', dns)}
            {render_asset_block('Поддомены', subdomains)}
            {render_asset_block('Порты Nmap', ports)}
            {render_asset_block('Пути', paths)}
            {render_asset_block('Инструменты', tool_assets)}
          </div>
        </section>
        <section class="tab-panel" id="tab-bdu">
          {render_bdu_block(report)}
        </section>
        <section class="tab-panel" id="tab-actions">
          <div class="recommendations">{''.join(f'<article><h3>{html.escape(k)}</h3><p>{html.escape(v)}</p></article>' for k, v in grouped.items())}</div>
        </section>
      </div>
    </section>"""


def render_download_buttons(saved_paths: tuple[Path, Path]) -> str:
    json_path, html_path = saved_paths
    return f"""<div class="download-actions">
      <a class="download-button primary-download" href="/reports/{html.escape(html_path.name)}" download>Скачать HTML-отчёт</a>
      <a class="download-button" href="/reports/{html.escape(json_path.name)}" download>Скачать JSON</a>
    </div>"""


def render_info_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    return f"""<details class="info-findings">
      <summary>Показать информационные находки ({len(findings)})</summary>
      <div class="finding-list compact">{''.join(render_finding_row(item) for item in findings)}</div>
    </details>"""


def render_finding_section(title: str, findings: list[dict[str, Any]], empty_text: str) -> str:
    if not findings:
        return f"""<section class="finding-section">
          <div class="finding-section-head">
            <h3>{html.escape(title)}</h3>
          </div>
          <p class="muted">{html.escape(empty_text)}</p>
        </section>"""
    return f"""<section class="finding-section">
      <div class="finding-section-head">
        <h3>{html.escape(title)}</h3>
        <span>{len(findings)}</span>
      </div>
      <div class="finding-list compact">{''.join(render_finding_row(item) for item in findings)}</div>
    </section>"""


def render_verification_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    return f"""<details class="verification-findings" open>
      <summary>Требуют ручной проверки ({len(findings)})</summary>
      <p class="muted">Это эвристики встроенных fallback-проверок или находки с низкой уверенностью. Их стоит подтвердить Nmap, Wapiti, ручным HTTP-запросом или логами сервера перед постановкой задачи.</p>
      <div class="finding-list compact">{''.join(render_finding_row(item) for item in findings)}</div>
    </details>"""


def render_executive_summary(report: ScanReport, metrics: dict[str, Any]) -> str:
    important = sorted([
        item for item in report.findings
        if item.severity in {"Критический", "Высокий", "Средний"} and item.confidence != "Низкая"
    ], key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), executive_priority(item)), reverse=True)[:3]
    if not important:
        verification_count = sum(
            1 for item in report.findings
            if item.severity != "Инфо" and item.confidence == "Низкая"
        )
        if verification_count:
            verdict = f"Подтверждённых критичных проблем не найдено; {verification_count} эвристик вынесены в ручную проверку."
        else:
            verdict = "Критических и высоких проблем не обнаружено в рамках выбранных проверок."
    else:
        titles = "; ".join(item.title for item in important)
        verdict = f"Главное: {titles}."
    next_steps = build_next_steps(report)
    steps = "".join(f"<li>{html.escape(step)}</li>" for step in next_steps)
    return f"""<section class="summary-panel">
      <div>
        <p class="eyebrow">Краткий вывод</p>
        <h2>{html.escape(metrics['grade'])}</h2>
        <p>{html.escape(verdict)}</p>
      </div>
      <div class="next-steps">
        <h3>Что сделать сначала</h3>
        <ol>{steps}</ol>
      </div>
    </section>"""


def executive_priority(item: Any) -> int:
    title = item.title.lower()
    category = item.category.lower()
    if "tls" in category or "сертификат" in title:
        return 5
    if "network exposure" in category:
        return 4
    if "http headers" in category:
        return 3
    if "sql" in category or "xss" in category:
        return 5
    return 1


def build_next_steps(report: ScanReport) -> list[str]:
    steps: list[str] = []
    titles = {item.title for item in report.findings}
    categories = {item.category for item in report.findings}
    if any("TLS" in item.category or "сертификат" in item.title.lower() for item in report.findings):
        steps.append("Разобраться с TLS-сертификатом: доверенная цепочка, самоподписанный сертификат, SNI и срок действия.")
    if "HTTP headers" in categories:
        steps.append("Добавить недостающие защитные HTTP-заголовки и повторить проверку.")
    if any(item.bdu_matches for item in report.findings):
        steps.append("Разобрать прямые совпадения БДУ/CVE и назначить исправления владельцам систем.")
    if any(item.severity != "Инфо" and item.confidence == "Низкая" for item in report.findings):
        steps.append("Подтвердить эвристические находки вручную, чтобы отделить реальные endpoints от soft-404/SPA fallback.")
    if report.notes:
        steps.append("Посмотреть диагностические сообщения сканеров: часть инструментов могла не дать результатов.")
    if not steps:
        steps.append("Проверить вкладку «Поверхность» и сохранить отчёт как baseline для следующего скана.")
    return steps[:4]


def render_scan_notes(report: ScanReport) -> str:
    if not report.notes:
        return ""
    items = "".join(f"<li>{html.escape(note)}</li>" for note in report.notes[:8])
    return f"""<details class="scan-notes">
      <summary>Диагностика запуска сканеров ({len(report.notes)})</summary>
      <ul>{items}</ul>
    </details>"""


def render_metric_strip(metrics: dict[str, Any], report: ScanReport) -> str:
    counts = metrics["counts"]
    total = max(metrics["total"], 1)
    bars = "".join(
        f"<div><span>{html.escape(sev)}</span><strong>{count}</strong><i style='width:{round(count / total * 100)}%'></i></div>"
        for sev, count in counts.items()
    )
    return f"""<section class="metric-strip">
      <div><strong>{metrics['total']}</strong><span>всего находок</span></div>
      <div><strong>{counts.get('Критический', 0) + counts.get('Высокий', 0)}</strong><span>критичных и высоких</span></div>
      <div><strong>{sum(1 for item in report.findings if item.bdu_matches)}</strong><span>прямых БДУ/CVE</span></div>
      <div class="severity-bars">{bars}</div>
    </section>"""


def render_report_analytics(report: ScanReport, metrics: dict[str, Any]) -> str:
    actionable = [item for item in report.findings if item.severity != "Инфо"]
    direct_matches = [item for item in report.findings if item.bdu_matches]
    category_counts: dict[str, int] = {}
    for item in actionable:
        category_counts[item.category] = category_counts.get(item.category, 0) + 1
    categories = "".join(
        f"<li><strong>{html.escape(category)}</strong><span>{count}</span></li>"
        for category, count in sorted(category_counts.items(), key=lambda pair: pair[1], reverse=True)
    )
    top_items = sorted(
        actionable,
        key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), confidence_factor(item.confidence)),
        reverse=True,
    )[:5]
    top = "".join(
        f"<li><strong>{html.escape(item.title)}</strong><p>{html.escape(item.description)}</p></li>"
        for item in top_items
    )
    if not top:
        top = "<li><strong>Значимых проблем не найдено</strong><p>Скан не подтвердил критичные или высокие риски в выбранной области проверки.</p></li>"
    bdu_text = (
        f"Найдено прямых совпадений БДУ/CVE: {len(direct_matches)}."
        if direct_matches
        else "Прямых совпадений с БДУ/CVE по найденным данным нет."
    )
    return f"""<div class="report-analytics">
      <article>
        <h3>Итоговая оценка</h3>
        <p>Оценка риска: <strong>{metrics['score']} / {html.escape(metrics['grade'])}</strong>. Всего находок: {metrics['total']}; критичных и высоких: {metrics['counts'].get('Критический', 0) + metrics['counts'].get('Высокий', 0)}.</p>
        <p>{html.escape(bdu_text)}</p>
      </article>
      <article>
        <h3>Группы проблем</h3>
        <ul class="category-list">{categories or '<li><strong>Нет значимых групп</strong><span>0</span></li>'}</ul>
      </article>
      <article class="wide">
        <h3>Главные риски</h3>
        <ol class="priority-list">{top}</ol>
      </article>
    </div>"""


def render_remediation_plan(report: ScanReport) -> str:
    grouped = group_recommendations([item.to_dict() for item in report.findings if item.severity != "Инфо"])
    if not grouped:
        return "<p class='muted'>План исправления не сформирован: значимых находок нет.</p>"
    cards = []
    for index, (category, remediation) in enumerate(grouped.items(), start=1):
        cards.append(
            f"""<article>
              <span>{index}</span>
              <div>
                <h3>{html.escape(category)}</h3>
                <p>{html.escape(remediation)}</p>
              </div>
            </article>"""
        )
    return f"<div class='remediation-plan'>{''.join(cards[:10])}</div>"


def render_finding_row(item: dict[str, Any]) -> str:
    bdu_badge = ""
    if item.get("bdu_matches"):
        bdu_badge = "<span class='badge bdu'>БДУ</span>"
    verification_badge = "<span class='badge verify'>проверить вручную</span>" if needs_manual_verification(item) else ""
    cve = ", ".join(item.get("cve") or [])
    cwe = ", ".join(item.get("cwe") or [])
    matches = ""
    if item.get("bdu_matches"):
        matches = "<details class='bdu-match'><summary>Прямые совпадения БДУ/CVE</summary>" + "".join(
            f"<p><strong>{html.escape(match.get('bdu_id', ''))}</strong> {html.escape(match.get('title', '')[:260])}</p>"
            for match in item["bdu_matches"][:2]
        ) + "</details>"
    evidence = item.get("evidence", "")
    tech = ""
    if evidence or cve or cwe:
        tech = f"""<details class="tech-details">
          <summary>Технические детали</summary>
          {f'<pre>{html.escape(evidence)}</pre>' if evidence else ''}
          <dl>
            {f'<div><dt>CVE</dt><dd>{html.escape(cve)}</dd></div>' if cve else ''}
            {f'<div><dt>CWE</dt><dd>{html.escape(cwe)}</dd></div>' if cwe else ''}
          </dl>
        </details>"""
    return f"""<article class="finding severity-{severity_class(item.get('severity', 'Инфо'))}">
      <div class="finding-top">
        <span class="badge">{html.escape(item.get('severity', 'Инфо'))}</span>
        <span class="badge confidence">{html.escape(item.get('confidence', 'Средняя'))} уверенность</span>
        {verification_badge}
        {bdu_badge}
        <span class="source">{html.escape(item.get('scanner', ''))}</span>
      </div>
      <h3>{html.escape(item.get('title', ''))}</h3>
      <div class="finding-meaning">
        <div><strong>Что это значит</strong><p>{html.escape(item.get('description', ''))}</p></div>
        <div><strong>Что сделать</strong><p>{html.escape(item.get('remediation', '') or 'Проверьте находку вручную и зафиксируйте корректирующее действие.')}</p></div>
      </div>
      {tech}
      {matches}
    </article>"""


def render_tool_card(item: Any) -> str:
    status = "available" if item.available else "missing"
    selected = " selected" if item.selected else ""
    return f"""<article class="tool-card {status}{selected}">
      <div><strong>{html.escape(item.name)}</strong><span>{'доступен' if item.available else 'не найден'}</span></div>
      <p>{html.escape(item.note)}</p>
      {f'<code>{html.escape(item.path)}</code>' if item.path else ''}
    </article>"""


def needs_manual_verification(item: dict[str, Any]) -> bool:
    scanner = item.get("scanner", "")
    if item.get("confidence") == "Низкая" and item.get("severity") != "Инфо":
        return True
    if item.get("severity") != "Инфо" and any(token in scanner for token in ["-lite", "Socket port scan"]):
        return item.get("confidence", "Средняя") != "Высокая"
    return False


def render_asset_block(title: str, value: Any) -> str:
    return f"""<article class="asset-block">
      <h3>{html.escape(title)}</h3>
      <pre>{html.escape(json.dumps(value, ensure_ascii=False, indent=2)[:5000])}</pre>
    </article>"""


def render_bdu_block(report: ScanReport) -> str:
    stats = report.bdu_stats
    matched = [item for item in report.findings if item.bdu_matches]
    return f"""<div class="bdu-panel">
      <div class="bdu-stat"><strong>{int(stats.get('total', 0)):,}</strong><span>записей в локальной базе</span></div>
      <div class="bdu-stat"><strong>{int(stats.get('with_cve', 0)):,}</strong><span>CVE-идентификаторов</span></div>
      <div class="bdu-stat"><strong>{len(matched)}</strong><span>находок с прямым совпадением</span></div>
    </div>
    <p class="muted">Прямое сопоставление выполняется только по CVE. Справочные примеры по CWE скрыты из карточек, чтобы не смешивать реальные находки с похожими записями базы.</p>"""


def group_recommendations(findings: list[dict[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    ordered = sorted(findings, key=lambda item: SEVERITY_ORDER.get(item.get("severity", "Инфо"), 0), reverse=True)
    for item in ordered:
        key = item.get("category") or item.get("title") or "Общие меры"
        result.setdefault(key, item.get("remediation") or "Проверьте находку вручную.")
    return result


def severity_class(value: str) -> str:
    return {
        "Критический": "critical",
        "Высокий": "high",
        "Средний": "medium",
        "Низкий": "low",
        "Инфо": "info",
    }.get(value, "info")
