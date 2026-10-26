# -*- coding: utf-8 -*-

"""Автообновление локальных данных анализатора.

Две части:
  * база БДУ ФСТЭК — скачать официальную выгрузку (или взять локальный файл),
    пересобрать bdu.db атомарно, записать метаданные версии;
  * версии сканеров — сверить закреплённые в SCANNERS_SOURCE.json версии с
    актуальными релизами upstream (GitHub) и сообщить о доступных обновлениях.

Сетевые сбои и геоблок обрабатываются мягко: существующая база не ломается.
Источники зафиксированы (официальный сайт/allowlist репозиториев) — значение из
внешнего ответа никогда не становится произвольной командой или путём.
"""

import gzip
import json
import os
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

from .bdu import BDUHandler
from .config import (
    BDU_DB_PATH,
    BDU_EXPORT_URL,
    BDU_FRESH_MAX_AGE_DAYS,
    BDU_MAX_DOWNLOAD_BYTES,
    BDU_XML_DIR,
    SCANNER_SOURCE_MANIFEST,
)

USER_AGENT = "BDU-Analyzer-Updater/1.0"
Logger = Callable[[str, str], None]


def _default_log(message: str, level: str = "info") -> None:
    print(f"[{level}] {message}")


# --------------------------------------------------------------------------
# База БДУ
# --------------------------------------------------------------------------

def update_bdu_database(
    source: str | None = None,
    *,
    db_path: Path = BDU_DB_PATH,
    xml_dir: Path = BDU_XML_DIR,
    log: Logger = _default_log,
) -> dict[str, Any]:
    """Обновить локальную базу БДУ из выгрузки ФСТЭК.

    ``source`` — URL (по умолчанию официальный BDU_EXPORT_URL, можно задать через
    переменную окружения BDU_EXPORT_URL) либо локальный путь к .xml/.zip/.gz или
    каталогу с такими файлами (для окружений с геоблоком — скачайте вручную и
    укажите файл). База пересобирается во временном файле и заменяется атомарно,
    поэтому при ошибке текущая база остаётся рабочей.
    """
    source = source or os.environ.get("BDU_EXPORT_URL") or BDU_EXPORT_URL
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="bdu_update_") as tmp:
        staging = Path(tmp) / "xml"
        staging.mkdir(parents=True, exist_ok=True)
        try:
            origin = _materialize_source(source, Path(tmp), log)
            xml_files = _collect_xml_files(origin, staging, log)
        except (OSError, urllib.error.URLError, zipfile.BadZipFile, ValueError) as exc:
            log(f"Обновление БДУ прервано: {exc}. Текущая база сохранена.", "error")
            return {"status": "failed", "error": str(exc), "source": source}

        if not xml_files:
            log("В источнике не найдено XML-файлов БДУ. Текущая база сохранена.", "error")
            return {"status": "failed", "error": "no xml files", "source": source}

        # Новую базу строим РЯДОМ с целевой (та же ФС), иначе os.replace может
        # упасть как cross-device. Заменяем атомарно только после успешного импорта.
        db_path.parent.mkdir(parents=True, exist_ok=True)
        new_db = db_path.with_name(db_path.name + ".new")
        new_db.unlink(missing_ok=True)
        handler = BDUHandler(db_path=new_db, xml_dir=staging)
        imported = handler.import_all_xml()
        total = handler.stats().get("total", 0)
        if total <= 0:
            new_db.unlink(missing_ok=True)
            log("После импорта база пуста — замена отменена, текущая база сохранена.", "error")
            return {"status": "failed", "error": "empty after import", "source": source}

        handler.set_meta("source", source)
        handler.set_meta("updated_at", time.strftime("%Y-%m-%d %H:%M:%S"))

        # Атомарная замена базы и обновление каталога XML-выгрузки.
        os.replace(new_db, db_path)
        _refresh_xml_dir(xml_files, xml_dir, log)

    elapsed = time.time() - started
    log(f"База БДУ обновлена: {total} записей, импортировано {imported}, за {elapsed:.1f} с.", "info")
    return {
        "status": "updated",
        "source": source,
        "imported": imported,
        "total": total,
        "duration_seconds": round(elapsed, 1),
    }


def bdu_age_days(db_path: Path = BDU_DB_PATH) -> float | None:
    """Возраст базы в днях по метаданным импорта.

    None означает «неизвестно» (нет отметки о версии) — вызывающий код считает
    такую базу устаревшей и обновляет её. На mtime файла не опираемся: простое
    открытие базы создаёт служебные таблицы и сбрасывает mtime.
    """
    try:
        handler = BDUHandler(db_path=db_path)
        stamp = handler.get_meta("updated_at") or handler.get_meta("last_import_at")
    except Exception:
        stamp = ""
    if stamp:
        try:
            parsed = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
            return (time.time() - parsed) / 86400.0
        except ValueError:
            pass
    return None


def ensure_bdu_fresh(
    max_age_days: int = BDU_FRESH_MAX_AGE_DAYS,
    source: str | None = None,
    *,
    log: Logger = _default_log,
) -> dict[str, Any]:
    """Обновить базу, только если она старше порога (для запуска при старте).

    Сетевой сбой не критичен: возвращается статус 'skipped'/'failed', работа
    продолжается на существующей базе.
    """
    age = bdu_age_days()
    if age is not None and age < max_age_days:
        return {"status": "fresh", "age_days": round(age, 1)}
    log(f"База БДУ устарела (возраст {age if age is None else round(age, 1)} дн.), обновляю…", "info")
    return update_bdu_database(source, log=log)


def _materialize_source(source: str, workdir: Path, log: Logger) -> Path:
    """Вернуть локальный путь к данным: скачать URL или использовать локальный путь."""
    if source.startswith(("http://", "https://")):
        destination = workdir / "download.bin"
        log(f"Скачиваю выгрузку БДУ: {source}", "info")
        _download(source, destination, log)
        return destination
    path = Path(source).expanduser()
    if not path.exists():
        raise ValueError(f"источник не найден: {source}")
    return path


def _download(url: str, destination: Path, log: Logger) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        downloaded = 0
        with open(destination, "wb") as handle:
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > BDU_MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"превышен лимит загрузки {BDU_MAX_DOWNLOAD_BYTES} байт")
                handle.write(chunk)
    log(f"Загружено {downloaded} байт", "info")


def _collect_xml_files(origin: Path, staging: Path, log: Logger) -> list[Path]:
    """Привести источник (файл/архив/каталог) к списку .xml в каталоге staging."""
    collected: list[Path] = []

    def take_xml(path: Path) -> None:
        target = staging / path.name
        if target.suffix.lower() != ".xml":
            target = target.with_suffix(".xml")
        shutil.copy2(path, target)
        collected.append(target)

    if origin.is_dir():
        for item in sorted(origin.rglob("*.xml")):
            take_xml(item)
    elif zipfile.is_zipfile(origin):
        with zipfile.ZipFile(origin) as archive:
            for name in archive.namelist():
                if name.endswith("/") or not name.lower().endswith(".xml"):
                    continue
                safe_name = Path(name).name
                with archive.open(name) as src, open(staging / safe_name, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=1 << 16)
                collected.append(staging / safe_name)
    elif origin.suffix.lower() == ".gz":
        target = staging / (origin.stem if origin.stem.endswith(".xml") else origin.stem + ".xml")
        with gzip.open(origin, "rb") as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst, length=1 << 16)
        collected.append(target)
    elif origin.suffix.lower() == ".xml":
        take_xml(origin)
    else:
        raise ValueError(f"неподдерживаемый формат источника: {origin.name}")

    log(f"Подготовлено XML-файлов: {len(collected)}", "info")
    return collected


def _refresh_xml_dir(xml_files: list[Path], xml_dir: Path, log: Logger) -> None:
    """Заменить содержимое каталога bdu_xml свежими файлами (README сохраняется)."""
    xml_dir.mkdir(parents=True, exist_ok=True)
    for existing in xml_dir.glob("*.xml"):
        existing.unlink(missing_ok=True)
    for item in xml_files:
        shutil.copy2(item, xml_dir / item.name)


# --------------------------------------------------------------------------
# Версии сканеров
# --------------------------------------------------------------------------

def check_scanner_updates(*, log: Logger = _default_log) -> list[dict[str, Any]]:
    """Сверить закреплённые версии сканеров с последними релизами upstream.

    Сами исходники не подтягиваются (политика проекта — фиксированные доверенные
    снапшоты); функция только сообщает, где доступно обновление.
    """
    try:
        manifest = json.loads(SCANNER_SOURCE_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"Не удалось прочитать манифест сканеров: {exc}", "error")
        return []

    results: list[dict[str, Any]] = []
    for scanner in manifest.get("scanners", []):
        key = str(scanner.get("key", ""))
        repository = str(scanner.get("repository", ""))
        current = str(scanner.get("version", ""))
        latest = _latest_github_release(repository, log) if "github.com" in repository else ""
        update_available = bool(latest) and _normalize_version(latest) != _normalize_version(current)
        results.append({
            "key": key,
            "current": current,
            "latest": latest or "неизвестно",
            "repository": repository,
            "update_available": update_available,
        })
        if update_available:
            log(f"{key}: доступно обновление {current} -> {latest}", "info")
    return results


def _latest_github_release(repository: str, log: Logger) -> str:
    owner_repo = repository.rstrip("/").removeprefix("https://github.com/").removeprefix("http://github.com/")
    if owner_repo.count("/") != 1:
        return ""
    for endpoint in (
        f"https://api.github.com/repos/{owner_repo}/releases/latest",
        f"https://api.github.com/repos/{owner_repo}/tags",
    ):
        try:
            request = urllib.request.Request(
                endpoint,
                headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read(1 << 20).decode("utf-8", "replace"))
        except (urllib.error.URLError, json.JSONDecodeError, ValueError, TimeoutError) as exc:
            log(f"{owner_repo}: не удалось получить релизы ({exc})", "warning")
            continue
        if isinstance(data, dict) and data.get("tag_name"):
            return str(data["tag_name"])
        if isinstance(data, list) and data:
            name = data[0].get("name") if isinstance(data[0], dict) else ""
            if name:
                return str(name)
    return ""


def _normalize_version(value: str) -> str:
    return (value or "").strip().lower().lstrip("v").split("@")[-1]


def update_scanner_manifest(updates: list[dict[str, Any]], *, log: Logger = _default_log) -> int:
    """Обновить поле version в манифесте для сканеров с доступным обновлением.

    Переписывает только метку версии; исходный код не трогается — его обновляют
    вручную, повторным вендорингом доверенного снапшота.
    """
    changed = 0
    try:
        manifest = json.loads(SCANNER_SOURCE_MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"Не удалось прочитать манифест сканеров: {exc}", "error")
        return 0
    by_key = {item["key"]: item for item in updates if item.get("update_available")}
    for scanner in manifest.get("scanners", []):
        info = by_key.get(scanner.get("key"))
        if info:
            scanner["version_available"] = info["latest"]
            changed += 1
    if changed:
        manifest["checked_at"] = time.strftime("%Y-%m-%d")
        SCANNER_SOURCE_MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"Манифест обновлён: отмечено {changed} доступных обновлений.", "info")
    return changed


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Автообновление данных анализатора БДУ.")
    parser.add_argument("--bdu", action="store_true", help="обновить базу БДУ")
    parser.add_argument("--source", default=None, help="URL или локальный путь к выгрузке БДУ")
    parser.add_argument("--max-age", type=int, default=None, help="обновить БДУ только если старше N дней")
    parser.add_argument("--scanners", action="store_true", help="проверить версии сканеров")
    parser.add_argument("--write-manifest", action="store_true", help="отметить доступные версии сканеров в манифесте")
    args = parser.parse_args(argv)

    if not args.bdu and not args.scanners:
        parser.print_help()
        return 2

    if args.bdu:
        if args.max_age is not None:
            result = ensure_bdu_fresh(args.max_age, args.source)
        else:
            result = update_bdu_database(args.source)
        print(json.dumps(result, ensure_ascii=False))

    if args.scanners:
        updates = check_scanner_updates()
        for item in updates:
            flag = "ОБНОВЛЕНИЕ" if item["update_available"] else "актуально"
            print(f"  {item['key']:14} {item['current']:20} -> {item['latest']:20} [{flag}]")
        if args.write_manifest:
            update_scanner_manifest(updates)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
