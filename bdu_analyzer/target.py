# -*- coding: utf-8 -*-

import re
from urllib.parse import urlparse, urlunparse


class TargetError(ValueError):
    pass


def normalize_target(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        raise TargetError("Введите адрес сайта или домена.")

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise TargetError("Поддерживаются только HTTP и HTTPS цели.")
    if not parsed.hostname:
        raise TargetError("Не удалось определить домен из адреса.")

    try:
        host = parsed.hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError("Домен содержит некорректные символы.") from exc

    if len(host) > 253 or not re.match(r"^[A-Za-z0-9._:-]+$", host):
        raise TargetError("Домен выглядит некорректно.")

    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme, netloc, path, "", parsed.query, ""))
    return normalized, host


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return cleaned.strip("._")[:120] or "target"


def base_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    netloc = parsed.netloc
    return f"{parsed.scheme}://{netloc}"

