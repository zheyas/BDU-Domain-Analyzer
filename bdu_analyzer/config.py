# -*- coding: utf-8 -*-

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
STATIC_DIR = BASE_DIR / "static"
WORDLIST_DIR = BASE_DIR / "wordlists"

BDU_DB_PATH = DATA_DIR / "bdu.db"
BDU_XML_DIR = DATA_DIR / "bdu_xml"
CLASSIFICATIONS_RU_PATH = DATA_DIR / "classifications_ru.json"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5059
REQUEST_TIMEOUT = 8
MAX_HTML_BYTES = 350_000

LEGACY_WAPITI_BIN = Path(
    "/Users/evgenijasakov/Wapiti_Gui/Сканер + БДУ/wapiti_scan /.venv/bin/wapiti"
)

EXTERNAL_TIMEOUTS = {
    "nmap": 55,
    "wapiti": 480,
    "wfuzz": 120,
    "whatweb": 90,
    "nikto": 240,
    "sqlmap": 360,
}

SEVERITY_ORDER = {
    "Критический": 5,
    "Высокий": 4,
    "Средний": 3,
    "Низкий": 2,
    "Инфо": 1,
}

SEVERITY_WEIGHT = {
    "Критический": 35,
    "Высокий": 20,
    "Средний": 8,
    "Низкий": 2,
    "Инфо": 0,
}
