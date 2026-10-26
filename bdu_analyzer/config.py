# -*- coding: utf-8 -*-

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
STATIC_DIR = BASE_DIR / "static"
WORDLIST_DIR = BASE_DIR / "wordlists"
RULES_DIR = BASE_DIR / "rules"
TOOLS_VENV_DIR = BASE_DIR / ".bdu-tools"
NATIVE_TOOLS_DIR = TOOLS_VENV_DIR / "native"
THIRD_PARTY_DIR = BASE_DIR / "third_party"
SCANNER_SOURCE_DIRS = {
    "nmap": THIRD_PARTY_DIR / "nmap",
    "wapiti": THIRD_PARTY_DIR / "wapiti",
    "wfuzz": THIRD_PARTY_DIR / "wfuzz",
    "whatweb": THIRD_PARTY_DIR / "whatweb",
    "nikto": THIRD_PARTY_DIR / "nikto",
    "sqlmap": THIRD_PARTY_DIR / "sqlmap",
    "skipfish": THIRD_PARTY_DIR / "skipfish",
    "legion": THIRD_PARTY_DIR / "legion",
    "theharvester": THIRD_PARTY_DIR / "theharvester",
    "dnsrecon": THIRD_PARTY_DIR / "dnsrecon",
    "knockpy": THIRD_PARTY_DIR / "knockpy",
    "altdns": THIRD_PARTY_DIR / "altdns",
}
WAPITI_SOURCE_DIR = SCANNER_SOURCE_DIRS["wapiti"]
SCANNER_SOURCE_MANIFEST = THIRD_PARTY_DIR / "SCANNERS_SOURCE.json"

BDU_DB_PATH = DATA_DIR / "bdu.db"
BDU_XML_DIR = DATA_DIR / "bdu_xml"
CLASSIFICATIONS_RU_PATH = DATA_DIR / "classifications_ru.json"

# Автообновление базы БДУ. Официальная выгрузка ФСТЭК (zip с export/export.xml).
# Сайт отдаёт данные только с российских IP; значение можно переопределить
# переменной окружения BDU_EXPORT_URL или локальным путём/URL в update_bdu_database().
BDU_EXPORT_URL = "https://bdu.fstec.ru/files/documents/vulxml.zip"
BDU_MAX_DOWNLOAD_BYTES = 400_000_000
BDU_FRESH_MAX_AGE_DAYS = 30

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5059
REQUEST_TIMEOUT = 8
MAX_HTML_BYTES = 350_000

EXTERNAL_TIMEOUTS = {
    "nmap": 180,
    "wapiti": 480,
    "wfuzz": 120,
    "whatweb": 90,
    "nikto": 240,
    "sqlmap": 360,
    "theharvester": 180,
    "dnsrecon": 180,
    "knockpy": 180,
    "altdns": 180,
}

# Верхние предохранители для полного режима. Они заметно больше обычных
# таймаутов, но не дают внешним CLI держать весь web-запрос бесконечно.
FULL_COMPLETION_TIMEOUTS = {
    "nmap": 900,
    "wapiti": 1200,
    "wfuzz": 300,
    "whatweb": 240,
    "nikto": 900,
    "sqlmap": 900,
    "theharvester": 600,
    "dnsrecon": 600,
    "knockpy": 600,
    "altdns": 600,
    "burp_lite": 300,
    "skipfish": 900,
    "legion": 600,
    "openvas": 600,
    "clamscan": 900,
    "yara": 600,
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
