# -*- coding: utf-8 -*-

import re
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .config import BDU_DB_PATH, BDU_XML_DIR
from .models import Finding


OVAL_NS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


class BDUHandler:
    def __init__(self, db_path: Path = BDU_DB_PATH, xml_dir: Path = BDU_XML_DIR):
        self.db_path = Path(db_path)
        self.xml_dir = Path(xml_dir)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.xml_dir.mkdir(parents=True, exist_ok=True)
        self._create_tables()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _create_tables(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    bdu_id TEXT PRIMARY KEY,
                    cve_id TEXT,
                    title TEXT,
                    description TEXT,
                    severity_level TEXT,
                    remediation TEXT,
                    cvss_score REAL,
                    cwe_list TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bdu_cve ON vulnerabilities(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bdu_severity ON vulnerabilities(severity_level)")

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            with_cve = conn.execute(
                "SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities WHERE cve_id IS NOT NULL AND cve_id != ''"
            ).fetchone()[0]
            severity_rows = conn.execute(
                "SELECT severity_level, COUNT(*) AS cnt FROM vulnerabilities GROUP BY severity_level"
            ).fetchall()
        return {
            "total": total,
            "with_cve": with_cve,
            "by_severity": {row["severity_level"] or "Неизвестно": row["cnt"] for row in severity_rows},
            "db_path": str(self.db_path),
        }

    def get_by_cve(self, cve_id: str) -> dict[str, Any] | None:
        if not cve_id:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM vulnerabilities WHERE upper(cve_id) = upper(?) LIMIT 1",
                (cve_id,),
            ).fetchone()
        return dict(row) if row else None

    def search_by_cwe(self, cwe_id: str, limit: int = 3) -> list[dict[str, Any]]:
        if not cwe_id:
            return []
        pattern = f"%{cwe_id.upper()}%"
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT bdu_id, cve_id, title, severity_level, cvss_score, cwe_list
                FROM vulnerabilities
                WHERE upper(cwe_list) LIKE ?
                ORDER BY cvss_score DESC
                LIMIT ?
                """,
                (pattern, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def enrich(self, finding: Finding) -> Finding:
        cves = set(finding.cve)
        for text in (finding.title, finding.description, finding.evidence):
            cves.update(extract_cves(text))
        finding.cve = sorted(cves)

        matches: list[dict[str, Any]] = []
        for cve in finding.cve:
            record = self.get_by_cve(cve)
            if record:
                matches.append(record)
        finding.bdu_matches = matches

        context: list[dict[str, Any]] = []
        for cwe in finding.cwe[:2]:
            context.extend(self.search_by_cwe(cwe, limit=2))
        finding.bdu_context = context[:4]
        return finding

    def import_all_xml(self) -> int:
        total = 0
        for xml_file in sorted(self.xml_dir.glob("*.xml")):
            total += self.import_from_xml(xml_file)
        return total

    def import_from_xml(self, xml_file: Path) -> int:
        imported = 0
        tree = ET.parse(xml_file)
        root = tree.getroot()
        definitions = root.find(f".//{OVAL_NS}definitions")
        if definitions is None:
            return 0

        with self._connect() as conn:
            for definition in definitions.findall(f"{OVAL_NS}definition"):
                if definition.get("class") != "vulnerability":
                    continue
                row = self._parse_definition(definition)
                if not row:
                    continue
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities
                    (bdu_id, cve_id, title, description, severity_level, remediation, cvss_score, cwe_list)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["bdu_id"],
                        row["cve_id"],
                        row["title"],
                        row["description"],
                        row["severity_level"],
                        row["remediation"],
                        row["cvss_score"],
                        row["cwe_list"],
                    ),
                )
                imported += 1
            conn.commit()
        return imported

    def _parse_definition(self, definition: ET.Element) -> dict[str, Any] | None:
        metadata = definition.find(f"{OVAL_NS}metadata")
        if metadata is None:
            return None

        title = _text(metadata.find(f"{OVAL_NS}title"))
        description = _text(metadata.find(f"{OVAL_NS}description"))
        cve_id = ""
        bdu_id = ""

        for ref in metadata.findall(f"{OVAL_NS}reference"):
            source = (ref.get("source") or "").upper()
            ref_id = ref.get("ref_id") or ""
            if source == "CVE":
                cve_id = ref_id
            elif source == "FSTEC":
                bdu_id = ref_id

        if not bdu_id:
            match = re.search(r"(BDU:\d+)", definition.get("id", ""))
            bdu_id = match.group(1) if match else definition.get("id", "")

        bdu_block = metadata.find(f"{OVAL_NS}bdu")
        severity = "Неизвестно"
        remediation = ""
        cvss_score = 0.0
        cwe_list: list[str] = []

        if bdu_block is not None:
            severity = _text(bdu_block.find(f"{OVAL_NS}severity")) or severity
            remediation = _text(bdu_block.find(f"{OVAL_NS}remediation"))
            cwe_list = [_text(item) for item in bdu_block.findall(f"{OVAL_NS}cwe") if _text(item)]
            cvss_score = parse_cvss_vector(_text(bdu_block.find(f"{OVAL_NS}cvssv20")))

        if not title or not bdu_id:
            return None
        if not remediation:
            remediation = "Обновите затронутое ПО до актуальной версии и примените рекомендации производителя."

        return {
            "bdu_id": bdu_id,
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "severity_level": severity,
            "remediation": remediation,
            "cvss_score": cvss_score,
            "cwe_list": ", ".join(cwe_list),
        }


def extract_cves(text: str | None) -> list[str]:
    if not text:
        return []
    return sorted({match.upper() for match in CVE_RE.findall(text)})


def parse_cvss_vector(vector: str) -> float:
    if not vector:
        return 0.0
    if "AV:N" in vector and "AC:L" in vector and "C:C" in vector and "I:C" in vector and "A:C" in vector:
        return 10.0
    if "C:C" in vector and "I:C" in vector:
        return 9.0
    if "C:C" in vector:
        return 7.5
    if "C:P" in vector and "I:P" in vector and "A:P" in vector:
        return 7.0
    if "C:P" in vector and "I:P" in vector:
        return 6.0
    if "C:P" in vector:
        return 5.0
    return 5.0


def _text(element: ET.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""

