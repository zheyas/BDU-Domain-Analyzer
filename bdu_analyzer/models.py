# -*- coding: utf-8 -*-

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    scanner: str
    description: str
    evidence: str = ""
    remediation: str = ""
    url: str = ""
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    confidence: str = "Средняя"
    bdu_matches: list[dict[str, Any]] = field(default_factory=list)
    bdu_context: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolStatus:
    name: str
    key: str
    available: bool
    path: str = ""
    mode: str = "optional"
    note: str = ""
    selected: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanContext:
    original_target: str
    target_url: str
    host: str
    selected_tools: set[str] = field(default_factory=set)
    active_mode: bool = False
    injection_profile: bool = False
    auth_cookie: str = ""
    auth_header: str = ""
    raw_request: str = ""
    scan_id: str = ""


@dataclass
class ScanReport:
    scan_id: str
    target_url: str
    host: str
    generated_at: str
    duration_seconds: float
    findings: list[Finding]
    assets: dict[str, Any]
    tool_statuses: list[ToolStatus]
    bdu_stats: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        data["tool_statuses"] = [item.to_dict() for item in self.tool_statuses]
        return data
