from datetime import datetime
from uuid import UUID

from typing import Literal

from pydantic import BaseModel, Field


class CVE(BaseModel):
    cve_id: str
    description: str
    cvss: float | None = None
    severity: str


class Port(BaseModel):
    port: int
    protocol: str
    service: str
    product: str | None = None
    version: str | None = None
    cves: list[CVE] = Field(default_factory=list)


class VulnScriptFinding(BaseModel):
    script_id: str
    port: int | None
    output: str
    cve_ids: list[str]
    state: str


class WebFinding(BaseModel):
    template_id: str
    name: str
    severity: str
    description: str | None = None
    matched_at: str
    reference: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    status: Literal['pending', 'scanning', 'done'] = 'pending'
    ports: list[Port] = Field(default_factory=list)
    vuln_findings: list[VulnScriptFinding] = Field(default_factory=list)
    web_findings: list[WebFinding] = Field(default_factory=list)
    score: int | None = None
    grade: str | None = None
    risk_reasons: list[str] = Field(default_factory=list)


class Scan(BaseModel):
    id: UUID
    cidr: str
    status: Literal['pending', 'discovering', 'completed', 'failed']
    created_at: datetime
    hosts: list[Host] = Field(default_factory=list)
    error: str | None = None
    network_score: int | None = None
    network_grade: str | None = None


class ScanSummary(BaseModel):
    id: UUID
    cidr: str
    status: Literal['pending', 'discovering', 'completed', 'failed']
    created_at: datetime
    network_score: int | None = None
    network_grade: str | None = None
    host_count: int


class ScanCreateRequest(BaseModel):
    cidr: str
    authorized: bool