from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class RawFinding:
    asset_id: str
    asset_name: str
    ipv4: list[str]
    ipv6: list[str]
    fqdn: list[str]
    mac_address: str | None
    os_name: str | None
    tags: list[str]
    last_seen_ms: int
    cve_id: str
    severity: str
    description: str
    evidence: str
    raw_output: str
    source: str  # "aws_inspector" | "azure_defender" | "tenable_vm"


@dataclass
class Credentials:
    cortex_api_key: str
    cortex_auth_id: str
    cortex_fqdn: str


@dataclass
class JobResult:
    job_id: str
    status: str
    assets_count: int
    vulnerabilities_count: int
    error_log: list[str] = field(default_factory=list)
