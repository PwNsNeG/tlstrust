from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


Severity = Literal["info", "low", "medium", "high"]
TrustStatus = Literal["trusted", "untrusted", "unknown"]


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    sni: str


@dataclass(frozen=True)
class CertSummary:
    """
    Parsed fields from an X.509 certificate (DER).
    """
    subject: str
    issuer: str
    serial_number: str
    not_before: str  # ISO-8601 UTC string
    not_after: str   # ISO-8601 UTC string
    san_dns: list[str] = field(default_factory=list)
    is_ca: bool = False
    key_usage: list[str] = field(default_factory=list)
    ext_key_usage: list[str] = field(default_factory=list)
    ski: str | None = None
    aki: str | None = None
    signature_algorithm: str | None = None
    public_key_type: str | None = None


@dataclass(frozen=True)
class Cert:
    """
    Raw certificate + parsed summary.
    """
    sha256: str
    der_b64: str
    summary: CertSummary


@dataclass(frozen=True)
class Finding:
    severity: Severity
    title: str
    evidence: str | None = None
    hint: str | None = None


@dataclass(frozen=True)
class Chain:
    """
    Server-presented chain: leaf first, then intermediates (if provided).
    """
    certs: list[Cert]


@dataclass
class AnalysisResult:
    target: dict[str, Any]
    trust_store: str
    chain: dict[str, Any] | None
    findings: list[dict[str, Any]]
    trust: dict[str, Any] | None
    errors: list[str]

