"""Finding is the central domain object; the runner wraps a rule's findings in a CheckResult."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from adsnap.model import ObjectType


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Status(StrEnum):
    FAIL = "fail"
    PASS = "pass"  # noqa: S105 - a check status, not a password
    NOT_ASSESSED = "not_assessed"
    NEEDS_ELEVATED = "needs_elevated"


Confidence = Literal["high", "medium", "low"]


class Localized(BaseModel):
    en: str
    ar: str


class Finding(BaseModel):
    rule_id: str
    category: str
    severity: Severity
    title: Localized
    why_it_matters: Localized
    remediation: Localized
    affected_object: str  # object_id
    affected_object_type: ObjectType
    affected_name: str
    subject_id: str | None = None  # trustee object_id (or SID when unresolved) for ACL checks
    subject_name: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    evidence_source: str
    control_mappings: dict[str, list[str]] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(default_factory=list)
    confidence: Confidence = "high"

    @property
    def key(self) -> tuple[str, str, str | None]:
        return (self.rule_id, self.affected_object, self.subject_id)


class CheckResult(BaseModel):
    rule_id: str
    status: Status
    reason: str | None = None
    confidence: Confidence = "high"
    findings: list[Finding] = Field(default_factory=list)
