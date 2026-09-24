"""Versioned Active Directory snapshot schema. Collectors produce facts; rules judge."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

COVERAGE_KEYS = (
    "directory_objects",
    "acls",
    "gpo_settings",
    "gpo_files",
    "adcs",
    "ca_registry",
    "dc_os_config",
)


class ObjectType(StrEnum):
    USER = "user"
    COMPUTER = "computer"
    GROUP = "group"
    OU = "ou"
    GPO = "gpo"
    CERT_TEMPLATE = "cert_template"
    CA = "ca"
    TRUST = "trust"
    FGPP = "fgpp"
    DOMAIN = "domain"
    CONTAINER = "container"


class CoverageLevel(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


class Ace(BaseModel):
    kind: Literal["allow", "deny"]
    trustee_sid: str
    trustee_name: str | None = None
    rights: list[str] = Field(default_factory=list)
    rights_mask: int = 0
    object_type_guid: str | None = None
    object_type_name: str | None = None
    inherited: bool = False


class SecurityDescriptor(BaseModel):
    owner_sid: str | None = None
    dacl_protected: bool = False
    aces: list[Ace] = Field(default_factory=list)


class ADObject(BaseModel):
    object_id: str  # objectGUID: every AD object has one
    object_type: ObjectType
    dn: str
    name: str
    object_sid: str | None = None  # GPOs, OUs, templates, trusts have none
    raw: dict[str, Any] = Field(default_factory=dict)
    derived: dict[str, Any] = Field(default_factory=dict)
    security_descriptor: SecurityDescriptor | None = None


class CollectorInfo(BaseModel):
    name: str
    version: str
    auth: str = "simple"  # MVP-1 binds with the UPN over LDAPS (D35)
    mode: Literal["standard", "privileged"] = "standard"


class DomainInfo(BaseModel):
    object_id: str
    dn: str
    netbios: str
    sid: str
    functional_level: str | None = None


class SnapshotMeta(BaseModel):
    id: str
    collected_at: datetime
    collector: CollectorInfo
    domain: DomainInfo


class CollectionError(BaseModel):
    stage: str
    msg: str


class Snapshot(BaseModel):
    schema_version: str = SCHEMA_VERSION
    snapshot: SnapshotMeta
    objects: list[ADObject] = Field(default_factory=list)
    coverage: dict[str, CoverageLevel] = Field(default_factory=dict)
    errors: list[CollectionError] = Field(default_factory=list)

    def by_type(self, object_type: ObjectType) -> list[ADObject]:
        return [o for o in self.objects if o.object_type == object_type]

    def get(self, object_id: str) -> ADObject | None:
        return next((o for o in self.objects if o.object_id == object_id), None)

    def by_sid(self, sid: str) -> ADObject | None:
        return next((o for o in self.objects if o.object_sid == sid), None)

    def domain(self) -> ADObject:
        for o in self.objects:
            if o.object_type == ObjectType.DOMAIN:
                return o
        raise LookupError("snapshot has no domain object")

    def coverage_of(self, key: str) -> CoverageLevel:
        return self.coverage.get(key, CoverageLevel.NONE)
