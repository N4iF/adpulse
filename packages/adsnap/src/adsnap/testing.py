"""Builders for mini-snapshots in tests. Nothing here comes from a real domain."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from adsnap.model import (
    ADObject,
    CollectorInfo,
    CoverageLevel,
    DomainInfo,
    ObjectType,
    Snapshot,
    SnapshotMeta,
)

DOMAIN_SID = "S-1-5-21-1-2-3"
DOMAIN_DN = "DC=corp,DC=local"
COLLECTED_AT = datetime(2026, 10, 1, tzinfo=UTC)
DEFAULT_COVERAGE: dict[str, CoverageLevel] = {"directory_objects": CoverageLevel.FULL}


def make_domain(**derived: Any) -> ADObject:
    d: dict[str, Any] = {"min_password_length": 14, "password_complexity": True, "lockout_threshold": 5, "machine_account_quota": 0}
    d.update(derived)
    return ADObject(
        object_id="guid-domain",
        object_type=ObjectType.DOMAIN,
        dn=DOMAIN_DN,
        name="corp.local",
        object_sid=DOMAIN_SID,
        derived=d,
    )


def make_user(name: str, *, rid: int, **derived: Any) -> ADObject:
    d: dict[str, Any] = {
        "enabled": True, "is_builtin": rid in (500, 501, 502), "passwd_notreqd": False, "asrep_roastable": False,
        "unconstrained_delegation": False, "spns": [], "kerberoastable": False,
        "password_in_text_indicator": False, "password_in_text_attrs": [],
    }
    d.update(derived)
    return ADObject(
        object_id=f"guid-{name}",
        object_type=ObjectType.USER,
        dn=f"CN={name},{DOMAIN_DN}",
        name=name,
        object_sid=f"{DOMAIN_SID}-{rid}",
        derived=d,
    )


def make_computer(name: str, *, rid: int, **derived: Any) -> ADObject:
    """A computer account named like AD names it (`APP01$`); by default a member, not trusted for delegation."""
    d: dict[str, Any] = {"is_dc": False, "unconstrained_delegation": False}
    d.update(derived)
    return ADObject(
        object_id=f"guid-{name}",
        object_type=ObjectType.COMPUTER,
        dn=f"CN={name.rstrip('$')},CN=Computers,{DOMAIN_DN}",
        name=name,
        object_sid=f"{DOMAIN_SID}-{rid}",
        derived=d,
    )


def make_snapshot(
    *objects: ADObject,
    coverage: dict[str, CoverageLevel] | None = None,
    collected_at: datetime = COLLECTED_AT,
    mode: Literal["standard", "privileged"] = "standard",
) -> Snapshot:
    objs = list(objects)
    if not any(o.object_type is ObjectType.DOMAIN for o in objs):
        objs.insert(0, make_domain())
    cov = dict(DEFAULT_COVERAGE)
    cov.update(coverage or {})
    meta = SnapshotMeta(
        id=f"{collected_at:%Y%m%dT%H%M%SZ}-corp.local",
        collected_at=collected_at,
        collector=CollectorInfo(name="adsnap-test", version="0", mode=mode),
        domain=DomainInfo(object_id="guid-domain", dn=DOMAIN_DN, netbios="CORP", sid=DOMAIN_SID),
    )
    return Snapshot(snapshot=meta, objects=objs, coverage=cov)
