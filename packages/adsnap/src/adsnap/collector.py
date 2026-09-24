"""Collect a Snapshot: the domain object and every user account. Facts only.

Raises if the domain object cannot be read at all; a failed user query becomes partial coverage.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from adsnap import __version__
from adsnap.derive import DOMAIN_POLICY_FIELDS, derive_domain, derive_user
from adsnap.ldap import DirectoryError, DirectorySource
from adsnap.model import (
    ADObject,
    CollectionError,
    CollectorInfo,
    CoverageLevel,
    DomainInfo,
    ObjectType,
    Snapshot,
    SnapshotMeta,
)

DOMAIN_FILTER = "(objectClass=domainDNS)"
DOMAIN_ATTRIBUTES = ["objectGUID", "objectSid", "name", *DOMAIN_POLICY_FIELDS.values()]
USER_FILTER = "(&(objectCategory=person)(objectClass=user))"
USER_ATTRIBUTES = ["objectGUID", "objectSid", "sAMAccountName", "userAccountControl"]
USER_RAW = ("sAMAccountName", "userAccountControl")  # data minimization: nothing else is stored


def _first(value: Any) -> Any:  # ldap3 may return single values as one-item lists
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def _guid(row: dict[str, Any]) -> str:
    return str(_first(row["objectGUID"])).strip("{}").lower()


def _users(rows: list[dict[str, Any]], errors: list[CollectionError]) -> list[ADObject]:
    users: list[ADObject] = []
    for row in rows:
        sid = _first(row.get("objectSid"))
        name = str(_first(row.get("sAMAccountName")) or row["dn"])
        derived = derive_user(row, sid=str(sid) if sid else None)
        if derived["enabled"] is None:
            errors.append(CollectionError(stage="directory_objects", msg=f"userAccountControl could not be read on {name}"))
        users.append(ADObject(
            object_id=_guid(row), object_type=ObjectType.USER, dn=row["dn"], name=name,
            object_sid=str(sid) if sid else None,
            raw={attribute: _first(row.get(attribute)) for attribute in USER_RAW},
            derived=derived,
        ))
    return users


def collect(
    source: DirectorySource,
    *,
    now: datetime | None = None,
    domain_dns: str = "",
    mode: Literal["standard", "privileged"] = "standard",
) -> Snapshot:
    now = now or datetime.now(UTC)
    base = source.base_dn()
    domain_rows = source.search(base, DOMAIN_FILTER, DOMAIN_ATTRIBUTES, scope="base")
    if not domain_rows:
        raise LookupError(f"domain object {base} not found")
    row = domain_rows[0]
    derived = derive_domain(row)
    errors = [
        CollectionError(stage="directory_objects", msg=f"{attribute} could not be read on the domain object")
        for field, attribute in DOMAIN_POLICY_FIELDS.items()
        if derived[field] is None
    ]
    domain = ADObject(
        object_id=_guid(row),
        object_type=ObjectType.DOMAIN,
        dn=row["dn"],
        name=domain_dns or str(_first(row.get("name"))),
        object_sid=str(_first(row["objectSid"])),
        raw={attribute: _first(row.get(attribute)) for attribute in DOMAIN_POLICY_FIELDS.values()},
        derived=derived,
    )
    try:
        user_rows = source.search(base, USER_FILTER, USER_ATTRIBUTES)
    except DirectoryError as exc:
        user_rows = []
        errors.append(CollectionError(stage="directory_objects", msg=f"user accounts could not be read: {exc}"))
    users = _users(user_rows, errors)
    meta = SnapshotMeta(
        id=f"{now:%Y%m%dT%H%M%SZ}-{domain.name}",
        collected_at=now,
        collector=CollectorInfo(name="adsnap", version=__version__, auth="simple", mode=mode),
        # netbios: first DNS label until the Partitions container is collected
        domain=DomainInfo(object_id=domain.object_id, dn=domain.dn, netbios=domain.name.split(".")[0].upper(), sid=domain.object_sid or ""),
    )
    coverage = CoverageLevel.PARTIAL if errors else CoverageLevel.FULL
    return Snapshot(snapshot=meta, objects=[domain, *users], coverage={"directory_objects": coverage}, errors=errors)
