"""Collect a Snapshot: the domain object, every user account and every computer account. Facts only.

Raises if the domain object cannot be read at all; a failed user or computer query becomes partial coverage.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from adsnap import __version__
from adsnap.derive import (
    DOMAIN_POLICY_FIELDS,
    TEXT_ATTRIBUTES,
    derive_computer,
    derive_domain,
    derive_user,
)
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
USER_ATTRIBUTES = ["objectGUID", "objectSid", "sAMAccountName", "userAccountControl", "servicePrincipalName", *TEXT_ATTRIBUTES]
USER_RAW = ("sAMAccountName", "userAccountControl")  # plus the SPNs; free text is read for ACC-04, never stored
COMPUTER_FILTER = "(objectCategory=computer)"
COMPUTER_ATTRIBUTES = ["objectGUID", "objectSid", "sAMAccountName", "userAccountControl", "primaryGroupID"]
COMPUTER_RAW = ("sAMAccountName", "userAccountControl", "primaryGroupID")


def _first(value: Any) -> Any:  # ldap3 may return single values as one-item lists
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def _guid(row: dict[str, Any]) -> str:
    return str(_first(row["objectGUID"])).strip("{}").lower()


def _search(source: DirectorySource, base: str, ldap_filter: str, attributes: list[str], what: str,
            errors: list[CollectionError]) -> list[dict[str, Any]]:
    try:
        return source.search(base, ldap_filter, attributes)
    except DirectoryError as exc:
        errors.append(CollectionError(stage="directory_objects", msg=f"{what} could not be read: {exc}"))
        return []


def _account(row: dict[str, Any], object_type: ObjectType, raw: dict[str, Any], derived: dict[str, Any]) -> ADObject:
    sid = _first(row.get("objectSid"))
    return ADObject(
        object_id=_guid(row), object_type=object_type, dn=row["dn"], name=str(_first(row.get("sAMAccountName")) or row["dn"]),
        object_sid=str(sid) if sid else None, raw=raw, derived=derived,
    )


def _users(rows: list[dict[str, Any]], errors: list[CollectionError]) -> list[ADObject]:
    users: list[ADObject] = []
    for row in rows:
        sid = _first(row.get("objectSid"))
        derived = derive_user(row, sid=str(sid) if sid else None)
        raw = {attribute: _first(row.get(attribute)) for attribute in USER_RAW} | {"servicePrincipalName": derived["spns"]}
        user = _account(row, ObjectType.USER, raw, derived)
        if derived["enabled"] is None:
            errors.append(CollectionError(stage="directory_objects", msg=f"userAccountControl could not be read on {user.name}"))
        users.append(user)
    return users


def _computers(rows: list[dict[str, Any]], errors: list[CollectionError]) -> list[ADObject]:
    computers: list[ADObject] = []
    for row in rows:
        derived = derive_computer(row)
        computer = _account(row, ObjectType.COMPUTER, {attribute: _first(row.get(attribute)) for attribute in COMPUTER_RAW}, derived)
        if None in derived.values():
            errors.append(CollectionError(
                stage="directory_objects", msg=f"userAccountControl or primaryGroupID could not be read on {computer.name}"))
        computers.append(computer)
    return computers


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
    users = _users(_search(source, base, USER_FILTER, USER_ATTRIBUTES, "user accounts", errors), errors)
    computers = _computers(_search(source, base, COMPUTER_FILTER, COMPUTER_ATTRIBUTES, "computer accounts", errors), errors)
    meta = SnapshotMeta(
        id=f"{now:%Y%m%dT%H%M%SZ}-{domain.name}",
        collected_at=now,
        collector=CollectorInfo(name="adsnap", version=__version__, auth="simple", mode=mode),
        # netbios: first DNS label until the Partitions container is collected
        domain=DomainInfo(object_id=domain.object_id, dn=domain.dn, netbios=domain.name.split(".")[0].upper(), sid=domain.object_sid or ""),
    )
    coverage = CoverageLevel.PARTIAL if errors else CoverageLevel.FULL
    return Snapshot(snapshot=meta, objects=[domain, *users, *computers], coverage={"directory_objects": coverage}, errors=errors)
