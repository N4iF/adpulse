"""Collect a Snapshot of the domain object. Facts only; raises if the directory cannot be read at all."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from adsnap import __version__
from adsnap.derive import DOMAIN_POLICY_FIELDS, derive_domain
from adsnap.ldap import DomainSource
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


def _first(value: Any) -> Any:  # ldap3 may return single values as one-item lists
    return value[0] if isinstance(value, list) and len(value) == 1 else value


def collect(
    source: DomainSource,
    *,
    now: datetime | None = None,
    domain_dns: str = "",
    mode: Literal["standard", "privileged"] = "standard",
) -> Snapshot:
    now = now or datetime.now(UTC)
    row = source.read_domain()
    derived = derive_domain(row)
    errors = [
        CollectionError(stage="directory_objects", msg=f"{attribute} could not be read on the domain object")
        for field, attribute in DOMAIN_POLICY_FIELDS.items()
        if derived[field] is None
    ]
    domain = ADObject(
        object_id=str(_first(row["objectGUID"])).strip("{}").lower(),
        object_type=ObjectType.DOMAIN,
        dn=row["dn"],
        name=domain_dns or str(_first(row.get("name"))),
        object_sid=str(_first(row["objectSid"])),
        raw={attribute: _first(row.get(attribute)) for attribute in DOMAIN_POLICY_FIELDS.values()},
        derived=derived,
    )
    meta = SnapshotMeta(
        id=f"{now:%Y%m%dT%H%M%SZ}-{domain.name}",
        collected_at=now,
        collector=CollectorInfo(name="adsnap", version=__version__, auth="simple", mode=mode),
        # netbios: first DNS label until the Partitions container is collected (increment 3)
        domain=DomainInfo(object_id=domain.object_id, dn=domain.dn, netbios=domain.name.split(".")[0].upper(), sid=domain.object_sid or ""),
    )
    coverage = CoverageLevel.PARTIAL if errors else CoverageLevel.FULL
    return Snapshot(snapshot=meta, objects=[domain], coverage={"directory_objects": coverage}, errors=errors)
