from datetime import UTC, datetime

import pytest

from adsnap.model import (
    SCHEMA_VERSION,
    Ace,
    ADObject,
    CollectorInfo,
    CoverageLevel,
    DomainInfo,
    ObjectType,
    SecurityDescriptor,
    Snapshot,
    SnapshotMeta,
)


def _meta() -> SnapshotMeta:
    return SnapshotMeta(
        id="2026-10-01T00:00:00Z-corp.local",
        collected_at=datetime(2026, 10, 1, tzinfo=UTC),
        collector=CollectorInfo(name="adsnap", version="0.0.1"),
        domain=DomainInfo(object_id="guid-domain", dn="DC=corp,DC=local", netbios="CORP", sid="S-1-5-21-1-2-3"),
    )


def test_snapshot_lookups_by_type_id_and_sid() -> None:
    domain = ADObject(object_id="guid-domain", object_type=ObjectType.DOMAIN, dn="DC=corp,DC=local", name="corp.local", object_sid="S-1-5-21-1-2-3")
    user = ADObject(object_id="guid-u1", object_type=ObjectType.USER, dn="CN=u1,DC=corp,DC=local", name="u1", object_sid="S-1-5-21-1-2-3-1105")
    gpo = ADObject(object_id="guid-gpo", object_type=ObjectType.GPO, dn="CN={X},CN=Policies,...", name="Lab-Legacy")
    snap = Snapshot(snapshot=_meta(), objects=[domain, user, gpo], coverage={"directory_objects": CoverageLevel.FULL})

    assert snap.schema_version == SCHEMA_VERSION
    assert [o.name for o in snap.by_type(ObjectType.USER)] == ["u1"]
    assert snap.get("guid-gpo") is gpo
    assert snap.get("missing") is None
    assert snap.by_sid("S-1-5-21-1-2-3-1105") is user
    assert gpo.object_sid is None  # GPOs have no SID
    assert snap.domain() is domain
    assert snap.coverage_of("directory_objects") is CoverageLevel.FULL
    assert snap.coverage_of("adcs") is CoverageLevel.NONE  # absent key means not collected


def test_domain_missing_raises() -> None:
    snap = Snapshot(snapshot=_meta(), objects=[])
    with pytest.raises(LookupError):
        snap.domain()


def test_security_descriptor_roundtrip_json() -> None:
    sd = SecurityDescriptor(owner_sid="S-1-5-21-1-2-3-512", dacl_protected=True, aces=[Ace(kind="allow", trustee_sid="S-1-5-21-1-2-3-1106", rights=["GenericWrite"], rights_mask=0x20)])
    obj = ADObject(object_id="g", object_type=ObjectType.USER, dn="CN=g", name="g", security_descriptor=sd)
    again = ADObject.model_validate_json(obj.model_dump_json())
    assert again.security_descriptor is not None
    assert again.security_descriptor.aces[0].rights == ["GenericWrite"]
