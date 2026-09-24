from datetime import UTC, datetime
from typing import Any

from adsnap.collector import collect
from adsnap.model import CoverageLevel, ObjectType

NOW = datetime(2026, 10, 1, tzinfo=UTC)
ROW: dict[str, Any] = {
    "dn": "DC=corp,DC=local", "objectGUID": "{AB12CD34-0000-0000-0000-000000000001}",
    "objectSid": "S-1-5-21-1-2-3", "name": "corp", "minPwdLength": 6, "pwdProperties": 0, "lockoutThreshold": 0,
}


class FakeSource:
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row

    def read_domain(self) -> dict[str, Any]:
        return dict(self.row)


def test_collect_builds_domain_snapshot() -> None:
    snap = collect(FakeSource(ROW), now=NOW, domain_dns="corp.local")
    d = snap.domain()
    assert d.object_type is ObjectType.DOMAIN
    assert d.object_id == "ab12cd34-0000-0000-0000-000000000001"
    assert d.derived == {"min_password_length": 6, "password_complexity": False, "lockout_threshold": 0}
    assert snap.coverage_of("directory_objects") is CoverageLevel.FULL
    assert snap.coverage_of("acls") is CoverageLevel.NONE
    assert snap.errors == []
    assert snap.snapshot.domain.sid == "S-1-5-21-1-2-3"
    assert snap.snapshot.id == "20261001T000000Z-corp.local"
    assert snap.snapshot.collector.auth == "simple"
    assert snap.snapshot.collector.mode == "standard"


def test_missing_policy_attribute_is_partial_coverage_with_an_error() -> None:
    row = {k: v for k, v in ROW.items() if k != "lockoutThreshold"}
    snap = collect(FakeSource(row), now=NOW, domain_dns="corp.local")
    assert snap.domain().derived["lockout_threshold"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert [e.stage for e in snap.errors] == ["directory_objects"]
    assert "lockoutThreshold" in snap.errors[0].msg


def test_snapshot_keeps_no_credentials_or_extra_attributes() -> None:
    snap = collect(FakeSource({**ROW, "description": "secret"}), now=NOW, domain_dns="corp.local")
    assert set(snap.domain().raw) == {"minPwdLength", "pwdProperties", "lockoutThreshold"}
    assert "secret" not in snap.model_dump_json()
