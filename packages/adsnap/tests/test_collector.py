from datetime import UTC, datetime
from typing import Any

import pytest

from adsnap.collector import DOMAIN_FILTER, USER_FILTER, collect
from adsnap.ldap import DirectoryError, Scope, entries_to_rows
from adsnap.model import CoverageLevel, ObjectType

NOW = datetime(2026, 10, 1, tzinfo=UTC)
BASE = "DC=corp,DC=local"
DOMAIN_ROW: dict[str, Any] = {
    "dn": BASE, "objectGUID": "{AB12CD34-0000-0000-0000-000000000001}",
    "objectSid": "S-1-5-21-1-2-3", "name": "corp", "minPwdLength": 6, "pwdProperties": 0, "lockoutThreshold": 0,
}
USER_ROWS: list[dict[str, Any]] = [
    {"dn": f"CN=temp.intern,OU=Staff,OU=Lab,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000A001}",
     "objectSid": "S-1-5-21-1-2-3-1105", "sAMAccountName": "temp.intern", "userAccountControl": 512 | 0x20,
     "description": "must never be stored"},
    {"dn": f"CN=Guest,CN=Users,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000A002}",
     "objectSid": "S-1-5-21-1-2-3-501", "sAMAccountName": "Guest", "userAccountControl": 66082},
]


class FakeSource:
    def __init__(self, domain: list[dict[str, Any]], users: list[dict[str, Any]] | Exception) -> None:
        self.domain, self.users = domain, users
        self.calls: list[tuple[str, str, str]] = []

    def base_dn(self) -> str:
        return BASE

    def search(self, base: str, ldap_filter: str, attributes: list[str], scope: Scope = "subtree") -> list[dict[str, Any]]:
        self.calls.append((base, ldap_filter, scope))
        if ldap_filter == DOMAIN_FILTER:
            return [dict(r) for r in self.domain]
        if isinstance(self.users, Exception):
            raise self.users
        return [dict(r) for r in self.users]


def test_collect_builds_domain_and_user_objects() -> None:
    source = FakeSource([DOMAIN_ROW], USER_ROWS)
    snap = collect(source, now=NOW, domain_dns="corp.local")
    d = snap.domain()
    assert d.object_id == "ab12cd34-0000-0000-0000-000000000001"
    assert d.derived == {"min_password_length": 6, "password_complexity": False, "lockout_threshold": 0}
    users = {u.name: u for u in snap.by_type(ObjectType.USER)}
    assert set(users) == {"temp.intern", "Guest"}
    assert users["temp.intern"].derived == {"enabled": True, "is_builtin": False, "passwd_notreqd": True, "asrep_roastable": False}
    assert users["temp.intern"].object_id == "00000000-0000-0000-0000-00000000a001"
    assert users["Guest"].derived["enabled"] is False and users["Guest"].derived["is_builtin"] is True
    assert snap.coverage_of("directory_objects") is CoverageLevel.FULL and snap.errors == []
    assert snap.snapshot.id == "20261001T000000Z-corp.local" and snap.snapshot.collector.auth == "simple"
    assert (BASE, DOMAIN_FILTER, "base") in source.calls and (BASE, USER_FILTER, "subtree") in source.calls


def test_user_accounts_store_only_what_is_needed() -> None:
    snap = collect(FakeSource([DOMAIN_ROW], USER_ROWS), now=NOW, domain_dns="corp.local")
    user = next(u for u in snap.by_type(ObjectType.USER) if u.name == "temp.intern")
    assert set(user.raw) == {"sAMAccountName", "userAccountControl"}
    assert "must never be stored" not in snap.model_dump_json()
    assert set(snap.domain().raw) == {"minPwdLength", "pwdProperties", "lockoutThreshold"}


def test_missing_policy_attribute_is_partial_coverage_with_an_error() -> None:
    row = {k: v for k, v in DOMAIN_ROW.items() if k != "lockoutThreshold"}
    snap = collect(FakeSource([row], USER_ROWS), now=NOW, domain_dns="corp.local")
    assert snap.domain().derived["lockout_threshold"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert "lockoutThreshold" in snap.errors[0].msg


def test_failed_user_query_is_partial_coverage_not_an_abort() -> None:
    snap = collect(FakeSource([DOMAIN_ROW], DirectoryError("search failed")), now=NOW, domain_dns="corp.local")
    assert snap.by_type(ObjectType.USER) == []
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert any("user accounts" in e.msg for e in snap.errors)


def test_user_without_user_account_control_is_recorded_as_an_error() -> None:
    rows = [{k: v for k, v in USER_ROWS[0].items() if k != "userAccountControl"}]
    snap = collect(FakeSource([DOMAIN_ROW], rows), now=NOW, domain_dns="corp.local")
    assert snap.by_type(ObjectType.USER)[0].derived["enabled"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL


def test_missing_domain_object_aborts() -> None:
    with pytest.raises(LookupError):
        collect(FakeSource([], USER_ROWS), now=NOW, domain_dns="corp.local")


def test_ldap3_entries_become_rows_and_referrals_are_skipped() -> None:
    entries = [
        {"type": "searchResEntry", "dn": "CN=a,DC=corp,DC=local", "attributes": {"sAMAccountName": "a", "userAccountControl": 512}},
        {"type": "searchResRef", "uri": ["ldap://DomainDnsZones.corp.local/DC=DomainDnsZones,DC=corp,DC=local"]},
    ]
    assert entries_to_rows(entries) == [{"dn": "CN=a,DC=corp,DC=local", "sAMAccountName": "a", "userAccountControl": 512}]
    assert entries_to_rows(None) == []
