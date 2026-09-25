from datetime import UTC, datetime
from typing import Any

import pytest

from adsnap.collector import COMPUTER_FILTER, DOMAIN_FILTER, USER_FILTER, collect
from adsnap.ldap import DirectoryError, Scope, entries_to_rows
from adsnap.model import CoverageLevel, ObjectType

NOW = datetime(2026, 10, 1, tzinfo=UTC)
BASE = "DC=corp,DC=local"
DOMAIN_ROW: dict[str, Any] = {
    "dn": BASE, "objectGUID": "{AB12CD34-0000-0000-0000-000000000001}",
    "objectSid": "S-1-5-21-1-2-3", "name": "corp", "minPwdLength": 6, "pwdProperties": 0, "lockoutThreshold": 0,
    "ms-DS-MachineAccountQuota": 10,
}
USER_ROWS: list[dict[str, Any]] = [
    {"dn": f"CN=temp.intern,OU=Staff,OU=Lab,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000A001}",
     "objectSid": "S-1-5-21-1-2-3-1105", "sAMAccountName": "temp.intern", "userAccountControl": 512 | 0x20,
     "description": "must never be stored"},
    {"dn": f"CN=Guest,CN=Users,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000A002}",
     "objectSid": "S-1-5-21-1-2-3-501", "sAMAccountName": "Guest", "userAccountControl": 66082},
    {"dn": f"CN=svc_sql,OU=ServiceAccounts,OU=Lab,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000A003}",
     "objectSid": "S-1-5-21-1-2-3-1120", "sAMAccountName": "svc_sql", "userAccountControl": 66048,
     "servicePrincipalName": "MSSQLSvc/app01.corp.local:1433",
     "info": "Temp password given by phone - see ticket 1042", "comment": "secret comment text"},
]
COMPUTER_ROWS: list[dict[str, Any]] = [
    {"dn": f"CN=DC1,OU=Domain Controllers,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000C001}",
     "objectSid": "S-1-5-21-1-2-3-1000", "sAMAccountName": "DC1$", "userAccountControl": 532480, "primaryGroupID": 516},
    {"dn": f"CN=APP01,OU=Servers,OU=Lab,{BASE}", "objectGUID": "{00000000-0000-0000-0000-00000000C002}",
     "objectSid": "S-1-5-21-1-2-3-1150", "sAMAccountName": "APP01$", "userAccountControl": 528384, "primaryGroupID": 515},
]


class FakeSource:
    def __init__(self, domain: list[dict[str, Any]], users: list[dict[str, Any]] | Exception,
                 computers: list[dict[str, Any]] | Exception | None = None) -> None:
        self.domain, self.users = domain, users
        self.computers = COMPUTER_ROWS if computers is None else computers
        self.calls: list[tuple[str, str, str]] = []

    def base_dn(self) -> str:
        return BASE

    def search(self, base: str, ldap_filter: str, attributes: list[str], scope: Scope = "subtree") -> list[dict[str, Any]]:
        self.calls.append((base, ldap_filter, scope))
        rows = {DOMAIN_FILTER: self.domain, USER_FILTER: self.users, COMPUTER_FILTER: self.computers}[ldap_filter]
        if isinstance(rows, Exception):
            raise rows
        return [{k: v for k, v in r.items() if k in ("dn", *attributes)} for r in rows]  # like LDAP: only what was asked


def test_collect_builds_domain_user_and_computer_objects() -> None:
    source = FakeSource([DOMAIN_ROW], USER_ROWS)
    snap = collect(source, now=NOW, domain_dns="corp.local")
    d = snap.domain()
    assert d.object_id == "ab12cd34-0000-0000-0000-000000000001"
    assert d.derived == {"min_password_length": 6, "password_complexity": False, "lockout_threshold": 0, "machine_account_quota": 10}
    users = {u.name: u for u in snap.by_type(ObjectType.USER)}
    assert set(users) == {"temp.intern", "Guest", "svc_sql"}
    assert users["temp.intern"].derived == {
        "enabled": True, "is_builtin": False, "passwd_notreqd": True, "asrep_roastable": False,
        "unconstrained_delegation": False, "spns": [], "kerberoastable": False,
        "password_in_text_indicator": False, "password_in_text_attrs": []}
    assert users["temp.intern"].object_id == "00000000-0000-0000-0000-00000000a001"
    assert users["Guest"].derived["enabled"] is False and users["Guest"].derived["is_builtin"] is True
    svc = users["svc_sql"].derived
    assert svc["spns"] == ["MSSQLSvc/app01.corp.local:1433"] and svc["kerberoastable"] is True
    assert svc["password_in_text_indicator"] is True and svc["password_in_text_attrs"] == ["info"]
    computers = {c.name: c for c in snap.by_type(ObjectType.COMPUTER)}
    assert computers["APP01$"].derived == {"is_dc": False, "unconstrained_delegation": True}
    assert computers["DC1$"].derived == {"is_dc": True, "unconstrained_delegation": True}
    assert computers["APP01$"].object_id == "00000000-0000-0000-0000-00000000c002"
    assert snap.coverage_of("directory_objects") is CoverageLevel.FULL and snap.errors == []
    assert snap.snapshot.id == "20261001T000000Z-corp.local" and snap.snapshot.collector.auth == "simple"
    assert (BASE, DOMAIN_FILTER, "base") in source.calls and (BASE, USER_FILTER, "subtree") in source.calls
    assert (BASE, COMPUTER_FILTER, "subtree") in source.calls


def test_only_what_is_needed_is_stored_and_free_text_never() -> None:
    snap = collect(FakeSource([DOMAIN_ROW], USER_ROWS), now=NOW, domain_dns="corp.local")
    user = next(u for u in snap.by_type(ObjectType.USER) if u.name == "svc_sql")
    assert user.raw == {"sAMAccountName": "svc_sql", "userAccountControl": 66048,
                        "servicePrincipalName": ["MSSQLSvc/app01.corp.local:1433"]}
    dumped = snap.model_dump_json()
    for text in ("must never be stored", "Temp password given by phone", "secret comment text"):
        assert text not in dumped  # description, info and comment are read for ACC-04, never stored
    assert set(snap.domain().raw) == {"minPwdLength", "pwdProperties", "lockoutThreshold", "ms-DS-MachineAccountQuota"}
    app = next(c for c in snap.by_type(ObjectType.COMPUTER) if c.name == "APP01$")
    assert app.raw == {"sAMAccountName": "APP01$", "userAccountControl": 528384, "primaryGroupID": 515}


def test_missing_policy_attribute_is_partial_coverage_with_an_error() -> None:
    row = {k: v for k, v in DOMAIN_ROW.items() if k != "lockoutThreshold"}
    snap = collect(FakeSource([row], USER_ROWS), now=NOW, domain_dns="corp.local")
    assert snap.domain().derived["lockout_threshold"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert "lockoutThreshold" in snap.errors[0].msg


def test_missing_machine_account_quota_is_partial_coverage_with_an_error() -> None:
    row = {k: v for k, v in DOMAIN_ROW.items() if k != "ms-DS-MachineAccountQuota"}
    snap = collect(FakeSource([row], USER_ROWS), now=NOW, domain_dns="corp.local")
    assert snap.domain().derived["machine_account_quota"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert any("ms-DS-MachineAccountQuota" in e.msg for e in snap.errors)


def test_failed_user_query_is_partial_coverage_not_an_abort() -> None:
    snap = collect(FakeSource([DOMAIN_ROW], DirectoryError("search failed")), now=NOW, domain_dns="corp.local")
    assert snap.by_type(ObjectType.USER) == []
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert any("user accounts" in e.msg for e in snap.errors)


def test_failed_computer_query_is_partial_coverage_not_an_abort() -> None:
    snap = collect(FakeSource([DOMAIN_ROW], USER_ROWS, DirectoryError("search failed")), now=NOW, domain_dns="corp.local")
    assert snap.by_type(ObjectType.COMPUTER) == [] and len(snap.by_type(ObjectType.USER)) == 3
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert any("computer accounts" in e.msg for e in snap.errors)


def test_user_without_user_account_control_is_recorded_as_an_error() -> None:
    rows = [{k: v for k, v in USER_ROWS[0].items() if k != "userAccountControl"}]
    snap = collect(FakeSource([DOMAIN_ROW], rows), now=NOW, domain_dns="corp.local")
    assert snap.by_type(ObjectType.USER)[0].derived["enabled"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL


def test_computer_without_its_flags_is_recorded_as_an_error() -> None:
    rows = [{k: v for k, v in COMPUTER_ROWS[1].items() if k != "primaryGroupID"}]
    snap = collect(FakeSource([DOMAIN_ROW], USER_ROWS, rows), now=NOW, domain_dns="corp.local")
    assert snap.by_type(ObjectType.COMPUTER)[0].derived["is_dc"] is None
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
    assert any("APP01$" in e.msg for e in snap.errors)


def test_missing_domain_object_aborts() -> None:
    with pytest.raises(LookupError):
        collect(FakeSource([], USER_ROWS), now=NOW, domain_dns="corp.local")


def test_ldap3_entries_become_rows_and_referrals_are_skipped() -> None:
    entries: list[dict[str, Any]] = [
        {"type": "searchResEntry", "dn": "CN=a,DC=corp,DC=local", "attributes": {"sAMAccountName": "a", "userAccountControl": 512}},
        {"type": "searchResRef", "uri": ["ldap://DomainDnsZones.corp.local/DC=DomainDnsZones,DC=corp,DC=local"]},
    ]
    assert entries_to_rows(entries) == [{"dn": "CN=a,DC=corp,DC=local", "sAMAccountName": "a", "userAccountControl": 512}]
    assert entries_to_rows(None) == []
