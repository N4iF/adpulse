from adrules.catalog import RuleContext, load_catalog, run_rule
from adrules.finding import CheckResult, Severity, Status
from adsnap.model import ADObject, ObjectType
from adsnap.testing import make_computer, make_domain, make_snapshot, make_user

DC = make_computer("DC1$", rid=1000, is_dc=True, unconstrained_delegation=True)


def _run(rule_id: str, *objects: ADObject) -> CheckResult:
    rule = next(r for r in load_catalog() if r.meta.id == rule_id)
    return run_rule(rule, make_snapshot(*objects), RuleContext(mode="standard"))


def test_del_01_flags_accounts_trusted_for_unconstrained_delegation_but_never_a_domain_controller() -> None:
    r = _run(
        "DEL-01",
        DC,
        make_computer("RODC1$", rid=1001, is_dc=True, unconstrained_delegation=True),
        make_computer("APP01$", rid=1150, unconstrained_delegation=True),
        make_computer("SRV01$", rid=1151),
        make_user("svc_x", rid=1160, unconstrained_delegation=True),
        make_user("old.svc", rid=1161, enabled=False, unconstrained_delegation=True),  # can be re-enabled
        make_user("it.fahad", rid=1112),
    )
    assert r.status is Status.FAIL
    assert [f.affected_name for f in r.findings] == ["APP01$", "old.svc", "svc_x"]
    assert r.findings[0].affected_object_type is ObjectType.COMPUTER
    assert r.findings[0].evidence == {
        "account": "APP01$", "setting": "userAccountControl",
        "current": "trusted for unconstrained delegation (TRUSTED_FOR_DELEGATION, 0x80000)",
        "expected": "no unconstrained delegation outside domain controllers"}
    assert "Set-ADAccountControl 'APP01$' -TrustedForDelegation $false" in r.findings[0].remediation.en  # works when pasted


def test_del_01_is_critical_and_passes_on_a_clean_domain() -> None:
    r = _run("DEL-01", DC, make_computer("SRV01$", rid=1151), make_user("it.fahad", rid=1112))
    assert r.status is Status.PASS
    meta = next(x.meta for x in load_catalog() if x.meta.id == "DEL-01")
    assert meta.severity is Severity.CRITICAL and meta.matches_pingcastle_rule == "P-UnconstrainedDelegation"
    assert meta.control_mappings["nca_ecc_2_2024"] == ["2-2-3-4"] and meta.attack_techniques == ["T1187", "T1550.003"]


def test_del_01_passes_only_when_both_users_and_computers_were_read() -> None:
    r = _run("DEL-01", make_user("it.fahad", rid=1112))
    assert r.status is Status.NOT_ASSESSED and r.reason == "no computer accounts were collected"
    assert _run("DEL-01", DC).status is Status.NOT_ASSESSED  # no users
    assert _run("DEL-01", DC, make_computer("SRV01$", rid=1151)).reason == "no user accounts were collected"


def test_del_01_still_reports_what_it_found_when_one_side_is_missing() -> None:
    r = _run("DEL-01", make_user("svc_x", rid=1160, unconstrained_delegation=True))  # computers not collected
    assert r.status is Status.FAIL and [f.affected_name for f in r.findings] == ["svc_x"]


def test_del_05_flags_a_machine_account_quota_above_zero() -> None:
    r = _run("DEL-05", make_domain(machine_account_quota=10))
    assert r.status is Status.FAIL and [f.affected_name for f in r.findings] == ["corp.local"]
    assert r.findings[0].evidence == {"setting": "ms-DS-MachineAccountQuota", "current": 10, "expected": 0}
    assert "Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}" in r.findings[0].remediation.en
    assert _run("DEL-05", make_domain(machine_account_quota=0)).status is Status.PASS


def test_del_05_missing_quota_is_not_assessed_never_a_pass() -> None:
    r = _run("DEL-05", make_domain(machine_account_quota=None))
    assert r.status is Status.NOT_ASSESSED and r.reason == "ms-DS-MachineAccountQuota was not collected from the domain object"
    meta = next(x.meta for x in load_catalog() if x.meta.id == "DEL-05")
    assert meta.matches_pingcastle_rule == "S-ADRegistration" and meta.control_mappings["nca_ecc_2_2024"] == ["2-2-3-3"]
