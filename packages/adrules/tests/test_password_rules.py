from typing import Any

import pytest

from adrules.catalog import RuleContext, load_catalog, run_rule
from adrules.finding import CheckResult, Status
from adsnap.testing import make_domain, make_snapshot


def run(rule_id: str, **domain: Any) -> CheckResult:
    rule = next(r for r in load_catalog() if r.meta.id == rule_id)
    return run_rule(rule, make_snapshot(make_domain(**domain)), RuleContext(mode="standard"))


def test_pwd_01_min_length() -> None:
    r = run("PWD-01", min_password_length=6)
    assert r.status is Status.FAIL
    assert r.findings[0].evidence == {"setting": "minPwdLength", "current": 6, "expected": ">= 12"}
    assert run("PWD-01", min_password_length=7).status is Status.FAIL  # the Windows default
    assert run("PWD-01", min_password_length=12).status is Status.PASS
    assert run("PWD-01", min_password_length=14).status is Status.PASS


def test_pwd_02_complexity() -> None:
    r = run("PWD-02", password_complexity=False)
    assert r.status is Status.FAIL
    assert r.findings[0].evidence == {"setting": "pwdProperties (complexity)", "current": "off", "expected": "on"}
    assert run("PWD-02", password_complexity=True).status is Status.PASS


def test_pwd_04_lockout() -> None:
    assert run("PWD-04", lockout_threshold=0).findings[0].evidence == {"setting": "lockoutThreshold", "current": 0, "expected": "1-10"}
    assert run("PWD-04", lockout_threshold=50).status is Status.FAIL
    assert run("PWD-04", lockout_threshold=5).status is Status.PASS
    assert run("PWD-04", lockout_threshold=10).status is Status.PASS


@pytest.mark.parametrize(("rule_id", "field"), [
    ("PWD-01", "min_password_length"), ("PWD-02", "password_complexity"), ("PWD-04", "lockout_threshold"),
])
def test_missing_value_is_not_assessed_never_fail_or_pass(rule_id: str, field: str) -> None:
    r = run(rule_id, **{field: None})
    assert r.status is Status.NOT_ASSESSED and r.findings == [] and r.reason


def test_remediation_is_one_sentence_plus_the_gpo_path_in_both_languages() -> None:
    for r in load_catalog():
        if not r.meta.id.startswith("PWD"):
            continue
        for text in (r.meta.remediation.en, r.meta.remediation.ar):
            first, path = text.split("\n")
            assert "Default Domain Policy" in first and "gpupdate /force" in first
            assert "Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > " in path


def test_fresh_windows_domain_fails_pwd_01_and_pwd_04_only() -> None:
    snap = make_snapshot(make_domain(min_password_length=7, password_complexity=True, lockout_threshold=0))
    results = {r.meta.id: run_rule(r, snap, RuleContext(mode="standard")).status for r in load_catalog() if r.meta.id.startswith("PWD")}
    assert results == {"PWD-01": Status.FAIL, "PWD-02": Status.PASS, "PWD-04": Status.FAIL}


def test_weak_domain_fails_all_three() -> None:
    snap = make_snapshot(make_domain(min_password_length=6, password_complexity=False, lockout_threshold=0))
    results = [run_rule(r, snap, RuleContext(mode="standard")) for r in load_catalog() if r.meta.id.startswith("PWD")]
    assert [x.status for x in results] == [Status.FAIL, Status.FAIL, Status.FAIL]
