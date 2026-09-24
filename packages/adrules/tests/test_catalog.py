from typing import Any

import pytest

from adrules.catalog import (
    NotAssessed,
    Rule,
    RuleContext,
    RuleMeta,
    finding,
    load_catalog,
    run_all,
    run_rule,
)
from adrules.finding import Finding, Localized, Severity, Status
from adsnap.model import CoverageLevel, Snapshot
from adsnap.testing import make_snapshot


def _meta(**over: Any) -> RuleMeta:
    base: dict[str, Any] = dict(
        id="TEST-01", category="test", severity=Severity.HIGH, requires_coverage=["directory_objects"],
        title=Localized(en="Test", ar="اختبار"), why_it_matters=Localized(en="w", ar="و"),
        remediation=Localized(en="r", ar="ر"), evidence_source="test", control_mappings={"nca_ecc_2_2024": ["2-2-3-1"]},
    )
    base.update(over)
    return RuleMeta(**base)


def _always_fails(meta: RuleMeta) -> Rule:
    def evaluate(snap: Snapshot, m: RuleMeta, ctx: RuleContext) -> list[Finding]:
        return [finding(m, snap.domain(), {"setting": "x", "current": 1, "expected": 2})]

    return Rule(meta=meta, evaluate=evaluate)


def _ctx() -> RuleContext:
    return RuleContext(mode="standard")


def test_fail_wraps_findings_with_metadata() -> None:
    r = run_rule(_always_fails(_meta()), make_snapshot(), _ctx())
    assert r.status is Status.FAIL
    assert r.findings[0].title.ar == "اختبار"
    assert r.findings[0].control_mappings == {"nca_ecc_2_2024": ["2-2-3-1"]}


def test_pass_when_no_findings() -> None:
    rule = Rule(meta=_meta(), evaluate=lambda snap, m, ctx: [])
    assert run_rule(rule, make_snapshot(), _ctx()).status is Status.PASS


def test_missing_coverage_is_not_assessed_never_pass() -> None:
    snap = make_snapshot(coverage={"directory_objects": CoverageLevel.NONE})
    r = run_rule(_always_fails(_meta()), snap, _ctx())
    assert r.status is Status.NOT_ASSESSED and r.findings == [] and "directory_objects" in (r.reason or "")


def test_partial_coverage_lowers_confidence() -> None:
    snap = make_snapshot(coverage={"directory_objects": CoverageLevel.PARTIAL})
    r = run_rule(_always_fails(_meta()), snap, _ctx())
    assert r.confidence == "medium" and r.findings[0].confidence == "medium"


def test_rule_without_its_data_is_not_assessed() -> None:
    def evaluate(snap: Snapshot, m: RuleMeta, ctx: RuleContext) -> list[Finding]:
        raise NotAssessed("minPwdLength was not collected")

    r = run_rule(Rule(meta=_meta(), evaluate=evaluate), make_snapshot(), _ctx())
    assert r.status is Status.NOT_ASSESSED and r.findings == [] and r.reason == "minPwdLength was not collected"


def test_privileged_rule_in_standard_mode_needs_elevated() -> None:
    rule = _always_fails(_meta(privilege_required="privileged"))
    assert run_rule(rule, make_snapshot(), _ctx()).status is Status.NEEDS_ELEVATED
    assert run_rule(rule, make_snapshot(), RuleContext(mode="privileged")).status is Status.FAIL


def test_run_all_uses_the_snapshot_mode() -> None:
    rule = _always_fails(_meta(privilege_required="privileged"))
    assert run_all(make_snapshot(), [rule])[0].status is Status.NEEDS_ELEVATED
    assert run_all(make_snapshot(mode="privileged"), [rule])[0].status is Status.FAIL


def test_unknown_coverage_key_rejected() -> None:
    with pytest.raises(ValueError):
        _meta(requires_coverage=["sessions"])


def test_catalog_rules_have_bilingual_texts_and_ecc_mapping() -> None:
    rules = load_catalog()
    assert [r.meta.id for r in rules] == ["PWD-01", "PWD-02", "PWD-04"]
    for r in rules:
        assert r.meta.title.ar and r.meta.why_it_matters.ar and r.meta.remediation.ar
        assert r.meta.control_mappings["nca_ecc_2_2024"] == ["2-2-3-1"]
        assert r.meta.privilege_required == "standard"
