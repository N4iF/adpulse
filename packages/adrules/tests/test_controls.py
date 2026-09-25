from datetime import UTC, datetime
from typing import Any

from adrules.catalog import NotAssessed, Rule, RuleContext, RuleMeta, load_catalog, run_all
from adrules.controls import ControlEvidence, ecc_view, load_controls, load_subdomain
from adrules.finding import CheckResult, Finding, Localized, Severity, Status
from adsnap.model import CoverageLevel, Snapshot
from adsnap.testing import make_computer, make_domain, make_snapshot, make_user

FRESH = dict(min_password_length=7, password_complexity=True, lockout_threshold=0)
FIXED = dict(min_password_length=14, password_complexity=True, lockout_threshold=5)
DC = make_computer("DC1$", rid=1000, is_dc=True, unconstrained_delegation=True)  # every domain has one


def _results(domain: dict[str, Any], coverage: dict[str, CoverageLevel] | None = None) -> list[CheckResult]:
    snap = make_snapshot(make_domain(**domain), make_user("Administrator", rid=500), DC, collected_at=datetime(2026, 10, 1, tzinfo=UTC), coverage=coverage)
    return run_all(snap)


def _by_id(view: list[ControlEvidence]) -> dict[str, ControlEvidence]:
    return {c.control_id: c for c in view}


def test_the_five_controls_of_2_2_3_always_appear_in_order_with_official_text() -> None:
    view = ecc_view(_results(FIXED))
    assert [c.control_id for c in view] == ["2-2-3-1", "2-2-3-2", "2-2-3-3", "2-2-3-4", "2-2-3-5"]
    assert view[0].text.en == "Single-factor authentication based on username and password."
    assert all(c.text.en and c.text.ar for c in view)


def test_fresh_domain_is_a_fail_for_2_2_3_1_with_its_checks() -> None:
    c = _by_id(ecc_view(_results(FRESH)))["2-2-3-1"]
    assert c.status == "technical_evidence_fail"
    assert c.failing == ["PWD-01", "PWD-04"]
    assert [(k.rule_id, k.status) for k in c.checks] == [
        ("ACC-01", Status.PASS), ("ACC-04", Status.PASS), ("PWD-01", Status.FAIL), ("PWD-02", Status.PASS), ("PWD-04", Status.FAIL)]


def test_fixed_domain_is_a_pass_for_2_2_3_1() -> None:
    c = _by_id(ecc_view(_results(FIXED)))["2-2-3-1"]
    assert c.status == "technical_evidence_pass" and c.failing == [] and c.reason is None


def test_controls_without_checks_are_not_assessed_with_reason_and_plan() -> None:
    view = _by_id(ecc_view(_results(FIXED)))
    for control_id in ("2-2-3-2", "2-2-3-5"):
        c = view[control_id]
        assert c.status == "not_assessed" and c.checks == [] and c.reason is not None
        assert c.reason.en and c.reason.ar
    assert "multi-factor" in view["2-2-3-2"].reason.en  # type: ignore[union-attr]
    assert view["2-2-3-3"].status == "technical_evidence_pass"  # DEL-05 gives 2-2-3-3 its first evidence
    assert view["2-2-3-3"].planned == ["ACL-01", "ACL-03"]
    assert view["2-2-3-1"].planned == ["GPO-01"]
    assert view["2-2-3-4"].status == "technical_evidence_pass"
    assert view["2-2-3-4"].planned == ["KRB-01", "PRV-04"]
    assert "2-2-3-5" in [c.control_id for c in view.values() if "history" in (c.reason.en if c.reason else "")]


def test_checks_that_could_not_run_are_not_assessed_never_pass() -> None:
    c = _by_id(ecc_view(_results(FIXED, coverage={"directory_objects": CoverageLevel.NONE})))["2-2-3-1"]
    assert c.status == "not_assessed" and c.reason is not None and "could not run" in c.reason.en


def test_partial_pass_says_how_many_checks_could_not_run() -> None:
    results = _results(FIXED)
    results = [CheckResult(rule_id="PWD-02", status=Status.NOT_ASSESSED, reason="pwdProperties was not collected from the domain object") if r.rule_id == "PWD-02" else r for r in results]
    c = _by_id(ecc_view(results))["2-2-3-1"]
    assert c.status == "technical_evidence_pass"
    assert c.reason is not None and "1 of 5" in c.reason.en


def test_a_planned_check_that_exists_is_no_longer_listed_as_planned() -> None:
    meta = RuleMeta(
        id="ACL-01", category="t", severity=Severity.HIGH, requires_coverage=["directory_objects"],
        title=Localized(en="t", ar="ت"), why_it_matters=Localized(en="w", ar="و"), remediation=Localized(en="r", ar="ر"),
        evidence_source="t", control_mappings={"nca_ecc_2_2024": ["2-2-3-3"]},
    )

    def evaluate(snap: Snapshot, m: RuleMeta, ctx: RuleContext) -> list[Finding]:
        return []

    rules = [*load_catalog(), Rule(meta=meta, evaluate=evaluate)]
    snap = make_snapshot(make_domain(**FIXED))
    c = _by_id(ecc_view(run_all(snap, rules), rules))["2-2-3-3"]
    assert c.status == "technical_evidence_pass" and "ACL-01" not in c.planned


def _extra_rule(rule_id: str, controls: list[str], *, not_assessed: bool = False) -> Rule:
    meta = RuleMeta(
        id=rule_id, category="t", severity=Severity.HIGH, requires_coverage=["directory_objects"],
        title=Localized(en="t", ar="ت"), why_it_matters=Localized(en="w", ar="و"), remediation=Localized(en="r", ar="ر"),
        evidence_source="t", control_mappings={"nca_ecc_2_2024": controls},
    )

    def evaluate(snap: Snapshot, m: RuleMeta, ctx: RuleContext) -> list[Finding]:
        if not_assessed:
            raise NotAssessed("not collected")
        return []

    return Rule(meta=meta, evaluate=evaluate)


def test_a_check_listed_twice_for_a_control_counts_once() -> None:
    rules = [*load_catalog(), _extra_rule("DUP-01", ["2-2-3-3", "2-2-3-3"])]
    c = _by_id(ecc_view(run_all(make_snapshot(make_domain(**FIXED)), rules), rules))["2-2-3-3"]
    assert [k.rule_id for k in c.checks] == ["DEL-05", "DUP-01"]


def test_a_mapped_check_without_a_result_counts_as_could_not_run() -> None:
    results = [r for r in _results(FIXED) if r.rule_id != "PWD-04"]
    c = _by_id(ecc_view(results))["2-2-3-1"]
    assert c.status == "technical_evidence_pass" and c.reason is not None and "1 of 5" in c.reason.en


def test_control_specific_reason_wins_when_its_checks_could_not_run() -> None:
    rules = [*load_catalog(), _extra_rule("ACC-10", ["2-2-3-2"], not_assessed=True)]
    c = _by_id(ecc_view(run_all(make_snapshot(make_domain(**FIXED)), rules), rules))["2-2-3-2"]
    assert c.status == "not_assessed" and c.reason is not None and "multi-factor" in c.reason.en


def test_every_rule_maps_only_to_known_controls() -> None:
    known = set(load_controls())
    for rule in load_catalog():
        unknown = set(rule.meta.control_mappings.get("nca_ecc_2_2024", [])) - known
        assert not unknown, f"{rule.meta.id} maps to unknown NCA ECC controls {sorted(unknown)}"


def test_control_texts_file_has_both_languages() -> None:
    controls = load_controls()
    assert set(controls) == {"2-2-3-1", "2-2-3-2", "2-2-3-3", "2-2-3-4", "2-2-3-5"}
    for c in controls.values():
        assert "PENDING" not in c.text.en + c.text.ar  # official texts only
    assert controls["2-2-3-5"].text.ar == "المراجعة الدورية لهويات الدخول والصلاحيات."
    assert controls["2-2-3-1"].text.ar.startswith("التحقق من الهوية أحادي العنصر (Single-factor authentication)")
    assert load_subdomain().title.ar == "إدارة هويات الدخول والصلاحيات"
