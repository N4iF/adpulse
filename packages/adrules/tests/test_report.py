import re
from datetime import UTC, datetime
from typing import Any

from adrules.catalog import run_all
from adrules.report import render_report
from adrules.scan import ScanResult, build_scan
from adsnap.model import CoverageLevel
from adsnap.testing import make_domain, make_snapshot

# Tests may not import each other (pytest --import-mode=importlib), so each file keeps its own helper.
WEAK = dict(min_password_length=6, password_complexity=False, lockout_threshold=0)
FIXED = dict(min_password_length=14, password_complexity=True, lockout_threshold=5)
FRESH = dict(min_password_length=7, password_complexity=True, lockout_threshold=0)


def _scan(domain: dict[str, Any], previous: ScanResult | None = None, day: int = 1,
          coverage: dict[str, CoverageLevel] | None = None, mode: Any = "standard") -> ScanResult:
    snap = make_snapshot(make_domain(**domain), collected_at=datetime(2026, 10, day, tzinfo=UTC), coverage=coverage, mode=mode)
    return build_scan(snap, run_all(snap), previous)


def _without_details(html: str) -> str:
    return re.sub(r"<details.*?</details>", "", html, flags=re.S)


def test_english_report_shows_findings_checks_and_counts() -> None:
    s1 = _scan(FRESH)
    html = render_report(s1, [s1], "en")
    assert '<html lang="en" dir="ltr">' in html
    assert "Minimum password length is too short" in html
    assert 'data-tile="checks">3<' in html and 'data-tile="failed">2<' in html and 'data-tile="new">2<' in html
    assert 'data-check="PWD-02" data-status="pass"' in html
    assert "Standard-user assessment" in html


def test_evidence_and_limitation_are_visible_without_opening_anything() -> None:
    s1 = _scan(FRESH)
    visible = _without_details(render_report(s1, [s1], "en"))
    assert "2-2-3-1" in visible and "organizational policy/process compliance is not assessed" in visible
    assert "minPwdLength" in visible and "&gt;= 12" in visible
    assert "Default Domain Policy" in visible  # the remediation


def test_arabic_report_is_rtl_and_shows_resolved() -> None:
    s1 = _scan(FRESH)
    s2 = _scan(FIXED, previous=s1, day=2)
    html = render_report(s2, [s1, s2], "ar")
    assert '<html lang="ar" dir="rtl">' in html
    assert "الحد الأدنى لطول كلمة المرور قصير جداً" in html
    assert 'data-tile="resolved">2<' in html
    assert "آخر قيمة" in html  # a resolved row shows the last seen value, not the current one
    assert "عالية" in html  # severity is translated


def test_arabic_keeps_latin_runs_and_values_left_to_right() -> None:
    s1 = _scan(FRESH)
    html = render_report(s1, [s1], "ar")
    assert '<bdi dir="ltr">Default Domain Policy</bdi>' in html
    assert '<code dir="ltr">&gt;= 12</code>' in html
    assert "2-2-3-5" in html  # the history is labelled as periodic-review evidence
    assert '<bdi dir="ltr">Default Domain Policy</bdi>' not in render_report(s1, [s1], "en")  # only Arabic text is isolated


def test_all_passed_only_when_every_check_passed() -> None:
    fixed = _scan(FIXED)
    assert "All checks passed" in render_report(fixed, [fixed], "en")
    blind = _scan(FIXED, coverage={"directory_objects": CoverageLevel.NONE})
    html = render_report(blind, [blind], "en")
    assert "All checks passed" not in html
    assert 'data-status="not_assessed"' in html and "coverage directory_objects is none" in html
    assert "0 of 3" in html  # coverage line: checks assessed


def test_not_assessed_is_visible_in_the_tiles_and_reasons_are_translated() -> None:
    blind = _scan(FIXED, coverage={"directory_objects": CoverageLevel.NONE})
    assert 'data-tile="not_assessed">3<' in render_report(blind, [blind], "en")
    ar = render_report(blind, [blind], "ar")
    assert 'data-tile="not_assessed">3<' in ar
    assert "coverage directory_objects is none" not in ar and "لم تُجمع بيانات" in ar
    clean = _scan(FIXED)
    assert 'data-tile="not_assessed"' not in render_report(clean, [clean], "en")


def test_not_reassessed_row_shows_last_seen_value() -> None:
    s1 = _scan(WEAK)
    s2 = _scan(WEAK, previous=s1, day=2, coverage={"directory_objects": CoverageLevel.NONE})
    html = render_report(s2, [s1, s2], "en")
    assert "not re-assessed in this scan" in html and "Last seen" in html and "<dt>Current</dt>" not in html


def test_ecc_control_view_in_both_languages() -> None:
    fresh = _scan(FRESH)
    html = render_report(fresh, [fresh], "en")
    assert 'data-control="2-2-3-1" data-evidence="technical_evidence_fail"' in html
    assert 'data-control="2-2-3-5" data-evidence="not_assessed"' in html
    assert "Single-factor authentication based on username and password." in html
    assert "Planned checks" in html and "ACL-01" in html
    ar = render_report(fresh, [fresh], "ar")
    assert 'data-control="2-2-3-2" data-evidence="not_assessed"' in ar and "فاشل" in ar
    assert '<bdi dir="ltr">&#34;Least Privilege&#34;</bdi>' in ar  # quotes keep their place in RTL text
    fixed = _scan(FIXED)
    assert 'data-control="2-2-3-1" data-evidence="technical_evidence_pass"' in render_report(fixed, [fixed], "en")


def test_the_report_never_claims_compliance() -> None:
    fresh = _scan(FRESH)
    html = render_report(fresh, [fresh], "en").lower()
    assert html.count("complian") == 1  # only in the limitation sentence: "... compliance is not assessed."
    assert "compliant" not in html


def test_mode_label_follows_the_scan() -> None:
    s = _scan(FIXED, mode="privileged")
    assert "Privileged assessment" in render_report(s, [s], "en")


def test_names_are_escaped() -> None:
    s1 = _scan(WEAK).model_copy(update={"domain": "<script>x</script>"})
    assert "<script>x</script>" not in render_report(s1, [s1], "en")
