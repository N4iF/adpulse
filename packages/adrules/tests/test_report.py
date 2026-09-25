import re
from datetime import UTC, datetime
from typing import Any

from markupsafe import escape

from adrules.catalog import ps_literal, run_all
from adrules.report import render_report
from adrules.scan import ScanResult, build_scan
from adsnap.model import CoverageLevel
from adsnap.testing import make_computer, make_domain, make_snapshot, make_user

# Tests may not import each other (pytest --import-mode=importlib), so each file keeps its own helper.
WEAK = dict(min_password_length=6, password_complexity=False, lockout_threshold=0)
FIXED = dict(min_password_length=14, password_complexity=True, lockout_threshold=5)
FRESH = dict(min_password_length=7, password_complexity=True, lockout_threshold=0)
DC = make_computer("DC1$", rid=1000, is_dc=True, unconstrained_delegation=True)  # every domain has one


def _scan(domain: dict[str, Any], previous: ScanResult | None = None, day: int = 1,
          coverage: dict[str, CoverageLevel] | None = None, mode: Any = "standard") -> ScanResult:
    snap = make_snapshot(make_domain(**domain), make_user("Administrator", rid=500), DC, collected_at=datetime(2026, 10, day, tzinfo=UTC), coverage=coverage, mode=mode)
    return build_scan(snap, run_all(snap), previous)


def _grc(html: str) -> str:
    match = re.search(r'<details class="grc".*?</details>', html, flags=re.S)
    assert match, "the NCA ECC view must be in its own collapsible section"
    return match.group(0)


def _without_grc(html: str) -> str:
    return html.replace(_grc(html), "")


def test_it_first_view_shows_what_to_fix_before_anything_else() -> None:
    s1 = _scan(FRESH)
    html = render_report(s1, [s1], "en")
    assert '<html lang="en" dir="ltr">' in html and "Standard-user assessment" in html
    assert 'data-tile="to_fix">2<' in html and 'data-tile="fixed">0<' in html and 'data-tile="passed">7<' in html
    main = _without_grc(html)
    assert main.index("What to fix") < main.index("All checks") < main.index("Scan history")
    assert main.index("Minimum password length is too short") < main.index("Accounts never lock")  # high before medium
    for text in ("What we found", "Why it matters", "How to fix", "minPwdLength", "&gt;= 12", "Default Domain Policy"):
        assert text in main
    assert 'data-check="PWD-02" data-status="pass"' in main


def test_ncaecc_view_is_collapsed_by_default_but_printed() -> None:
    s1 = _scan(FRESH)
    html = render_report(s1, [s1], "en")
    grc = _grc(html)
    assert grc.startswith('<details class="grc">')  # closed: no "open" attribute
    assert "governance, risk and audit teams" in grc
    assert 'data-control="2-2-3-1" data-evidence="technical_evidence_fail"' in grc
    assert 'data-control="2-2-3-1"' not in _without_grc(html)
    assert "details.grc::details-content" in html  # the print stylesheet shows the section when printing


def test_limitation_sentence_is_always_visible_and_compliance_is_never_claimed() -> None:
    s1 = _scan(FRESH)
    html = render_report(s1, [s1], "en")
    assert "organizational policy/process compliance is not assessed" in _without_grc(html)
    lowered = html.lower()
    assert lowered.count("complian") == 1 and "compliant" not in lowered


def test_arabic_report_is_rtl_and_shows_what_was_fixed() -> None:
    s1 = _scan(FRESH)
    s2 = _scan(FIXED, previous=s1, day=2)
    html = render_report(s2, [s1, s2], "ar")
    assert '<html lang="ar" dir="rtl">' in html
    assert "الحد الأدنى لطول كلمة المرور قصير جداً" in html
    assert 'data-tile="fixed">2<' in html and 'data-tile="to_fix">0<' in html
    assert "آخر قيمة" in html  # a fixed row shows the last seen value, not the current one
    assert "عالية" in html  # severity is translated
    assert "لا توجد مشكلات" in html


def test_arabic_keeps_latin_runs_and_values_left_to_right() -> None:
    s1 = _scan(FRESH)
    html = render_report(s1, [s1], "ar")
    assert '<bdi dir="ltr">Default Domain Policy</bdi>' in html
    assert '<code dir="ltr">&gt;= 12</code>' in html
    assert '<bdi dir="ltr">&#34;Least Privilege&#34;</bdi>' in html  # quotes keep their place in RTL text
    assert '<bdi dir="ltr">Default Domain Policy</bdi>' not in render_report(s1, [s1], "en")  # only Arabic text is isolated


def test_all_passed_only_when_every_check_passed() -> None:
    fixed = _scan(FIXED)
    assert "All checks passed" in render_report(fixed, [fixed], "en")
    blind = _scan(FIXED, coverage={"directory_objects": CoverageLevel.NONE})
    html = render_report(blind, [blind], "en")
    assert "All checks passed" not in html
    assert 'data-status="not_assessed"' in html and "coverage directory_objects is none" in html


def test_not_checked_is_visible_in_the_tiles_and_reasons_are_translated() -> None:
    blind = _scan(FIXED, coverage={"directory_objects": CoverageLevel.NONE})
    assert 'data-tile="not_assessed">9<' in render_report(blind, [blind], "en")
    ar = render_report(blind, [blind], "ar")
    assert 'data-tile="not_assessed">9<' in ar
    assert "coverage directory_objects is none" not in ar and "لم تُجمع بيانات" in ar
    clean = _scan(FIXED)
    assert 'data-tile="not_assessed"' not in render_report(clean, [clean], "en")


def test_not_rechecked_problem_stays_in_what_to_fix_with_its_last_seen_value() -> None:
    s1 = _scan(WEAK)
    s2 = _scan(WEAK, previous=s1, day=2, coverage={"directory_objects": CoverageLevel.NONE})
    html = render_report(s2, [s1, s2], "en")
    assert 'data-tile="to_fix">3<' in html
    assert "not re-checked in this scan" in html and "Last seen value" in html and "<dt>Current value</dt>" not in html


def test_ecc_control_view_in_both_languages() -> None:
    fresh = _scan(FRESH)
    grc = _grc(render_report(fresh, [fresh], "en"))
    assert 'data-control="2-2-3-5" data-evidence="not_assessed"' in grc
    assert "Single-factor authentication based on username and password." in grc
    assert "Planned checks" in grc and "ACL-01" in grc and "2-2-3-5" in grc
    ar = _grc(render_report(fresh, [fresh], "ar"))
    assert 'data-control="2-2-3-2" data-evidence="not_assessed"' in ar and "فاشل" in ar
    fixed = _scan(FIXED)
    assert 'data-control="2-2-3-1" data-evidence="technical_evidence_pass"' in render_report(fixed, [fixed], "en")


def test_account_findings_name_the_account() -> None:
    snap = make_snapshot(make_domain(**FIXED), make_user("temp.intern", rid=1105, passwd_notreqd=True),
                         collected_at=datetime(2026, 10, 1, tzinfo=UTC))
    scan = build_scan(snap, run_all(snap), None)
    en = render_report(scan, [scan], "en")
    assert "Account can be used with an empty password <span class=\"muted\">· <bdi dir=\"ltr\">temp.intern</bdi></span>" in en
    assert "<dt>Account</dt>" in en
    assert "Set-ADUser &#39;temp.intern&#39; -PasswordNotRequired $false" in en  # ready to paste
    ar = render_report(scan, [scan], "ar")
    assert "<dt>الحساب</dt>" in ar
    assert '<bdi dir="ltr">Set-ADUser &#39;temp.intern&#39; -PasswordNotRequired $false</bdi>' in ar  # the command stays in order


def test_arabic_keeps_odd_but_legal_account_names_in_one_run() -> None:
    # sAMAccountName allows punctuation ps_literal doesn't need to escape: ( ) & ! # % @ ^ ` { } ~ and
    # typographic quotes (doubled by ps_literal). The command's <bdi> run must not fragment on it.
    for name in ("svc(prod)", "a&b!#%@^~{x}", "o’neil"):  # o'neil with a typographic right quote
        snap = make_snapshot(make_domain(**FIXED), make_user(name, rid=1105, passwd_notreqd=True),
                             collected_at=datetime(2026, 10, 1, tzinfo=UTC))
        scan = build_scan(snap, run_all(snap), None)
        ar = render_report(scan, [scan], "ar")
        command = f"Set-ADUser {ps_literal(name)} -PasswordNotRequired $false"
        assert f'<bdi dir="ltr">{escape(command)}</bdi>' in ar, name


def test_arabic_keeps_a_command_or_note_that_ends_in_a_bracket_in_one_run() -> None:
    snap = make_snapshot(make_domain(**FRESH, machine_account_quota=10), make_user("Administrator", rid=500),
                         make_user("svc_sql", rid=1120, spns=["MSSQLSvc/app01.corp.local:1433"], kerberoastable=True),
                         DC, collected_at=datetime(2026, 10, 1, tzinfo=UTC))
    ar = render_report(build_scan(snap, run_all(snap), None), [], "ar")
    assert '<bdi dir="ltr">Set-ADDomain (Get-ADDomain) -Replace @{&#39;ms-DS-MachineAccountQuota&#39;=0}</bdi>' in ar
    assert '<bdi dir="ltr">servicePrincipalName on enabled user accounts (krbtgt excluded)</bdi>' in ar
    assert '(يوصى بـ <bdi dir="ltr">14</bdi>)' in ar  # a bracket opened in Arabic stays outside


def test_arabic_translates_the_reasons_of_checks_that_could_not_run() -> None:
    snap = make_snapshot(make_domain(**FIXED, machine_account_quota=None), collected_at=datetime(2026, 10, 1, tzinfo=UTC))
    ar = render_report(build_scan(snap, run_all(snap), None), [], "ar")
    assert "was not collected" not in ar and "accounts were collected" not in ar
    assert "لم يُقرأ <bdi dir=\"ltr\">ms-DS-MachineAccountQuota</bdi> من كائن المجال" in ar
    assert "لم تُجمع حسابات المستخدمين" in ar and "لم تُجمع حسابات الأجهزة" in ar


def test_mode_label_follows_the_scan() -> None:
    s = _scan(FIXED, mode="privileged")
    assert "Privileged assessment" in render_report(s, [s], "en")


def test_names_are_escaped() -> None:
    s1 = _scan(WEAK).model_copy(update={"domain": "<script>x</script>"})
    assert "<script>x</script>" not in render_report(s1, [s1], "en")
