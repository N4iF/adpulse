from adrules.catalog import RuleContext, load_catalog, run_rule
from adrules.finding import CheckResult, Status
from adsnap.model import ADObject, CoverageLevel
from adsnap.testing import make_snapshot, make_user


def _run(rule_id: str, *users: ADObject, coverage: dict[str, CoverageLevel] | None = None) -> CheckResult:
    rule = next(r for r in load_catalog() if r.meta.id == rule_id)
    return run_rule(rule, make_snapshot(*users, coverage=coverage), RuleContext(mode="standard"))


def test_acc_01_flags_enabled_accounts_that_may_have_an_empty_password() -> None:
    r = _run(
        "ACC-01",
        make_user("temp.intern", rid=1105, passwd_notreqd=True),
        make_user("Guest", rid=501, enabled=False, passwd_notreqd=True),  # built-in, disabled by default
        make_user("hr.noura", rid=1106),
    )
    assert r.status is Status.FAIL
    assert [f.affected_name for f in r.findings] == ["temp.intern"]
    assert r.findings[0].evidence == {
        "account": "temp.intern", "setting": "userAccountControl",
        "current": "password not required (PASSWD_NOTREQD, 0x20)", "expected": "flag cleared, strong password set"}


def test_acc_01_flags_an_enabled_guest_too() -> None:
    r = _run("ACC-01", make_user("Guest", rid=501, enabled=True, passwd_notreqd=True))
    assert [f.affected_name for f in r.findings] == ["Guest"]


def test_krb_02_flags_enabled_accounts_without_preauthentication() -> None:
    r = _run(
        "KRB-02",
        make_user("svc_legacy", rid=1110, asrep_roastable=True),
        make_user("old.svc", rid=1111, enabled=False, asrep_roastable=True),
        make_user("it.fahad", rid=1112),
    )
    assert r.status is Status.FAIL and [f.affected_name for f in r.findings] == ["svc_legacy"]
    assert r.findings[0].evidence["expected"] == "Kerberos pre-authentication required"


def test_fix_commands_name_the_account() -> None:
    acc = _run("ACC-01", make_user("temp.intern", rid=1105, passwd_notreqd=True)).findings[0].remediation
    krb = _run("KRB-02", make_user("svc_legacy", rid=1110, asrep_roastable=True)).findings[0].remediation
    for text in (acc.en, acc.ar):
        assert "Set-ADAccountPassword 'temp.intern' -Reset; Set-ADUser 'temp.intern' -PasswordNotRequired $false" in text
    for text in (krb.en, krb.ar):
        assert "Set-ADAccountControl 'svc_legacy' -DoesNotRequirePreAuth $false" in text
    assert "<account>" not in acc.en + acc.ar + krb.en + krb.ar


def test_an_account_name_cannot_break_out_of_the_fix_command() -> None:
    # A sAMAccountName may hold $, ( ) and quotes; pasted unquoted, "$(...)" would run in PowerShell.
    fix = _run("KRB-02", make_user("a'b’$(calc)", rid=1400, asrep_roastable=True)).findings[0].remediation.en
    assert "Set-ADAccountControl 'a''b’’$(calc)' -DoesNotRequirePreAuth $false" in fix


def test_healthy_accounts_pass() -> None:
    users = (make_user("it.fahad", rid=1112), make_user("Administrator", rid=500))
    assert _run("ACC-01", *users).status is Status.PASS
    assert _run("KRB-02", *users).status is Status.PASS


def test_findings_are_sorted_by_account_name() -> None:
    r = _run("KRB-02", make_user("zeta", rid=1201, asrep_roastable=True), make_user("Alpha", rid=1202, asrep_roastable=True))
    assert [f.affected_name for f in r.findings] == ["Alpha", "zeta"]


def test_no_user_accounts_is_not_assessed_never_pass() -> None:
    for rule_id in ("ACC-01", "KRB-02"):
        r = _run(rule_id)  # a domain-only snapshot, e.g. from the MVP-1 collector
        assert r.status is Status.NOT_ASSESSED and r.reason == "no user accounts were collected"


def test_unreadable_flags_are_skipped_and_all_unreadable_is_not_assessed() -> None:
    unknown = make_user("x", rid=1300, enabled=None, passwd_notreqd=None, asrep_roastable=None)
    r = _run("ACC-01", unknown, make_user("temp.intern", rid=1105, passwd_notreqd=True))
    assert [f.affected_name for f in r.findings] == ["temp.intern"]
    assert _run("ACC-01", unknown).status is Status.NOT_ASSESSED


def test_rules_map_to_ecc_and_attack() -> None:
    meta = {r.meta.id: r.meta for r in load_catalog()}
    assert meta["ACC-01"].control_mappings["nca_ecc_2_2024"] == ["2-2-3-1"] and meta["ACC-01"].attack_techniques == ["T1078.002"]
    assert meta["KRB-02"].control_mappings["nca_ecc_2_2024"] == ["2-2-3-4"] and meta["KRB-02"].attack_techniques == ["T1558.004"]
    assert meta["ACC-01"].matches_pingcastle_rule == "S-PwdNotRequired" and meta["KRB-02"].matches_pingcastle_rule == "S-NoPreAuth"
