import pytest

from adsnap.derive import (
    UAC_DONT_REQ_PREAUTH,
    UAC_PASSWD_NOTREQD,
    UAC_TRUSTED_FOR_DELEGATION,
    derive_computer,
    derive_domain,
    derive_user,
)

DOM = "S-1-5-21-1-2-3"
NO_EXTRAS = {"unconstrained_delegation": False, "spns": [], "kerberoastable": False,
             "password_in_text_indicator": False, "password_in_text_attrs": []}


def test_derive_user_flags() -> None:
    d = derive_user({"sAMAccountName": "svc_legacy", "userAccountControl": 512 | UAC_DONT_REQ_PREAUTH | UAC_PASSWD_NOTREQD}, sid=f"{DOM}-1105")
    assert d == {"enabled": True, "is_builtin": False, "passwd_notreqd": True, "asrep_roastable": True, **NO_EXTRAS}
    assert derive_user({"sAMAccountName": "a", "userAccountControl": [514]}, sid=f"{DOM}-1106")["enabled"] is False


def test_derive_user_builtin_accounts() -> None:
    assert derive_user({"sAMAccountName": "Guest", "userAccountControl": 66082}, sid=f"{DOM}-501")["is_builtin"] is True
    assert derive_user({"sAMAccountName": "krbtgt_12345", "userAccountControl": 514}, sid=f"{DOM}-1200")["is_builtin"] is True
    assert derive_user({"sAMAccountName": "Administrator", "userAccountControl": 66048}, sid=f"{DOM}-500")["is_builtin"] is True


def test_derive_user_without_user_account_control_is_unknown_not_false() -> None:
    assert derive_user({"sAMAccountName": "x"}, sid=None) == {
        "enabled": None, "is_builtin": False, "passwd_notreqd": None, "asrep_roastable": None,
        **NO_EXTRAS, "unconstrained_delegation": None}


def test_a_user_with_a_service_principal_name_is_kerberoastable_except_krbtgt() -> None:
    d = derive_user({"sAMAccountName": "svc_sql", "userAccountControl": 512,
                     "servicePrincipalName": ["MSSQLSvc/app01.corp.local:1433", "MSSQLSvc/app01.corp.local"]}, sid=f"{DOM}-1120")
    assert d["spns"] == ["MSSQLSvc/app01.corp.local", "MSSQLSvc/app01.corp.local:1433"] and d["kerberoastable"] is True
    one = derive_user({"sAMAccountName": "svc_web", "userAccountControl": 512, "servicePrincipalName": "HTTP/intranet.corp.local"}, sid=f"{DOM}-1121")
    assert one["spns"] == ["HTTP/intranet.corp.local"] and one["kerberoastable"] is True
    krbtgt = derive_user({"sAMAccountName": "krbtgt", "userAccountControl": 514, "servicePrincipalName": "kadmin/changepw"}, sid=f"{DOM}-502")
    assert krbtgt["spns"] == ["kadmin/changepw"] and krbtgt["kerberoastable"] is False
    admin = derive_user({"sAMAccountName": "Administrator", "userAccountControl": 512, "servicePrincipalName": "HTTP/x"}, sid=f"{DOM}-500")
    assert admin["kerberoastable"] is True  # only krbtgt is excluded


def test_unconstrained_delegation_on_a_user() -> None:
    d = derive_user({"sAMAccountName": "svc_x", "userAccountControl": 512 | UAC_TRUSTED_FOR_DELEGATION}, sid=f"{DOM}-1130")
    assert d["unconstrained_delegation"] is True


@pytest.mark.parametrize("text", [
    "Temp password given by phone - see ticket 1042", "Password: Summer2024", "pwd=abc", "PASS: x", "pass = x",
    "password1", "passwd", "passphrase here", "كلمة المرور: 1234", "كلمة مرور مؤقتة", "كلمة السر", "كلمة سر",
    "كلمة  المرور", "كلمة\nسر",  # any spacing between the two words
])
def test_password_words_are_found(text: str) -> None:
    d = derive_user({"sAMAccountName": "a", "userAccountControl": 512, "description": text}, sid=f"{DOM}-1140")
    assert d["password_in_text_indicator"] is True and d["password_in_text_attrs"] == ["description"]


@pytest.mark.parametrize("text", [
    "bypass", "passport", "compass", "passage", "Pass-the-hash notes", "Pass-through auth service", "hall pass",
    "Built-in account for administering the computer/domain", "Key Distribution Center Service Account", "كلمة",
])
def test_ordinary_text_is_not_a_password_mention(text: str) -> None:
    d = derive_user({"sAMAccountName": "a", "userAccountControl": 512, "description": text}, sid=f"{DOM}-1141")
    assert d["password_in_text_indicator"] is False and d["password_in_text_attrs"] == []


def test_every_text_attribute_is_checked_and_named() -> None:
    d = derive_user({"sAMAccountName": "a", "userAccountControl": 512, "description": "Sales",
                     "info": ["pwd: x"], "comment": "password in the safe"}, sid=f"{DOM}-1142")
    assert d["password_in_text_attrs"] == ["info", "comment"]


def test_derive_computer() -> None:
    app = derive_computer({"sAMAccountName": "APP01$", "userAccountControl": 528384, "primaryGroupID": 515})
    assert app == {"is_dc": False, "unconstrained_delegation": True}
    assert derive_computer({"userAccountControl": 532480, "primaryGroupID": [516]}) == {"is_dc": True, "unconstrained_delegation": True}
    assert derive_computer({"userAccountControl": 83890176, "primaryGroupID": 521})["is_dc"] is True  # read-only DC
    assert derive_computer({"userAccountControl": 4096, "primaryGroupID": 515}) == {"is_dc": False, "unconstrained_delegation": False}
    assert derive_computer({}) == {"is_dc": None, "unconstrained_delegation": None}


def test_derive_domain_reads_policy_attributes() -> None:
    assert derive_domain({"minPwdLength": 6, "pwdProperties": 0, "lockoutThreshold": 0, "ms-DS-MachineAccountQuota": 10}) == {
        "min_password_length": 6, "password_complexity": False, "lockout_threshold": 0, "machine_account_quota": 10}
    assert derive_domain({"minPwdLength": [14], "pwdProperties": [1], "lockoutThreshold": [5], "ms-DS-MachineAccountQuota": [0]}) == {
        "min_password_length": 14, "password_complexity": True, "lockout_threshold": 5, "machine_account_quota": 0}


def test_complexity_is_bit_0x1_only() -> None:
    assert derive_domain({"minPwdLength": 7, "pwdProperties": 0x10, "lockoutThreshold": 0})["password_complexity"] is False
    assert derive_domain({"minPwdLength": 7, "pwdProperties": 0x11, "lockoutThreshold": 0})["password_complexity"] is True


def test_missing_or_empty_attributes_derive_to_none_not_zero() -> None:
    expected = {"min_password_length": None, "password_complexity": None, "lockout_threshold": None, "machine_account_quota": None}
    assert derive_domain({}) == expected
    assert derive_domain({"minPwdLength": [], "pwdProperties": [], "lockoutThreshold": [], "ms-DS-MachineAccountQuota": []}) == expected
    assert derive_domain({"minPwdLength": None, "pwdProperties": "", "lockoutThreshold": None}) == expected
