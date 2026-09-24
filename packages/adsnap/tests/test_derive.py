from adsnap.derive import UAC_DONT_REQ_PREAUTH, UAC_PASSWD_NOTREQD, derive_domain, derive_user

DOM = "S-1-5-21-1-2-3"


def test_derive_user_flags() -> None:
    d = derive_user({"sAMAccountName": "svc_legacy", "userAccountControl": 512 | UAC_DONT_REQ_PREAUTH | UAC_PASSWD_NOTREQD}, sid=f"{DOM}-1105")
    assert d == {"enabled": True, "is_builtin": False, "passwd_notreqd": True, "asrep_roastable": True}
    assert derive_user({"sAMAccountName": "a", "userAccountControl": [514]}, sid=f"{DOM}-1106")["enabled"] is False


def test_derive_user_builtin_accounts() -> None:
    assert derive_user({"sAMAccountName": "Guest", "userAccountControl": 66082}, sid=f"{DOM}-501")["is_builtin"] is True
    assert derive_user({"sAMAccountName": "krbtgt_12345", "userAccountControl": 514}, sid=f"{DOM}-1200")["is_builtin"] is True
    assert derive_user({"sAMAccountName": "Administrator", "userAccountControl": 66048}, sid=f"{DOM}-500")["is_builtin"] is True


def test_derive_user_without_user_account_control_is_unknown_not_false() -> None:
    assert derive_user({"sAMAccountName": "x"}, sid=None) == {
        "enabled": None, "is_builtin": False, "passwd_notreqd": None, "asrep_roastable": None}


def test_derive_domain_reads_policy_attributes() -> None:
    assert derive_domain({"minPwdLength": 6, "pwdProperties": 0, "lockoutThreshold": 0}) == {
        "min_password_length": 6, "password_complexity": False, "lockout_threshold": 0}
    assert derive_domain({"minPwdLength": [14], "pwdProperties": [1], "lockoutThreshold": [5]}) == {
        "min_password_length": 14, "password_complexity": True, "lockout_threshold": 5}


def test_complexity_is_bit_0x1_only() -> None:
    assert derive_domain({"minPwdLength": 7, "pwdProperties": 0x10, "lockoutThreshold": 0})["password_complexity"] is False
    assert derive_domain({"minPwdLength": 7, "pwdProperties": 0x11, "lockoutThreshold": 0})["password_complexity"] is True


def test_missing_or_empty_attributes_derive_to_none_not_zero() -> None:
    expected = {"min_password_length": None, "password_complexity": None, "lockout_threshold": None}
    assert derive_domain({}) == expected
    assert derive_domain({"minPwdLength": [], "pwdProperties": [], "lockoutThreshold": []}) == expected
    assert derive_domain({"minPwdLength": None, "pwdProperties": "", "lockoutThreshold": None}) == expected
