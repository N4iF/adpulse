from adsnap.derive import derive_domain


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
