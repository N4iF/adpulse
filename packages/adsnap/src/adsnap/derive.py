"""Raw LDAP attributes -> derived fields (the collector/rules contract in docs/architecture.md).

A value that was not collected derives to None, never to 0 or False, so a rule can report
`not_assessed` instead of inventing a failure (D35). Optional multi-valued attributes (SPNs, free text)
are absent when empty, so their absence means "none".
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

DOMAIN_PASSWORD_COMPLEX = 0x1

UAC_ACCOUNTDISABLE = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000
BUILTIN_RIDS = frozenset({500, 501, 502})  # Administrator, Guest, krbtgt
DC_GROUP_RIDS = frozenset({516, 521})  # Domain Controllers, Read-only Domain Controllers

# derived field -> LDAP attribute on the domain object
DOMAIN_POLICY_FIELDS = {
    "min_password_length": "minPwdLength",
    "password_complexity": "pwdProperties",
    "lockout_threshold": "lockoutThreshold",
    "machine_account_quota": "ms-DS-MachineAccountQuota",
}

# Free text on a user, read only to look for password words (ACC-04) and never stored.
TEXT_ATTRIBUTES = ("description", "info", "comment")
_NO_LETTER_BEFORE, _NO_LETTER_AFTER = r"(?<![^\W\d_])", r"(?![^\W\d_])"  # a digit may touch, a letter may not
PASSWORD_WORDS = re.compile(
    rf"{_NO_LETTER_BEFORE}(?:password|passwd|passphrase|pwd){_NO_LETTER_AFTER}"
    rf"|{_NO_LETTER_BEFORE}pass\s*[:=]"  # a bare "pass" only as "pass:" or "pass=" (not bypass, Pass-the-hash)
    r"|كلمة\s+(?:ال)?(?:مرور|سر)",  # كلمة المرور، كلمة مرور، كلمة السر، كلمة سر (any spacing)
    re.IGNORECASE,
)


def _int(value: Any) -> int | None:
    if isinstance(value, list | tuple):
        value = value[0] if value else None
    if value is None or value == "":
        return None
    return int(value)


def values(value: Any) -> list[str]:
    """Every value of a possibly multi-valued attribute as text; [] when absent or empty."""
    items = value if isinstance(value, list | tuple) else [value]
    return [str(v) for v in items if v is not None and v != ""]


def _rid(sid: str | None) -> int | None:
    tail = (sid or "").rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else None


def derive_user(raw: Mapping[str, Any], *, sid: str | None) -> dict[str, Any]:
    """Account flags from userAccountControl (None, unknown, when it was not read), SPNs and password words."""
    uac = _int(raw.get("userAccountControl"))
    name = raw.get("sAMAccountName")
    name = str(name[0] if isinstance(name, list) and name else name or "").lower()
    is_krbtgt = _rid(sid) == 502 or name == "krbtgt" or name.startswith("krbtgt_")
    spns = sorted(values(raw.get("servicePrincipalName")))
    text_attrs = [a for a in TEXT_ATTRIBUTES if any(PASSWORD_WORDS.search(t) for t in values(raw.get(a)))]
    return {
        "enabled": None if uac is None else not uac & UAC_ACCOUNTDISABLE,
        "is_builtin": _rid(sid) in BUILTIN_RIDS or is_krbtgt,
        "passwd_notreqd": None if uac is None else bool(uac & UAC_PASSWD_NOTREQD),
        "asrep_roastable": None if uac is None else bool(uac & UAC_DONT_REQ_PREAUTH),
        "unconstrained_delegation": None if uac is None else bool(uac & UAC_TRUSTED_FOR_DELEGATION),
        "spns": spns,
        "kerberoastable": bool(spns) and not is_krbtgt,
        "password_in_text_indicator": bool(text_attrs),
        "password_in_text_attrs": text_attrs,
    }


def derive_computer(raw: Mapping[str, Any]) -> dict[str, Any]:
    uac = _int(raw.get("userAccountControl"))
    group = _int(raw.get("primaryGroupID"))
    return {
        "is_dc": None if group is None else group in DC_GROUP_RIDS,
        "unconstrained_delegation": None if uac is None else bool(uac & UAC_TRUSTED_FOR_DELEGATION),
    }


def derive_domain(raw: Mapping[str, Any]) -> dict[str, Any]:
    properties = _int(raw.get("pwdProperties"))
    return {
        "min_password_length": _int(raw.get("minPwdLength")),
        "password_complexity": None if properties is None else bool(properties & DOMAIN_PASSWORD_COMPLEX),
        "lockout_threshold": _int(raw.get("lockoutThreshold")),
        "machine_account_quota": _int(raw.get("ms-DS-MachineAccountQuota")),
    }
