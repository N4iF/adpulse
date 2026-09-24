"""Raw LDAP attributes -> derived fields (the collector/rules contract in docs/architecture.md).

A value that was not collected derives to None, never to 0 or False, so a rule can report
`not_assessed` instead of inventing a failure (D35).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

DOMAIN_PASSWORD_COMPLEX = 0x1

UAC_ACCOUNTDISABLE = 0x2
UAC_PASSWD_NOTREQD = 0x20
UAC_DONT_REQ_PREAUTH = 0x400000
BUILTIN_RIDS = frozenset({500, 501, 502})  # Administrator, Guest, krbtgt

# derived field -> LDAP attribute on the domain object
DOMAIN_POLICY_FIELDS = {
    "min_password_length": "minPwdLength",
    "password_complexity": "pwdProperties",
    "lockout_threshold": "lockoutThreshold",
}


def _int(value: Any) -> int | None:
    if isinstance(value, list | tuple):
        value = value[0] if value else None
    if value is None or value == "":
        return None
    return int(value)


def _rid(sid: str | None) -> int | None:
    tail = (sid or "").rsplit("-", 1)[-1]
    return int(tail) if tail.isdigit() else None


def derive_user(raw: Mapping[str, Any], *, sid: str | None) -> dict[str, Any]:
    """Account flags from userAccountControl; None (unknown) when the attribute was not read."""
    uac = _int(raw.get("userAccountControl"))
    name = raw.get("sAMAccountName")
    name = str(name[0] if isinstance(name, list) and name else name or "").lower()
    return {
        "enabled": None if uac is None else not uac & UAC_ACCOUNTDISABLE,
        "is_builtin": _rid(sid) in BUILTIN_RIDS or name == "krbtgt" or name.startswith("krbtgt_"),
        "passwd_notreqd": None if uac is None else bool(uac & UAC_PASSWD_NOTREQD),
        "asrep_roastable": None if uac is None else bool(uac & UAC_DONT_REQ_PREAUTH),
    }


def derive_domain(raw: Mapping[str, Any]) -> dict[str, Any]:
    properties = _int(raw.get("pwdProperties"))
    return {
        "min_password_length": _int(raw.get("minPwdLength")),
        "password_complexity": None if properties is None else bool(properties & DOMAIN_PASSWORD_COMPLEX),
        "lockout_threshold": _int(raw.get("lockoutThreshold")),
    }
