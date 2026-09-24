"""Raw LDAP attributes -> derived fields (the collector/rules contract in docs/architecture.md).

A value that was not collected derives to None, never to 0 or False, so a rule can report
`not_assessed` instead of inventing a failure (D35).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

DOMAIN_PASSWORD_COMPLEX = 0x1

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


def derive_domain(raw: Mapping[str, Any]) -> dict[str, Any]:
    properties = _int(raw.get("pwdProperties"))
    return {
        "min_password_length": _int(raw.get("minPwdLength")),
        "password_complexity": None if properties is None else bool(properties & DOMAIN_PASSWORD_COMPLEX),
        "lockout_threshold": _int(raw.get("lockoutThreshold")),
    }
