"""DEL-01: an account other than a domain controller is trusted for unconstrained delegation."""

from adrules.catalog import (
    NotAssessed,
    RuleContext,
    RuleMeta,
    computer_accounts,
    finding,
    user_accounts,
)
from adrules.finding import Finding
from adsnap.model import ADObject, Snapshot


def _computers(snapshot: Snapshot) -> list[ADObject]:
    return [c for c in computer_accounts(snapshot, "is_dc", "unconstrained_delegation") if not c.derived["is_dc"]]


def _users(snapshot: Snapshot) -> list[ADObject]:
    return user_accounts(snapshot, "unconstrained_delegation")


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    accounts: list[ADObject] = []
    missing: list[str] = []
    for read in (_computers, _users):
        try:  # users and computers separately: a side that could not be read never hides the other
            accounts += read(snapshot)
        except NotAssessed as exc:
            missing.append(str(exc))
    findings = [
        finding(meta, account, {
            "account": account.name, "setting": "userAccountControl",
            "current": "trusted for unconstrained delegation (TRUSTED_FOR_DELEGATION, 0x80000)",
            "expected": "no unconstrained delegation outside domain controllers",
        })
        for account in sorted(accounts, key=lambda a: a.name.lower())
        if account.derived["unconstrained_delegation"]  # enabled or not: a disabled account keeps the trust
    ]
    if missing and not findings:
        raise NotAssessed(missing[0])  # a pass needs both sides
    return findings
