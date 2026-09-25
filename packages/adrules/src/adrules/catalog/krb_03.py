"""KRB-03: an enabled user account has a service principal name, so its password can be attacked offline."""

from adrules.catalog import RuleContext, RuleMeta, finding, user_accounts
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    return [
        finding(meta, user, {
            "account": user.name, "setting": "servicePrincipalName", "current": ", ".join(user.derived["spns"]),
            "expected": "no SPN on a user account; a gMSA, or a long random password with AES only",
        })
        for user in user_accounts(snapshot, "enabled", "kerberoastable", "spns")
        if user.derived["enabled"] and user.derived["kerberoastable"]
    ]
