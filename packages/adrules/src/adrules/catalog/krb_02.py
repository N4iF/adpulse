"""KRB-02: an enabled user account does not require Kerberos pre-authentication (DONT_REQ_PREAUTH)."""

from adrules.catalog import RuleContext, RuleMeta, finding, user_accounts
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    return [
        finding(meta, user, {
            "account": user.name, "setting": "userAccountControl",
            "current": "pre-authentication not required (DONT_REQ_PREAUTH, 0x400000)",
            "expected": "Kerberos pre-authentication required",
        })
        for user in user_accounts(snapshot, "enabled", "asrep_roastable")
        if user.derived["enabled"] and user.derived["asrep_roastable"]
    ]
